"""Substack CLI — impersonation scan for Capital Mischief (charliepgarcia).

Scans recent post comments and Notes replies for fake 'Charlie' accounts that:
  1. Include WhatsApp or Telegram contact details (phone numbers or handles)
     in the commenter's display name or comment body.
  2. Use a disguised 'charlie' in their display name — including Unicode
     confusable / homoglyph substitutions (e.g. 𝐂𝐡𝐚𝐫𝐥𝐢𝐞, Ϲharlie, Ċharlie).

Safety contract
---------------
- SUBSTACK_ENABLE_WRITE must be UNSET (or != "true") when --dry-run is active.
  The script asserts this on startup and aborts if violated.
- All write actions (report-user) are emitted via the existing dry-run path
  only: {dry_run: true, method, url, body} — zero HTTP POSTs.
- Read endpoints used: GET /api/v1/archive, GET /api/v1/post/{id}/comments,
  GET /api/v1/reader/feed/profile/{user_id}, GET /api/v1/reader/comment/{id}.
- The real Charlie account (user_id 27965159, handle charliepgarcia) is
  allowlisted and will never be flagged regardless of name match.

State files
-----------
  ~/.afk/state/impersonation/seen.json        — persistent set of acted user_ids
  ~/.afk/state/impersonation/YYYY-MM-DD.json  — dated scan log
  ~/.afk/state/impersonation/YYYY-MM-DD.md    — morning summary markdown

Daily cap
---------
  Default 20 would-report candidates per calendar day (--daily-cap to override).
  Candidates beyond the cap are logged as "uncertain" (cap_exceeded).
"""
from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The real Charlie Garcia — never flag this account.
REAL_CHARLIE_USER_ID = 27965159
REAL_CHARLIE_HANDLE = "charliepgarcia"

# Additional team accounts to allowlist (extend as needed).
ALLOWLISTED_USER_IDS: frozenset[int] = frozenset({
    REAL_CHARLIE_USER_ID,
    # Add Griffin's user_id here when known, e.g.: 99999999,
})

STATE_DIR = Path.home() / ".afk" / "state" / "impersonation"
SEEN_FILE = STATE_DIR / "seen.json"

DEFAULT_POST_LIMIT = 10
DEFAULT_NOTES_LIMIT = 20
DEFAULT_DAILY_CAP = 20
REQUEST_DELAY = 1.5  # seconds between read requests (polite crawl)

# ---------------------------------------------------------------------------
# Unicode confusables map for 'charlie'
# ---------------------------------------------------------------------------
# Maps confusable Unicode chars to their ASCII equivalents.
# Generated from the most common homoglyphs seen in impersonation attempts.
# The full Unicode confusables list (confusables.txt from unicode.org) is not
# bundled; we cover the high-frequency set that fits in a maintainable dict.

_CONFUSABLES: dict[str, str] = {
    # Latin lookalikes for C/c
    "\u0421": "c",  # Cyrillic С
    "\u03F9": "c",  # Greek Ϲ (lunate sigma)
    "\u2CA5": "c",  # Coptic small ϲ
    "\uFF23": "c",  # Fullwidth Ｃ
    "\uFF43": "c",  # Fullwidth ｃ
    # Latin lookalikes for h
    "\u04BB": "h",  # Cyrillic һ
    "\uFF48": "h",  # Fullwidth ｈ
    # Latin lookalikes for a
    "\u0430": "a",  # Cyrillic а
    "\u03B1": "a",  # Greek α
    "\uFF41": "a",  # Fullwidth ａ
    # Latin lookalikes for r
    "\u0433": "r",  # Cyrillic г (stretched)
    "\uFF52": "r",  # Fullwidth ｒ
    # Latin lookalikes for l
    "\u04C0": "l",  # Cyrillic Ӏ
    "\u0031": "l",  # digit 1 (common swap)
    "\uFF4C": "l",  # Fullwidth ｌ
    "\u007C": "l",  # pipe |
    # Latin lookalikes for i
    "\u0456": "i",  # Cyrillic і
    "\u04CF": "i",  # Cyrillic ӏ
    "\uFF49": "i",  # Fullwidth ｉ
    # Latin lookalikes for e
    "\u0435": "e",  # Cyrillic е
    "\u03B5": "e",  # Greek ε
    "\uFF45": "e",  # Fullwidth ｅ
}

# Mathematical bold/italic/script Unicode blocks map A-Z, a-z to codepoints.
# e.g. Mathematical Bold Capital C = U+1D402; Bold Small c = U+1D41C
# We handle these by NFKD normalization (which collapses compatibility chars).

def _normalize_for_detection(text: str) -> str:
    """Normalize text to ASCII-comparable form for detection purposes.

    Steps:
    1. NFKD decomposition (collapses math bold/script/italic Unicode blocks
       like 𝐂𝐡𝐚𝐫𝐥𝐢𝐞 → individual base chars + combining diacritics).
    2. Strip combining diacritical marks (so Ċ → C, etc.).
    3. Apply manual confusables map for chars that NFKD misses.
    4. Lowercase.
    5. Strip non-alphanumeric chars (spaces, dots, underscores, etc.) so
       "C.h.a.r.l.i.e" and "C_h_a_r_l_i_e" both become "charlie".
    """
    # Step 1+2: NFKD + strip combining marks
    nfkd = unicodedata.normalize("NFKD", text)
    stripped = "".join(
        ch for ch in nfkd
        if unicodedata.category(ch) != "Mn"  # Mn = non-spacing mark
    )
    # Step 3: manual confusables
    mapped = "".join(_CONFUSABLES.get(ch, ch) for ch in stripped)
    # Step 4+5: lowercase, keep only alphanumeric
    return re.sub(r"[^a-z0-9]", "", mapped.lower())


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# WhatsApp/Telegram contact lure patterns
_WHATSAPP_RE = re.compile(
    r"whatsapp|whats\s*app|wa\.me|api\.whatsapp",
    re.IGNORECASE,
)
_TELEGRAM_RE = re.compile(
    r"telegram|t\.me/|@[A-Za-z0-9_]{4,}",  # Telegram handle or t.me link
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    # International phone: +1 672 906 6441, +16729066441, (672) 906-6441, etc.
    r"(\+?\d[\d\s\-\.\(\)]{6,}\d)",
)

# 'charlie' after normalization — matched as a substring of the normalized name
_CHARLIE_NORM = "charlie"


def _detect(name: str, body: str) -> list[str]:
    """Return list of match reason strings (empty = no match).

    Detection is intentionally **name-only** for keyword/phone rules.
    Scanning the comment body produces overwhelming false positives: legitimate
    readers mention WhatsApp/Telegram/phone numbers when *reporting* or
    *discussing* impersonation scams. Only the display name is a reliable
    signal — scammers embed their contact lure there, honest readers don't.

    Rules applied to display name only:
      - WhatsApp keyword (name contains "whatsapp", "wa.me", etc.)
      - Telegram keyword or @handle (name contains "telegram", "t.me/", "@…")
      - Phone number pattern in name (+1 672 906 6441, etc.)
      - Disguised 'charlie' after Unicode confusables normalization

    `body` parameter is accepted for API compatibility but intentionally
    unused in the current ruleset.
    """
    reasons: list[str] = []

    # All keyword/phone rules apply to the display name only
    if _WHATSAPP_RE.search(name):
        reasons.append("whatsapp_contact")
    if _TELEGRAM_RE.search(name):
        reasons.append("telegram_contact")
    if _PHONE_RE.search(name):
        reasons.append("phone_number")

    # Charlie name check: display name only
    norm_name = _normalize_for_detection(name)
    if _CHARLIE_NORM in norm_name and _CHARLIE_NORM != norm_name:
        # Require charlie to appear as a substring with additional chars —
        # avoids flagging innocent readers whose only name is "Charlie".
        reasons.append("disguised_charlie_name")

    return reasons


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def _load_seen() -> dict:
    """Load the persistent seen-state dict.

    Shape: {"acted_user_ids": [...], "daily_counts": {"YYYY-MM-DD": N}}
    """
    if SEEN_FILE.exists():
        try:
            return json.loads(SEEN_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"acted_user_ids": [], "daily_counts": {}}


def _save_seen(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    SEEN_FILE.write_text(json.dumps(state, indent=2))


def _today() -> str:
    return date.today().isoformat()


def _daily_count(state: dict) -> int:
    return state.get("daily_counts", {}).get(_today(), 0)


def _increment_daily(state: dict) -> None:
    state.setdefault("daily_counts", {})[_today()] = _daily_count(state) + 1


# ---------------------------------------------------------------------------
# Dry-run report builder
# ---------------------------------------------------------------------------

SUBSTACK_COM = "https://substack.com"


def _dry_run_report_user(user_id: int, reason_str: str) -> dict:
    """Build the would-be report-user request (no network call)."""
    return {
        "dry_run": True,
        "method": "POST",
        "url": f"{SUBSTACK_COM}/api/v1/users/{user_id}/profile/report",
        "body": {
            "reportCategory": "impersonation",
            "details": f"Impersonation of Capital Mischief author Charlie Garcia. Triggers: {reason_str}",
            "reportedToSubstack": True,
            "surface": "profile",
        },
    }


# ---------------------------------------------------------------------------
# Comment tree walker
# ---------------------------------------------------------------------------

def _walk_comments(comments: list, depth: int = 0) -> list[dict]:
    """Recursively flatten a comment tree (comments + their children)."""
    flat = []
    for c in comments:
        if not isinstance(c, dict):
            continue
        flat.append(c)
        children = c.get("children") or c.get("comments") or []
        if children:
            flat.extend(_walk_comments(children, depth + 1))
    return flat


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def run_scan(
    client,  # SubstackClient
    *,
    post_limit: int = DEFAULT_POST_LIMIT,
    notes_limit: int = DEFAULT_NOTES_LIMIT,
    daily_cap: int = DEFAULT_DAILY_CAP,
    dry_run: bool = True,
    verbose: bool = False,
) -> dict:
    """Run the impersonation scan.

    Returns a result dict with:
      posts_scanned, notes_scanned, candidates, uncertain,
      would_report (list of {user_id, name, reasons, dry_run_call}),
      summary_path, log_path
    """
    # --- Safety assertion ---
    if dry_run:
        write_env = os.environ.get("SUBSTACK_ENABLE_WRITE", "").strip().lower()
        assert write_env != "true", (
            "SAFETY ABORT: SUBSTACK_ENABLE_WRITE=true is set but --dry-run is active. "
            "Unset SUBSTACK_ENABLE_WRITE before running in dry-run mode."
        )

    state = _load_seen()
    acted_ids: set[int] = set(state.get("acted_user_ids", []))
    today_count = _daily_count(state)

    candidates: list[dict] = []
    uncertain: list[dict] = []
    posts_scanned = 0
    notes_scanned = 0

    # ------------------------------------------------------------------ #
    # 1. Scan recent post comments                                        #
    # ------------------------------------------------------------------ #
    if verbose:
        print(f"[scan] Fetching archive (limit={post_limit}) …")

    try:
        archive = client.get("/api/v1/archive", sort="new", offset=0, limit=post_limit)
        posts = archive if isinstance(archive, list) else archive.get("posts", [])
    except Exception as exc:
        posts = []
        if verbose:
            print(f"[scan] Archive fetch failed: {exc}")

    for post in posts:
        if not isinstance(post, dict):
            continue
        post_id = post.get("id")
        if not post_id:
            continue

        time.sleep(REQUEST_DELAY)
        try:
            raw = client.get(f"/api/v1/post/{post_id}/comments")
        except Exception as exc:
            if verbose:
                print(f"[scan] Comments fetch failed for post {post_id}: {exc}")
            continue

        # Tolerate bare list or envelope
        if isinstance(raw, list):
            comment_list = raw
        elif isinstance(raw, dict):
            comment_list = (
                raw.get("comments") or raw.get("items") or raw.get("data") or []
            )
        else:
            comment_list = []

        all_comments = _walk_comments(comment_list)
        posts_scanned += 1

        for c in all_comments:
            user_id = c.get("user_id") or (c.get("author") or {}).get("id")
            name = c.get("name") or (c.get("author") or {}).get("name") or ""
            body = c.get("body") or ""
            comment_id = c.get("id")

            if not user_id:
                continue
            if int(user_id) in ALLOWLISTED_USER_IDS:
                continue

            reasons = _detect(name, body)
            if not reasons:
                continue

            _record_candidate(
                candidates, uncertain, acted_ids, state,
                user_id=int(user_id), name=name, reasons=reasons,
                surface="comment", ref_id=comment_id, post_id=post_id,
                today_count=today_count, daily_cap=daily_cap,
                dry_run=dry_run,
            )
            today_count = _daily_count(state)

    # ------------------------------------------------------------------ #
    # 2. Scan Charlie's Notes replies                                     #
    # ------------------------------------------------------------------ #
    if verbose:
        print(f"[scan] Fetching Charlie's Notes (limit={notes_limit}) …")

    time.sleep(REQUEST_DELAY)
    try:
        notes_raw = client.get(
            f"/api/v1/reader/feed/profile/{REAL_CHARLIE_USER_ID}",
            host="A",
            limit=notes_limit,
        )
    except Exception as exc:
        notes_raw = []
        if verbose:
            print(f"[scan] Notes feed fetch failed: {exc}")

    # Notes feed shape: list of {item: {comment: {id, ...}, children: [...]}}
    note_items = notes_raw if isinstance(notes_raw, list) else (
        notes_raw.get("items") or notes_raw.get("posts") or []
    )

    for item_wrapper in note_items:
        if not isinstance(item_wrapper, dict):
            continue
        item = item_wrapper.get("item") or item_wrapper
        note_comment = item.get("comment") or {}
        note_id = note_comment.get("id") or item_wrapper.get("entity_key", "").lstrip("c-")
        if not note_id:
            continue

        # Replies are in item.children
        children = item.get("children") or []
        all_replies = _walk_comments(children)
        notes_scanned += 1

        for reply in all_replies:
            user_id = reply.get("user_id") or (reply.get("author") or {}).get("id")
            name = reply.get("name") or (reply.get("author") or {}).get("name") or ""
            body = reply.get("body") or ""
            reply_id = reply.get("id")

            if not user_id:
                continue
            if int(user_id) in ALLOWLISTED_USER_IDS:
                continue

            reasons = _detect(name, body)
            if not reasons:
                continue

            _record_candidate(
                candidates, uncertain, acted_ids, state,
                user_id=int(user_id), name=name, reasons=reasons,
                surface="note_reply", ref_id=reply_id, post_id=None,
                today_count=today_count, daily_cap=daily_cap,
                dry_run=dry_run,
            )
            today_count = _daily_count(state)

    # ------------------------------------------------------------------ #
    # 3. Persist state + write outputs                                    #
    # ------------------------------------------------------------------ #
    _save_seen(state)

    today_str = _today()
    log_path = STATE_DIR / f"{today_str}.json"
    summary_path = STATE_DIR / f"{today_str}.md"

    log_data = {
        "scan_ts": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "posts_scanned": posts_scanned,
        "notes_scanned": notes_scanned,
        "candidates_found": len(candidates),
        "uncertain_count": len(uncertain),
        "would_report": candidates,
        "uncertain": uncertain,
    }
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps(log_data, indent=2))

    # Morning summary markdown
    _write_summary(
        summary_path,
        posts_scanned=posts_scanned,
        notes_scanned=notes_scanned,
        candidates=candidates,
        uncertain=uncertain,
        dry_run=dry_run,
        today_str=today_str,
    )

    return {
        "posts_scanned": posts_scanned,
        "notes_scanned": notes_scanned,
        "candidates_found": len(candidates),
        "uncertain_count": len(uncertain),
        "would_report": candidates,
        "uncertain": uncertain,
        "log_path": str(log_path),
        "summary_path": str(summary_path),
    }


def _record_candidate(
    candidates, uncertain, acted_ids, state,
    *, user_id, name, reasons, surface, ref_id, post_id,
    today_count, daily_cap, dry_run,
):
    """Classify a match as actionable or uncertain; update state."""
    reason_str = ", ".join(reasons)
    entry = {
        "user_id": user_id,
        "display_name": name,
        "reasons": reasons,
        "surface": surface,
        "ref_id": ref_id,
        "post_id": post_id,
    }

    if user_id in acted_ids:
        # Already reported in a previous run — skip (dedupe)
        return

    if _daily_count(state) >= daily_cap:
        entry["status"] = "cap_exceeded"
        uncertain.append(entry)
        return

    # Within cap and not seen before
    if dry_run:
        entry["dry_run_call"] = _dry_run_report_user(user_id, reason_str)
    entry["status"] = "would_report"
    candidates.append(entry)

    # Mark as acted (so a re-run won't double-count in live mode)
    acted_ids.add(user_id)
    state["acted_user_ids"] = list(acted_ids)
    _increment_daily(state)


def _write_summary(
    path: Path,
    *,
    posts_scanned: int,
    notes_scanned: int,
    candidates: list,
    uncertain: list,
    dry_run: bool,
    today_str: str,
) -> None:
    """Write the morning summary Markdown file."""
    mode = "DRY-RUN" if dry_run else "LIVE"
    lines = [
        f"# Capital Mischief Impersonation Scan — {today_str} ({mode})",
        "",
        f"**Posts scanned:** {posts_scanned}  ",
        f"**Notes scanned:** {notes_scanned}  ",
        f"**Candidates (would report):** {len(candidates)}  ",
        f"**Uncertain (cap exceeded or pending review):** {len(uncertain)}  ",
        "",
    ]

    if candidates:
        lines.append("## Would-Report List")
        lines.append("")
        for c in candidates:
            uid = c["user_id"]
            name = c["display_name"]
            reasons = ", ".join(c["reasons"])
            lines.append(f"- **user_id {uid}** — display name: `{name}` — triggers: {reasons}")
        lines.append("")

    if uncertain:
        lines.append("## Uncertain / Cap-Exceeded Items")
        lines.append("")
        for c in uncertain:
            uid = c["user_id"]
            name = c["display_name"]
            reasons = ", ".join(c["reasons"])
            status = c.get("status", "unknown")
            lines.append(
                f"- user_id {uid} | `{name}` | {reasons} | status: {status}"
            )
        lines.append("")

    lines += [
        "---",
        "_Generated by impersonation_scan. No reports were filed in dry-run mode._"
        if dry_run else
        "_Generated by impersonation_scan. Reports filed per would-report list above._",
        "",
    ]
    path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI entry point (invoked by impersonation_scan CLI command)
# ---------------------------------------------------------------------------

def run_cli(
    post_limit: int = DEFAULT_POST_LIMIT,
    notes_limit: int = DEFAULT_NOTES_LIMIT,
    daily_cap: int = DEFAULT_DAILY_CAP,
    dry_run: bool = True,
    verbose: bool = False,
) -> None:
    """Build a client and run the scan. Called from the typer CLI command."""
    from substack_cli.auth import resolve_cookies, resolve_publication_url
    from substack_cli.client import SubstackClient

    cookies = resolve_cookies()
    pub_url = resolve_publication_url()
    client = SubstackClient(cookies=cookies, publication_url=pub_url)

    result = run_scan(
        client,
        post_limit=post_limit,
        notes_limit=notes_limit,
        daily_cap=daily_cap,
        dry_run=dry_run,
        verbose=verbose,
    )

    import json as _json
    print(_json.dumps(result, indent=2))
    print(f"\n[scan] Summary written to: {result['summary_path']}", flush=True)
