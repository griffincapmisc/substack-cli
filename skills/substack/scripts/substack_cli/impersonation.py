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
  Body-only matches always go to uncertain regardless of the cap, and are never
  auto-reported.
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


def _has_non_ascii_confusable(text: str) -> bool:
    """Return True if *text* contains any non-ASCII character that our
    confusables map (or NFKD) converts to an ASCII letter.

    Used to distinguish 'Ϲharlie Garcia' (confusable C → disguise signal)
    from plain ASCII 'Charlie Garcia' (innocent reader).
    """
    for ch in text:
        if ord(ch) <= 127:
            continue
        # Check manual confusables map
        if ch in _CONFUSABLES:
            return True
        # Check whether NFKD decomposition yields any ASCII base letter
        nfkd_ch = unicodedata.normalize("NFKD", ch)
        base = "".join(
            c for c in nfkd_ch if unicodedata.category(c) != "Mn"
        )
        if base and all(ord(c) <= 127 for c in base) and base.isalpha():
            return True
    return False


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

# 'charlie' and 'charliegarcia' after normalization
_CHARLIE_NORM = "charlie"
_CHARLIEGARCIA_NORM = "charliegarcia"
_CHARLIEPGARCIA_NORM = "charliepgarcia"

# Surnames that, combined with 'charlie', target Charlie Garcia specifically.
# Normalization strips spaces/punctuation so "p garcia", "garcia" both match.
_GARCIA_VARIANTS: frozenset[str] = frozenset({
    "charliegarcia",
    "charliepgarcia",
})

# Body scanning: only flag bodies that contain a *direct contact invitation*
# — an imperative verb near whatsapp/telegram, or a bare link/phone together
# with whatsapp/telegram.  Readers reporting or discussing the scam say things
# like "I got a WhatsApp from fake Charlie" — those must NOT match.

# Imperative contact verbs: "WhatsApp me", "message me on Telegram", etc.
_BODY_INVITE_VERB_RE = re.compile(
    r"\b(?:whatsapp|message|text|contact|dm|reach|ping|chat)\s+me\b"
    r"|"
    r"\b(?:reach\s+out|get\s+in\s+touch)\b",
    re.IGNORECASE,
)

# wa.me / t.me links  (direct invite links)
_BODY_INVITE_LINK_RE = re.compile(
    r"(?:wa\.me|t\.me)/\S+",
    re.IGNORECASE,
)

# Phone number in body (same pattern as name)
_BODY_PHONE_RE = _PHONE_RE

# @handle in body (Telegram-style, ≥4 chars)
_BODY_HANDLE_RE = re.compile(r"@[A-Za-z0-9_]{4,}")


def _body_has_contact_lure(body: str) -> bool:
    """Return True only when the body carries a *direct contact invitation*.

    A direct contact invitation is one of:
      (a) An imperative contact verb ("WhatsApp me", "message me", etc.)
          near whatsapp or telegram keyword.
      (b) A wa.me or t.me invite link together with whatsapp/telegram keyword.
      (c) A phone number or @handle together with whatsapp/telegram keyword.

    A reader saying "I got a WhatsApp from a fake Charlie" does NOT match
    because there is no imperative verb, invite link, or bare phone/handle
    paired with the platform keyword.
    """
    has_whatsapp = bool(_WHATSAPP_RE.search(body))
    has_telegram = bool(_TELEGRAM_RE.search(body))
    if not (has_whatsapp or has_telegram):
        return False

    # Condition (a): imperative verb present
    if _BODY_INVITE_VERB_RE.search(body):
        return True

    # Condition (b): invite link present
    if _BODY_INVITE_LINK_RE.search(body):
        return True

    # Condition (c): phone number or @handle present alongside platform keyword
    if _BODY_PHONE_RE.search(body) or _BODY_HANDLE_RE.search(body):
        return True

    return False


def _detect(name: str, body: str, *, user_id: Optional[int] = None) -> tuple[list[str], list[str]]:
    """Return (name_reasons, body_reasons).

    name_reasons — triggers from the display name; actionable (candidates).
    body_reasons — triggers from the comment body; uncertain bucket only,
                   never auto-reported.

    Bug 1 fix — disguised_charlie_name rules (replaces the old substring-only
    check that matched any 'Charlie <Surname>'):

      Rule A — charlie_garcia_name:
        Normalized name contains 'charliegarcia' or 'charliepgarcia' AND
        user_id is not the real Charlie (27965159).  Catches impersonators
        who write "Charlie Garcia", "Charlie P. Garcia", "charliepgarcia", etc.

      Rule B — charlie_confusable_name:
        The raw name contains at least one non-ASCII confusable letter AND
        the normalized form contains 'charlie'.  A disguise signal regardless
        of surname: scammers use 𝐂𝐡𝐚𝐫𝐥𝐢𝐞, Ϲharlie, ＣＨＡＲＬＩＥ, etc.

      Rule C — charlie_with_lure_name:
        'charlie' in normalized name AND a contact lure (whatsapp/telegram/
        phone/@handle) also appears in the display name.  Catches "Charlie
        WhatsApp +1 672 906 6441" even without a Garcia surname.

    A plain ASCII 'Charlie <OtherSurname>' with no lure does NOT match any
    rule and is never flagged (e.g. 'Charlie Smith', 'Charlie Brown').

    Note on 'Charles Garcia' / 'Charlotte Garcia': normalized forms are
    'charlesgarcia' / 'charlottegarcia' — neither contains 'charliegarcia',
    and both are plain ASCII with no lure, so they do NOT match.  'Charles
    Garcia' is at most uncertain; flagging it would be a false positive.

    Bug 2 fix — body scanning:
      Body matches go to body_reasons (uncertain bucket, never auto-reported).
      Only direct contact invitations match (see _body_has_contact_lure).
    """
    name_reasons: list[str] = []
    body_reasons: list[str] = []

    # ---- Name rules (contact lures) ----
    if _WHATSAPP_RE.search(name):
        name_reasons.append("whatsapp_contact")
    if _TELEGRAM_RE.search(name):
        name_reasons.append("telegram_contact")
    if _PHONE_RE.search(name):
        name_reasons.append("phone_number")

    # ---- Name rules (disguised Charlie) ----
    norm_name = _normalize_for_detection(name)

    # Rule A: charlie garcia / charliepgarcia exact target
    if any(variant in norm_name for variant in _GARCIA_VARIANTS):
        is_real = (user_id is not None and int(user_id) == REAL_CHARLIE_USER_ID)
        if not is_real:
            name_reasons.append("charlie_garcia_name")

    # Rule B: confusable letters that normalize to 'charlie' (disguise signal)
    if _CHARLIE_NORM in norm_name and _has_non_ascii_confusable(name):
        name_reasons.append("charlie_confusable_name")

    # Rule C: 'charlie' in name AND contact lure also in name
    if _CHARLIE_NORM in norm_name and (
        _WHATSAPP_RE.search(name) or _TELEGRAM_RE.search(name) or _PHONE_RE.search(name)
    ):
        name_reasons.append("charlie_with_lure_name")

    # ---- Body rule (uncertain bucket only) ----
    if _body_has_contact_lure(body):
        body_reasons.append("body_contact_lure")

    return name_reasons, body_reasons


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

            name_reasons, body_reasons = _detect(name, body, user_id=int(user_id))
            _record_candidate(
                candidates, uncertain, acted_ids, state,
                user_id=int(user_id), name=name,
                name_reasons=name_reasons, body_reasons=body_reasons,
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

            name_reasons, body_reasons = _detect(name, body, user_id=int(user_id))
            _record_candidate(
                candidates, uncertain, acted_ids, state,
                user_id=int(user_id), name=name,
                name_reasons=name_reasons, body_reasons=body_reasons,
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
    *, user_id, name, name_reasons, body_reasons,
    surface, ref_id, post_id,
    today_count, daily_cap, dry_run,
):
    """Classify a match as actionable (candidate) or uncertain; update state.

    Routing:
    - body_reasons only → always uncertain (never auto-reported, never counted
      toward the daily cap).
    - name_reasons (with or without body_reasons) → actionable candidate if
      within daily cap and not already acted on; otherwise uncertain/cap_exceeded.
    """
    if not name_reasons and not body_reasons:
        return

    reasons = name_reasons + body_reasons
    reason_str = ", ".join(reasons)
    entry = {
        "user_id": user_id,
        "display_name": name,
        "reasons": reasons,
        "name_reasons": name_reasons,
        "body_reasons": body_reasons,
        "surface": surface,
        "ref_id": ref_id,
        "post_id": post_id,
    }

    # Body-only → uncertain, never auto-reported, never counts toward cap
    if not name_reasons:
        entry["status"] = "body_only_review"
        uncertain.append(entry)
        return

    # Name-triggered: check dedupe and cap
    if user_id in acted_ids:
        return  # Already reported in a previous run — dedupe

    if _daily_count(state) >= daily_cap:
        entry["status"] = "cap_exceeded"
        uncertain.append(entry)
        return

    # Within cap, not seen before → actionable candidate
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
    # Separate body-only uncertain from cap-exceeded uncertain
    body_only = [u for u in uncertain if u.get("status") == "body_only_review"]
    cap_exceeded = [u for u in uncertain if u.get("status") == "cap_exceeded"]

    lines = [
        f"# Capital Mischief Impersonation Scan — {today_str} ({mode})",
        "",
        f"**Posts scanned:** {posts_scanned}  ",
        f"**Notes scanned:** {notes_scanned}  ",
        f"**Candidates (would report):** {len(candidates)}  ",
        f"**Uncertain — body-only (human review):** {len(body_only)}  ",
        f"**Uncertain — cap exceeded:** {len(cap_exceeded)}  ",
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

    if body_only:
        lines.append("## Body-Only Matches (Human Review — NOT auto-reported)")
        lines.append("")
        for c in body_only:
            uid = c["user_id"]
            name = c["display_name"]
            reasons = ", ".join(c["reasons"])
            lines.append(f"- user_id {uid} | `{name}` | {reasons} | status: body_only_review")
        lines.append("")

    if cap_exceeded:
        lines.append("## Cap-Exceeded Items")
        lines.append("")
        for c in cap_exceeded:
            uid = c["user_id"]
            name = c["display_name"]
            reasons = ", ".join(c["reasons"])
            lines.append(f"- user_id {uid} | `{name}` | {reasons} | status: cap_exceeded")
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
