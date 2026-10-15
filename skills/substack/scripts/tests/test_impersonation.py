"""Unit tests for impersonation detection rules.

Covers:
  POSITIVE cases — must be flagged:
    - WhatsApp phone number in display name
    - Telegram handle in display name
    - Unicode-styled 'Charlie Garcia' (mathematical bold)
    - Cyrillic confusable in 'Charlie'
    - Phone number in comment body

  NEGATIVE cases — must NOT be flagged:
    - Ordinary reader named Charles
    - The real Charlie account (allowlisted by user_id)
    - A subscriber whose name contains 'arch' but not 'charlie'
    - A name that normalizes to exactly 'charlie' (no extra content)
"""
import pytest

from substack_cli.impersonation import (
    ALLOWLISTED_USER_IDS,
    REAL_CHARLIE_USER_ID,
    _detect,
    _normalize_for_detection,
    _walk_comments,
    _record_candidate,
    _load_seen,
)


# ---------------------------------------------------------------------------
# _normalize_for_detection
# ---------------------------------------------------------------------------

class TestNormalizeForDetection:
    def test_plain_ascii(self):
        assert _normalize_for_detection("Charlie") == "charlie"

    def test_mathematical_bold(self):
        # 𝐂𝐡𝐚𝐫𝐥𝐢𝐞 — U+1D402 U+1D421 U+1D41A U+1D42B U+1D425 U+1D422 U+1D41E
        bold = "\U0001D402\U0001D421\U0001D41A\U0001D42B\U0001D425\U0001D422\U0001D41E"
        assert _normalize_for_detection(bold) == "charlie"

    def test_cyrillic_c(self):
        # Cyrillic С + harlie
        assert _normalize_for_detection("\u0421harlie") == "charlie"

    def test_dots_between_letters(self):
        assert _normalize_for_detection("C.h.a.r.l.i.e") == "charlie"

    def test_mixed_case(self):
        assert _normalize_for_detection("CHARLIE") == "charlie"

    def test_nfkd_diacritics(self):
        # Ċ (U+010A) — C with dot above — NFKD strips the combining dot
        assert _normalize_for_detection("\u010Aharlie") == "charlie"

    def test_fullwidth(self):
        # Fullwidth Ｃｈａｒｌｉｅ
        fw = "\uFF23\uFF48\uFF41\uFF52\uFF4C\uFF49\uFF45"
        assert _normalize_for_detection(fw) == "charlie"


# ---------------------------------------------------------------------------
# _detect — POSITIVE cases
# ---------------------------------------------------------------------------

class TestDetectPositive:
    def test_whatsapp_phone_in_name(self):
        """'Charlie WhatsApp +1 672 906 6441' → whatsapp_contact + phone_number"""
        reasons = _detect("Charlie WhatsApp +1 672 906 6441", "")
        assert "whatsapp_contact" in reasons
        assert "phone_number" in reasons

    def test_telegram_handle_in_name(self):
        """'Telegram me (@CharlieGarcia1)' → telegram_contact"""
        reasons = _detect("Telegram me (@CharlieGarcia1)", "")
        assert "telegram_contact" in reasons

    def test_telegram_in_name(self):
        """Telegram handle embedded directly in display name."""
        reasons = _detect("Charlie Garcia @CharlieOfficial_tg", "")
        assert "telegram_contact" in reasons

    def test_whatsapp_in_name(self):
        """WhatsApp keyword embedded directly in display name."""
        reasons = _detect("Charlie WhatsApp Investor", "")
        assert "whatsapp_contact" in reasons

    def test_body_alone_does_not_trigger(self):
        """A reader mentioning WhatsApp/Telegram in the body (as victim/reporter)
        must NOT be flagged — body is intentionally not scanned."""
        reasons = _detect("Ellen", "I've gotten countless WhatsApp messages from fake Charlie accounts")
        assert reasons == []

    def test_body_telegram_not_trigger(self):
        reasons = _detect("Tom H", "Sorry you have to deal with these Telegram scammers")
        assert reasons == []

    def test_unicode_bold_charlie_name(self):
        """Mathematical bold 𝐂𝐡𝐚𝐫𝐥𝐢𝐞 Garcia → disguised_charlie_name"""
        bold_charlie = (
            "\U0001D402\U0001D421\U0001D41A\U0001D42B\U0001D425\U0001D422\U0001D41E"
            " Garcia"
        )
        reasons = _detect(bold_charlie, "")
        assert "disguised_charlie_name" in reasons

    def test_cyrillic_charlie_name(self):
        """\u0421harlie Garcia (Cyrillic С) → disguised_charlie_name"""
        reasons = _detect("\u0421harlie Garcia", "")
        assert "disguised_charlie_name" in reasons

    def test_phone_in_name(self):
        """Phone number embedded in display name triggers phone_number."""
        reasons = _detect("Charlie +16729066441", "")
        assert "phone_number" in reasons

    def test_phone_only_in_body_no_trigger(self):
        """Phone in body alone must NOT trigger — body is not scanned."""
        reasons = _detect("Random Name", "call me at +16729066441 for details")
        assert "phone_number" not in reasons

    def test_dotted_charlie_garcia(self):
        """C.h.a.r.l.i.e Garcia → disguised_charlie_name"""
        reasons = _detect("C.h.a.r.l.i.e Garcia", "")
        assert "disguised_charlie_name" in reasons

    def test_tme_link_in_name(self):
        """t.me/ link embedded in display name triggers telegram_contact."""
        reasons = _detect("Some Guy t.me/charliegarcia_official", "")
        assert "telegram_contact" in reasons

    def test_tme_link_in_body_no_trigger(self):
        """t.me/ in body alone must NOT trigger — body is not scanned."""
        reasons = _detect("Some Guy", "Join at t.me/charliegarcia_official")
        assert "telegram_contact" not in reasons

    def test_whatsapp_api_url_in_name(self):
        """api.whatsapp.com URL in display name triggers whatsapp_contact."""
        reasons = _detect("Some Guy api.whatsapp.com/send", "")
        assert "whatsapp_contact" in reasons

    def test_whatsapp_api_url_in_body_no_trigger(self):
        """api.whatsapp.com in body alone must NOT trigger."""
        reasons = _detect("Some Guy", "api.whatsapp.com/send?phone=16729066441")
        assert "whatsapp_contact" not in reasons


# ---------------------------------------------------------------------------
# _detect — NEGATIVE cases
# ---------------------------------------------------------------------------

class TestDetectNegative:
    def test_ordinary_charles(self):
        """Charles Smith — a real reader, no contact lure."""
        reasons = _detect("Charles Smith", "Great article, thanks!")
        assert reasons == []

    def test_ordinary_reader_no_charlie(self):
        reasons = _detect("Sarah Johnson", "Looking forward to the next issue.")
        assert reasons == []

    def test_arch_in_name_not_charlie(self):
        """'Marchello' contains 'arch' but normalized is 'marchello', not 'charlie'."""
        reasons = _detect("Marchello", "")
        assert reasons == []

    def test_exactly_charlie_normalized(self):
        """A name that normalizes to EXACTLY 'charlie' with nothing else.

        The rule requires charlie to appear plus something more in the normalized
        form (len > len('charlie')), so a standalone 'Charlie' is NOT flagged —
        it would catch innocent readers named Charlie.
        """
        # Plain 'Charlie' alone: normalized = 'charlie', which equals _CHARLIE_NORM
        # so the condition `_CHARLIE_NORM in norm_name and _CHARLIE_NORM != norm_name`
        # is False — correctly NOT flagged.
        reasons = _detect("Charlie", "")
        assert "disguised_charlie_name" not in reasons

    def test_real_charlie_allowlist(self):
        """The real Charlie account is protected by allowlist (user_id check),
        not the detection function itself — _detect doesn't see user_id.
        Confirm his display name 'Charlie Garcia' would fire the rule..."""
        reasons = _detect("Charlie Garcia", "")
        # 'Charlie Garcia' normalizes to 'charliegarcia' which contains 'charlie'
        # and is longer — so _detect DOES flag it. This is expected and correct:
        # the allowlist (by user_id) is what prevents action, not _detect.
        assert "disguised_charlie_name" in reasons

    def test_allowlist_contains_real_charlie(self):
        """Confirm REAL_CHARLIE_USER_ID is in ALLOWLISTED_USER_IDS."""
        assert REAL_CHARLIE_USER_ID in ALLOWLISTED_USER_IDS
        assert REAL_CHARLIE_USER_ID == 27965159


# ---------------------------------------------------------------------------
# _walk_comments — tree flattening
# ---------------------------------------------------------------------------

class TestWalkComments:
    def test_flat_list(self):
        comments = [{"id": 1}, {"id": 2}]
        assert _walk_comments(comments) == [{"id": 1}, {"id": 2}]

    def test_nested_children(self):
        comments = [
            {"id": 1, "children": [{"id": 2, "children": [{"id": 3}]}]},
        ]
        flat = _walk_comments(comments)
        assert [c["id"] for c in flat] == [1, 2, 3]

    def test_empty(self):
        assert _walk_comments([]) == []

    def test_non_dict_entries_skipped(self):
        assert _walk_comments([None, "bad", 42]) == []


# ---------------------------------------------------------------------------
# _record_candidate — daily cap and dedupe
# ---------------------------------------------------------------------------

class TestRecordCandidate:
    def _make_state(self):
        return {"acted_user_ids": [], "daily_counts": {}}

    def test_records_candidate(self):
        candidates, uncertain = [], []
        state = self._make_state()
        acted = set()
        _record_candidate(
            candidates, uncertain, acted, state,
            user_id=999, name="Test User", reasons=["whatsapp_contact"],
            surface="comment", ref_id=1, post_id=1,
            today_count=0, daily_cap=20, dry_run=True,
        )
        assert len(candidates) == 1
        assert candidates[0]["user_id"] == 999
        assert candidates[0]["status"] == "would_report"
        assert "dry_run_call" in candidates[0]

    def test_dedupe_skips_acted(self):
        candidates, uncertain = [], []
        state = self._make_state()
        acted = {999}  # already acted on this user
        _record_candidate(
            candidates, uncertain, acted, state,
            user_id=999, name="Test User", reasons=["whatsapp_contact"],
            surface="comment", ref_id=1, post_id=1,
            today_count=0, daily_cap=20, dry_run=True,
        )
        assert candidates == []
        assert uncertain == []

    def test_daily_cap_shunts_to_uncertain(self):
        candidates, uncertain = [], []
        state = {"acted_user_ids": [], "daily_counts": {"2026-10-15": 20}}
        acted = set()
        import unittest.mock as mock
        with mock.patch("substack_cli.impersonation._today", return_value="2026-10-15"):
            _record_candidate(
                candidates, uncertain, acted, state,
                user_id=888, name="Cap Test", reasons=["phone_number"],
                surface="comment", ref_id=2, post_id=2,
                today_count=20, daily_cap=20, dry_run=True,
            )
        assert candidates == []
        assert len(uncertain) == 1
        assert uncertain[0]["status"] == "cap_exceeded"
