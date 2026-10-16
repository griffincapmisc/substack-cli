"""Substack CLI — moderation helpers: shared client factory and dry-run output.

Extracted from moderation.py to keep that module within the 350-LOC limit.
Import only from moderation.py and tests — not from moderation_core.py (which
must remain command-free and import-cycle-free).
"""
from __future__ import annotations

from substack_cli.auth import resolve_cookies, resolve_publication_url
from substack_cli.client import SubstackClient, output


def _make_client() -> SubstackClient:
    """Resolve credentials and return a ready SubstackClient."""
    cookies = resolve_cookies()
    pub_url = resolve_publication_url()
    return SubstackClient(cookies=cookies, publication_url=pub_url)


def _dry_run_output(method: str, url: str, body: dict, pretty: bool) -> None:
    """Print the exact request that would be fired, then exit 0."""
    payload = {
        "dry_run": True,
        "method": method,
        "url": url,
        "body": body,
    }
    output(payload, pretty=pretty)
