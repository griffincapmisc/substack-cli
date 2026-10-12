"""Substack CLI — comment moderation: report, ban, and helper read commands.

New commands
------------
comments report <comment_id>         POST /api/v1/comment/{id}/report
comments report-user <user_id>       POST https://substack.com/api/v1/users/{id}/profile/report
comments ban <comment_id>            POST /api/v1/comment_ban/{id}
comments bans <user_id>              GET  /api/v1/user/{id}/bans  (read-only)
moderation report-categories         GET  https://substack.com/api/v1/reporting/flows
moderation delete-reasons            GET  /api/v1/comment/moderation/delete_reasons

All write commands are gated by is_write_enabled() AND default to
dry-run mode unless --no-dry-run / --yes is passed.

Endpoint notes (reverse-engineered from Substack web bundle):
  • comment report:      POST /api/v1/comment/{comment_id}/report
                         body: {publication_id, details, reportCategory,
                                reportedToSubstack, report_context}
  • profile report:      POST https://substack.com/api/v1/users/{user_id}/profile/report
                         body: {details, reportCategory, surface:"profile",
                                report_context}
  • ban:                 POST /api/v1/comment_ban/{comment_id}
                         body: {user_id, expiry, commentVisibility}
    commentVisibility enum (confirmed from bundle):
        "visible"              — keep comments visible
        "delete_all_comments"  — delete all user's comments
    expiry format: ISO-8601 datetime string (e.g. "2027-10-12T00:00:00Z");
        the bundle shows the UI passing an expiry value from a select whose
        result is later compared with isAfter(), confirming ISO datetime.
        Common durations: +1d, +30d, +90d, +365d, or a far-future date for
        "permanent" (bundle shows expiry > now()+100years → "permanently banned").
  • report_context:  shape not found in bundle; accepted as optional JSON
                     string; omit or pass null and the API ignores it.
"""
from __future__ import annotations

import json
from typing import Optional

import typer

from substack_cli.app import app, comments_app
from substack_cli.auth import (
    AuthError,
    is_write_enabled,
    resolve_cookies,
    resolve_publication_url,
)
from substack_cli.client import (
    SUBSTACK_COM,
    SubstackApiError,
    SubstackClient,
    emit_error,
    output,
)

# ---------------------------------------------------------------------------
# New top-level sub-app: moderation
# ---------------------------------------------------------------------------

moderation_app = typer.Typer(
    help="Comment moderation helpers: report categories, delete reasons.",
    no_args_is_help=True,
)
app.add_typer(moderation_app, name="moderation")

# ---------------------------------------------------------------------------
# Validated enum values
# ---------------------------------------------------------------------------

# reportCategory values confirmed from bundle module 74588
VALID_CATEGORIES = {
    "spam",
    "impersonation",
    "hate",
    "private_information",
    "plagiarism",
    "illegal_activity",
    "pornography",
    "other",
}

# commentVisibility values confirmed from bundle (ban UI toggle)
VALID_VISIBILITIES = {"visible", "delete_all_comments"}


# ---------------------------------------------------------------------------
# Helper: build client
# ---------------------------------------------------------------------------

def _make_client() -> SubstackClient:
    cookies = resolve_cookies()
    pub_url = resolve_publication_url()
    return SubstackClient(cookies=cookies, publication_url=pub_url)


def _resolve_pub_id(client: SubstackClient) -> Optional[int]:
    """Try to fetch the publication id from the /self profile endpoint.
    Returns None if unavailable (non-fatal for report commands)."""
    try:
        profile = client.get("/api/v1/publication/self")
        return profile.get("id")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DRY-RUN helper
# ---------------------------------------------------------------------------

def _dry_run_output(method: str, url: str, body: dict, pretty: bool) -> None:
    """Print the exact request that would be fired, then exit 0."""
    payload = {
        "dry_run": True,
        "method": method,
        "url": url,
        "body": body,
    }
    output(payload, pretty=pretty)


# ---------------------------------------------------------------------------
# Core logic functions (testable without CLI layer)
# ---------------------------------------------------------------------------

def report_comment(
    client: SubstackClient,
    comment_id: int,
    category: str,
    details: str,
    reported_to_substack: bool,
    publication_id: Optional[int],
    report_context: Optional[str],
) -> dict:
    """Report a comment via POST /api/v1/comment/{comment_id}/report."""
    if not is_write_enabled():
        raise ValueError("Write operations require SUBSTACK_ENABLE_WRITE=true")
    body: dict = {
        "reportCategory": category,
        "details": details,
        "reportedToSubstack": reported_to_substack,
    }
    if publication_id is not None:
        body["publication_id"] = publication_id
    if report_context is not None:
        try:
            body["report_context"] = json.loads(report_context)
        except json.JSONDecodeError:
            body["report_context"] = report_context
    return client.post(f"/api/v1/comment/{comment_id}/report", json_body=body)


def report_user_profile(
    client: SubstackClient,
    user_id: int,
    category: str,
    details: str,
    reported_to_substack: bool,
    report_context: Optional[str],
) -> dict:
    """Report a user profile via POST https://substack.com/api/v1/users/{user_id}/profile/report."""
    if not is_write_enabled():
        raise ValueError("Write operations require SUBSTACK_ENABLE_WRITE=true")
    body: dict = {
        "reportCategory": category,
        "details": details,
        "reportedToSubstack": reported_to_substack,
        "surface": "profile",
    }
    if report_context is not None:
        try:
            body["report_context"] = json.loads(report_context)
        except json.JSONDecodeError:
            body["report_context"] = report_context
    return client.post(
        f"/api/v1/users/{user_id}/profile/report",
        host="A",
        json_body=body,
    )


def ban_commenter(
    client: SubstackClient,
    comment_id: int,
    user_id: int,
    expiry: str,
    comment_visibility: str,
) -> dict:
    """Ban a commenter via POST /api/v1/comment_ban/{comment_id}."""
    if not is_write_enabled():
        raise ValueError("Write operations require SUBSTACK_ENABLE_WRITE=true")
    if comment_visibility not in VALID_VISIBILITIES:
        raise ValueError(
            f"Invalid commentVisibility {comment_visibility!r}. "
            f"Must be one of: {sorted(VALID_VISIBILITIES)}"
        )
    body: dict = {
        "user_id": user_id,
        "expiry": expiry,
        "commentVisibility": comment_visibility,
    }
    return client.post(f"/api/v1/comment_ban/{comment_id}", json_body=body)


def get_user_bans(client: SubstackClient, user_id: int) -> dict:
    """Read bans for a user: GET /api/v1/user/{user_id}/bans."""
    return client.get(f"/api/v1/user/{user_id}/bans")


def get_report_categories(client: SubstackClient) -> dict:
    """GET https://substack.com/api/v1/reporting/flows — report category tree."""
    return client.get("/api/v1/reporting/flows", host="A")


def get_delete_reasons(client: SubstackClient) -> dict:
    """GET /api/v1/comment/moderation/delete_reasons."""
    return client.get("/api/v1/comment/moderation/delete_reasons")


# ---------------------------------------------------------------------------
# CLI: comments report
# ---------------------------------------------------------------------------

@comments_app.command("report")
def comments_report_cmd(
    comment_id: int = typer.Argument(..., help="Comment ID to report."),
    category: str = typer.Option(
        "spam",
        "--category", "-c",
        help=(
            "Report category. One of: spam, impersonation, hate, "
            "private_information, plagiarism, illegal_activity, pornography, other."
        ),
    ),
    details: str = typer.Option(
        "",
        "--details", "-d",
        help="Human-readable description of the violation.",
    ),
    to_substack: bool = typer.Option(
        True,
        "--to-substack/--no-to-substack",
        help="Whether to also report to Substack trust & safety.",
    ),
    report_context: Optional[str] = typer.Option(
        None,
        "--report-context",
        help=(
            "Optional JSON string for report_context field "
            "(shape unknown; omit in most cases)."
        ),
    ),
    no_dry_run: bool = typer.Option(
        False,
        "--no-dry-run",
        "--yes",
        help="Actually send the request. Omit to print the request and exit.",
    ),
    pretty: bool = typer.Option(False, "--pretty"),
):
    """Report a comment by ID. Dry-run by default (prints request without sending)."""
    if category not in VALID_CATEGORIES:
        emit_error(
            f"Invalid --category {category!r}. "
            f"Valid values: {sorted(VALID_CATEGORIES)}",
            pretty=pretty,
        )
    if not is_write_enabled():
        emit_error("Write operations require SUBSTACK_ENABLE_WRITE=true", pretty=pretty)

    try:
        client = _make_client()
        pub_id = _resolve_pub_id(client)

        body: dict = {
            "reportCategory": category,
            "details": details,
            "reportedToSubstack": to_substack,
        }
        if pub_id is not None:
            body["publication_id"] = pub_id
        if report_context is not None:
            try:
                body["report_context"] = json.loads(report_context)
            except json.JSONDecodeError:
                body["report_context"] = report_context

        url = f"{client._publication_url}/api/v1/comment/{comment_id}/report"

        if not no_dry_run:
            _dry_run_output("POST", url, body, pretty=pretty)
            return

        result = report_comment(
            client, comment_id, category, details, to_substack, pub_id, report_context
        )
        output(result, pretty=pretty)

    except (SubstackApiError, AuthError, ValueError) as exc:
        emit_error(str(exc), status_code=getattr(exc, "status_code", None), pretty=pretty)
    except Exception as exc:
        emit_error(f"Unexpected error: {exc}", pretty=pretty)


# ---------------------------------------------------------------------------
# CLI: comments report-user
# ---------------------------------------------------------------------------

@comments_app.command("report-user")
def comments_report_user_cmd(
    user_id: int = typer.Argument(..., help="User ID to report."),
    category: str = typer.Option(
        "spam",
        "--category", "-c",
        help=(
            "Report category. One of: spam, impersonation, hate, "
            "private_information, plagiarism, illegal_activity, pornography, other."
        ),
    ),
    details: str = typer.Option(
        "",
        "--details", "-d",
        help="Human-readable description of the violation.",
    ),
    to_substack: bool = typer.Option(
        True,
        "--to-substack/--no-to-substack",
        help="Whether to also report to Substack trust & safety.",
    ),
    report_context: Optional[str] = typer.Option(
        None,
        "--report-context",
        help="Optional JSON string for report_context field.",
    ),
    no_dry_run: bool = typer.Option(
        False,
        "--no-dry-run",
        "--yes",
        help="Actually send the request. Omit to print the request and exit.",
    ),
    pretty: bool = typer.Option(False, "--pretty"),
):
    """Report a user's profile. Dry-run by default."""
    if category not in VALID_CATEGORIES:
        emit_error(
            f"Invalid --category {category!r}. "
            f"Valid values: {sorted(VALID_CATEGORIES)}",
            pretty=pretty,
        )
    if not is_write_enabled():
        emit_error("Write operations require SUBSTACK_ENABLE_WRITE=true", pretty=pretty)

    try:
        body: dict = {
            "reportCategory": category,
            "details": details,
            "reportedToSubstack": to_substack,
            "surface": "profile",
        }
        if report_context is not None:
            try:
                body["report_context"] = json.loads(report_context)
            except json.JSONDecodeError:
                body["report_context"] = report_context

        url = f"{SUBSTACK_COM}/api/v1/users/{user_id}/profile/report"

        if not no_dry_run:
            _dry_run_output("POST", url, body, pretty=pretty)
            return

        client = _make_client()
        result = report_user_profile(
            client, user_id, category, details, to_substack, report_context
        )
        output(result, pretty=pretty)

    except (SubstackApiError, AuthError, ValueError) as exc:
        emit_error(str(exc), status_code=getattr(exc, "status_code", None), pretty=pretty)
    except Exception as exc:
        emit_error(f"Unexpected error: {exc}", pretty=pretty)


# ---------------------------------------------------------------------------
# CLI: comments ban
# ---------------------------------------------------------------------------

@comments_app.command("ban")
def comments_ban_cmd(
    comment_id: int = typer.Argument(..., help="Comment ID that triggered the ban."),
    user_id: int = typer.Option(..., "--user-id", "-u", help="User ID to ban."),
    expiry: str = typer.Option(
        ...,
        "--expiry",
        "-e",
        help=(
            "Ban expiry as ISO-8601 datetime string, e.g. "
            "2027-10-12T00:00:00Z for ~1 year, "
            "or 2126-10-12T00:00:00Z for permanent."
        ),
    ),
    visibility: str = typer.Option(
        "visible",
        "--visibility",
        help=(
            "Comment visibility after ban. "
            "'visible' (default) keeps comments; "
            "'delete_all_comments' removes them. "
            "Note: Substack reloads the page when visibility != 'visible'."
        ),
    ),
    no_dry_run: bool = typer.Option(
        False,
        "--no-dry-run",
        "--yes",
        help="Actually send the request. Omit to print the request and exit.",
    ),
    pretty: bool = typer.Option(False, "--pretty"),
):
    """Ban a commenter by comment ID. Dry-run by default."""
    if visibility not in VALID_VISIBILITIES:
        emit_error(
            f"Invalid --visibility {visibility!r}. "
            f"Must be one of: {sorted(VALID_VISIBILITIES)}",
            pretty=pretty,
        )
    if not is_write_enabled():
        emit_error("Write operations require SUBSTACK_ENABLE_WRITE=true", pretty=pretty)

    try:
        client = _make_client()

        body: dict = {
            "user_id": user_id,
            "expiry": expiry,
            "commentVisibility": visibility,
        }
        url = f"{client._publication_url}/api/v1/comment_ban/{comment_id}"

        if not no_dry_run:
            _dry_run_output("POST", url, body, pretty=pretty)
            return

        result = ban_commenter(client, comment_id, user_id, expiry, visibility)
        output(result, pretty=pretty)

    except (SubstackApiError, AuthError, ValueError) as exc:
        emit_error(str(exc), status_code=getattr(exc, "status_code", None), pretty=pretty)
    except Exception as exc:
        emit_error(f"Unexpected error: {exc}", pretty=pretty)


# ---------------------------------------------------------------------------
# CLI: comments bans  (READ-ONLY)
# ---------------------------------------------------------------------------

@comments_app.command("bans")
def comments_bans_cmd(
    user_id: int = typer.Argument(..., help="User ID to look up bans for."),
    pretty: bool = typer.Option(False, "--pretty"),
):
    """List existing bans for a user (read-only). GET /api/v1/user/{user_id}/bans."""
    try:
        client = _make_client()
        result = get_user_bans(client, user_id)
        output(result, pretty=pretty)
    except (SubstackApiError, AuthError) as exc:
        emit_error(str(exc), status_code=getattr(exc, "status_code", None), pretty=pretty)
    except Exception as exc:
        emit_error(f"Unexpected error: {exc}", pretty=pretty)


# ---------------------------------------------------------------------------
# CLI: moderation report-categories  (READ-ONLY)
# ---------------------------------------------------------------------------

@moderation_app.command("report-categories")
def moderation_report_categories_cmd(
    pretty: bool = typer.Option(False, "--pretty"),
):
    """Fetch Substack's reporting flow tree (report categories). Read-only."""
    try:
        client = _make_client()
        result = get_report_categories(client)
        output(result, pretty=pretty)
    except (SubstackApiError, AuthError) as exc:
        emit_error(str(exc), status_code=getattr(exc, "status_code", None), pretty=pretty)
    except Exception as exc:
        emit_error(f"Unexpected error: {exc}", pretty=pretty)


# ---------------------------------------------------------------------------
# CLI: moderation delete-reasons  (READ-ONLY)
# ---------------------------------------------------------------------------

@moderation_app.command("delete-reasons")
def moderation_delete_reasons_cmd(
    pretty: bool = typer.Option(False, "--pretty"),
):
    """Fetch comment deletion reason codes. Read-only."""
    try:
        client = _make_client()
        result = get_delete_reasons(client)
        output(result, pretty=pretty)
    except (SubstackApiError, AuthError) as exc:
        emit_error(str(exc), status_code=getattr(exc, "status_code", None), pretty=pretty)
    except Exception as exc:
        emit_error(f"Unexpected error: {exc}", pretty=pretty)
