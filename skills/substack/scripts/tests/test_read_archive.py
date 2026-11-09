"""Tests for substack_cli.read — archive listing, categories, sections."""
import httpx
import respx

from substack_cli.client import SubstackClient, SUBSTACK_COM
from substack_cli.read import get_archive, get_archive_page, list_categories, list_sections


@respx.mock
def test_get_archive_default_sort_new(fake_cookies, fake_publication_url):
    route = respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "title": "Post"}])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    result = get_archive(client)
    assert route.called
    assert result == [{"id": 1, "title": "Post"}]


@respx.mock
def test_get_archive_sort_top_changes_ordering_param(fake_cookies, fake_publication_url):
    route = respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    get_archive(client, sort="top")
    assert "sort" in route.calls[0].request.url.params
    assert route.calls[0].request.url.params["sort"] == "top"


@respx.mock
def test_get_archive_never_sends_offset(fake_cookies, fake_publication_url):
    """Substack rejects any `offset` on /api/v1/archive with 400; the compat
    kwarg must be swallowed, never forwarded."""
    route = respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    get_archive(client, offset=10, limit=5)
    params = route.calls[0].request.url.params
    assert "offset" not in params
    assert params["limit"] == "5"


@respx.mock
def test_get_archive_page_cursor_passed_through_and_next_cursor_returned(
    fake_cookies, fake_publication_url
):
    route = respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json={"posts": [{"id": 3}], "nextCursor": "c2"})
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    posts, next_cursor = get_archive_page(client, limit=1, cursor="c1")
    params = route.calls[0].request.url.params
    assert params["cursor"] == "c1"
    assert "offset" not in params
    assert posts == [{"id": 3}]
    assert next_cursor == "c2"


@respx.mock
def test_get_archive_page_omits_cursor_on_first_page(fake_cookies, fake_publication_url):
    route = respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json=[{"id": 1}])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    posts, next_cursor = get_archive_page(client)
    assert "cursor" not in route.calls[0].request.url.params
    assert posts == [{"id": 1}]
    assert next_cursor is None


@respx.mock
def test_get_archive_search_param_passed_through(fake_cookies, fake_publication_url):
    route = respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json=[])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    get_archive(client, search="AI")
    params = route.calls[0].request.url.params
    assert params["search"] == "AI"


@respx.mock
def test_get_archive_uses_extract_list_for_envelope_tolerance(fake_cookies, fake_publication_url):
    respx.get(f"{fake_publication_url}/api/v1/archive").mock(
        return_value=httpx.Response(200, json={"posts": [{"id": 1}], "hasMore": True})
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    result = get_archive(client)
    assert result == [{"id": 1}]


@respx.mock
def test_list_categories_hits_host_a(fake_cookies, fake_publication_url):
    route = respx.get(f"{SUBSTACK_COM}/api/v1/categories").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "name": "Tech"}])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    result = list_categories(client)
    assert route.called
    assert result == [{"id": 1, "name": "Tech"}]


@respx.mock
def test_list_sections_hits_publication_host(fake_cookies, fake_publication_url):
    route = respx.get(f"{fake_publication_url}/api/v1/publication/sections").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "name": "Default"}])
    )
    client = SubstackClient(cookies=fake_cookies, publication_url=fake_publication_url)
    result = list_sections(client)
    assert route.called
    assert result == [{"id": 1, "name": "Default"}]