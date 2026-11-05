"""Tests for browser-backed Atlassian authentication helpers."""

import asyncio
import threading
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest
from requests import Session

from mcp_atlassian.confluence.client import ConfluenceClient
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira.client import JiraClient
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.playwright_auth import (
    PlaywrightAuthenticationError,
    PlaywrightLoginConfig,
    _is_post_login_atlassian_page,
    build_login_url,
    clear_playwright_session_cache,
    get_playwright_session,
    login_with_playwright,
)


def test_build_login_url_maps_saml_parameters() -> None:
    url = build_login_url(
        login_url="https://id.atlassian.com/login/saml/start",
        connection="connection-id",
        application="application-id",
        org_id="org-id",
    )

    assert (
        url == "https://id.atlassian.com/login/saml/start?"
        "connection=connection-id&application=application-id&orgId=org-id"
    )


def test_build_login_url_accepts_parameters_embedded_in_url() -> None:
    url = build_login_url(
        login_url=(
            "https://id.atlassian.com/login/saml/start?"
            "connection=connection-id&application=application-id&orgId=org-id"
        ),
        connection=None,
        application=None,
        org_id=None,
    )

    assert "connection=connection-id" in url
    assert "application=application-id" in url
    assert "orgId=org-id" in url


def test_build_login_url_rejects_missing_saml_parameters() -> None:
    with pytest.raises(ValueError, match="connection, application, orgId"):
        build_login_url(
            login_url=None,
            connection=None,
            application=None,
            org_id=None,
        )


def test_login_with_playwright_reports_missing_dependency() -> None:
    config = PlaywrightLoginConfig(
        username="user@example.com",
        password="password",
        service_url="https://example.atlassian.net",
        connection="connection-id",
        application="application-id",
        org_id="org-id",
    )

    with patch.dict("sys.modules", {"playwright": None, "playwright.sync_api": None}):
        with pytest.raises(
            PlaywrightAuthenticationError, match="requires the 'playwright' package"
        ):
            login_with_playwright(config)


def test_login_with_playwright_copies_browser_cookies() -> None:
    config = PlaywrightLoginConfig(
        username="user@example.com",
        password="password",
        service_url="https://example.atlassian.net",
        connection="connection-id",
        application="application-id",
        org_id="org-id",
    )
    browser = MagicMock()
    context = browser.new_context.return_value
    page = context.new_page.return_value
    page.url = "https://example.atlassian.net"
    context.cookies.return_value = [
        {"name": "cloud.session.token", "value": "session", "domain": ".atlassian.net"}
    ]
    context.request.get.return_value.status = 200
    context.request.get.return_value.url = (
        "https://example.atlassian.net/rest/api/3/myself"
    )

    playwright = MagicMock()
    playwright.chromium.launch.return_value = browser
    playwright_context = MagicMock()
    playwright_context.__enter__.return_value = playwright
    playwright_context.__exit__.return_value = False

    with patch("playwright.sync_api.sync_playwright", return_value=playwright_context):
        with patch("playwright.sync_api.Error", Exception):
            with patch("playwright.sync_api.TimeoutError", TimeoutError):
                session = login_with_playwright(config)

    assert session.cookies.get("cloud.session.token") == "session"
    browser.close.assert_called_once()


def test_jira_client_uses_browser_session() -> None:
    browser_session = Session()
    config = JiraConfig(
        url="https://example.atlassian.net",
        auth_type="playwright",
        username="user@example.com",
        password="password",
        playwright_connection="connection-id",
        playwright_application="application-id",
        playwright_org_id="org-id",
    )

    with (
        patch("mcp_atlassian.jira.client.Jira") as jira_class,
        patch(
            "mcp_atlassian.jira.client.get_playwright_session",
            return_value=browser_session,
        ) as login,
        patch("mcp_atlassian.jira.client.configure_ssl_verification"),
    ):
        JiraClient(config)

    login.assert_called_once()
    assert login.call_args.args[0].service == "jira"
    jira_class.assert_called_once_with(
        url=config.url,
        session=browser_session,
        cloud=True,
        verify_ssl=True,
        timeout=75,
    )


def test_confluence_client_uses_browser_session() -> None:
    browser_session = Session()
    config = ConfluenceConfig(
        url="https://example.atlassian.net/wiki",
        auth_type="playwright",
        username="user@example.com",
        password="password",
        playwright_connection="connection-id",
        playwright_application="application-id",
        playwright_org_id="org-id",
    )

    with (
        patch("mcp_atlassian.confluence.client.Confluence") as confluence_class,
        patch(
            "mcp_atlassian.confluence.client.get_playwright_session",
            return_value=browser_session,
        ) as login,
        patch("mcp_atlassian.confluence.client.configure_ssl_verification"),
    ):
        ConfluenceClient(config)

    login.assert_called_once()
    assert login.call_args.args[0].service == "confluence"
    confluence_class.assert_called_once_with(
        url=config.url,
        session=browser_session,
        cloud=True,
        verify_ssl=True,
        timeout=75,
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://home.atlassian.com/", True),
        ("https://start.atlassian.com/?x=1", True),
        ("https://id.atlassian.com/login", False),
        ("https://login.microsoftonline.com/kmsi", False),
        ("https://example.atlassian.net/wiki", False),
    ],
)
def test_is_post_login_atlassian_page(url: str, expected: bool) -> None:  # noqa: FBT001
    assert _is_post_login_atlassian_page(url) is expected


@pytest.fixture
def clean_session_cache() -> Iterator[None]:
    clear_playwright_session_cache()
    yield
    clear_playwright_session_cache()


def _login_config(password: str = "secret") -> PlaywrightLoginConfig:
    return PlaywrightLoginConfig(
        username="user@example.com",
        password=password,
        service_url="https://example.atlassian.net",
        connection="connection-id",
        application="application-id",
        org_id="org-id",
    )


def _browser_session(token: str) -> Session:
    session = Session()
    session.cookies.set("cloud.session.token", token, domain=".atlassian.net")
    return session


@pytest.mark.usefixtures("clean_session_cache")
def test_get_playwright_session_reuses_valid_cached_cookies() -> None:
    config = _login_config()
    with (
        patch(
            "mcp_atlassian.utils.playwright_auth.login_with_playwright",
            return_value=_browser_session("first"),
        ) as login,
        patch.object(Session, "get") as session_get,
    ):
        session_get.return_value.status_code = 200
        first = get_playwright_session(config)
        second = get_playwright_session(config)

    login.assert_called_once()
    assert first is not second
    assert second.cookies.get("cloud.session.token") == "first"
    session_get.assert_called_once()
    assert session_get.call_args.args[0] == (
        "https://example.atlassian.net/rest/api/3/myself"
    )
    assert session_get.call_args.kwargs["allow_redirects"] is False


@pytest.mark.usefixtures("clean_session_cache")
def test_get_playwright_session_logs_in_again_when_cookies_expire() -> None:
    config = _login_config()
    with (
        patch(
            "mcp_atlassian.utils.playwright_auth.login_with_playwright",
            side_effect=[_browser_session("first"), _browser_session("second")],
        ) as login,
        patch.object(Session, "get") as session_get,
    ):
        session_get.return_value.status_code = 302
        get_playwright_session(config)
        refreshed = get_playwright_session(config)

    assert login.call_count == 2
    assert refreshed.cookies.get("cloud.session.token") == "second"


@pytest.mark.usefixtures("clean_session_cache")
def test_get_playwright_session_separates_credentials() -> None:
    with patch(
        "mcp_atlassian.utils.playwright_auth.login_with_playwright",
        side_effect=[_browser_session("first"), _browser_session("second")],
    ) as login:
        get_playwright_session(_login_config("first-password"))
        get_playwright_session(_login_config("second-password"))

    assert login.call_count == 2


def test_login_with_playwright_runs_in_worker_thread_inside_event_loop() -> None:
    config = _login_config()
    caller_thread = threading.get_ident()
    login_threads: list[int] = []

    def fake_login(_: PlaywrightLoginConfig) -> Session:
        login_threads.append(threading.get_ident())
        return _browser_session("token")

    async def call_from_event_loop() -> Session:
        return login_with_playwright(config)

    with patch(
        "mcp_atlassian.utils.playwright_auth._login_with_playwright",
        side_effect=fake_login,
    ):
        session = asyncio.run(call_from_event_loop())
        login_with_playwright(config)

    assert session.cookies.get("cloud.session.token") == "token"
    assert login_threads[0] != caller_thread
    assert login_threads[1] == caller_thread
