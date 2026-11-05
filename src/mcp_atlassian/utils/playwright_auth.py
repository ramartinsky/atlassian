"""Browser-backed authentication for Atlassian SSO deployments."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import requests

logger = logging.getLogger("mcp-atlassian.playwright-auth")

DEFAULT_LOGIN_URL = "https://id.atlassian.com/login/saml/start"
ServiceName = Literal["jira", "confluence"]


class PlaywrightAuthenticationError(RuntimeError):
    """Raised when browser-based Atlassian authentication cannot complete."""


@dataclass(frozen=True)
class PlaywrightLoginConfig:
    """Configuration required to establish an Atlassian browser session."""

    username: str
    password: str
    service_url: str
    login_url: str | None = None
    connection: str | None = None
    application: str | None = None
    org_id: str | None = None
    service: ServiceName = "jira"
    timeout_seconds: int = 120


def build_login_url(
    *,
    login_url: str | None,
    connection: str | None,
    application: str | None,
    org_id: str | None,
) -> str:
    """Build and validate the Atlassian SAML login URL.

    The three SAML query parameters may be supplied separately or embedded in
    ``login_url``. Explicit values replace matching values already in the URL.
    """
    configured_url = login_url or DEFAULT_LOGIN_URL
    parsed = urlsplit(configured_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Playwright login URL must be an absolute HTTP or HTTPS URL.")

    query = parse_qs(parsed.query, keep_blank_values=True)
    explicit_params = {
        "connection": connection,
        "application": application,
        "orgId": org_id,
    }
    for name, value in explicit_params.items():
        if value is not None:
            query[name] = [value]

    missing = [
        name
        for name in ("connection", "application", "orgId")
        if not query.get(name) or not query[name][0]
    ]
    if missing:
        missing_text = ", ".join(missing)
        error_message = (
            "Playwright authentication requires the Atlassian SAML login "
            f"parameter(s): {missing_text}. Set them explicitly or include "
            "them in the login URL."
        )
        raise ValueError(error_message)

    encoded_query = urlencode(
        [(name, value) for name, values in query.items() for value in values],
    )
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, encoded_query, parsed.fragment)
    )


def login_with_playwright(config: PlaywrightLoginConfig) -> requests.Session:
    """Log in through a browser and return a requests session with its cookies.

    Playwright is imported lazily so installations using token, PAT, OAuth, or
    external authentication do not need a browser runtime.
    """
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise PlaywrightAuthenticationError(
            "Playwright authentication requires the 'playwright' package. "
            "Install the project with its Playwright dependency and run "
            "`python -m playwright install chromium`."
        ) from exc

    login_url = build_login_url(
        login_url=config.login_url,
        connection=config.connection,
        application=config.application,
        org_id=config.org_id,
    )
    timeout_ms = config.timeout_seconds * 1000
    logger.info("Starting Playwright authentication for %s.", config.service)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
                page.set_default_timeout(timeout_ms)
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
                _complete_login(
                    page,
                    email=config.username,
                    password=config.password,
                    origin_base_url=config.service_url,
                    timeout_ms=timeout_ms,
                    timeout_error=PlaywrightTimeoutError,
                )
                _wait_for_session(
                    context,
                    page,
                    service=config.service,
                    service_url=config.service_url,
                    timeout_seconds=config.timeout_seconds,
                    timeout_error=PlaywrightTimeoutError,
                    transient_errors=(PlaywrightError, PlaywrightTimeoutError),
                )
                session = _requests_session_from_browser_context(context)
            finally:
                browser.close()
    except PlaywrightAuthenticationError:
        raise
    except (PlaywrightError, PlaywrightTimeoutError) as exc:
        error_message = (
            f"Atlassian Playwright authentication failed. Last browser error: {exc}"
        )
        raise PlaywrightAuthenticationError(error_message) from exc

    logger.info("Playwright authentication completed for %s.", config.service)
    return session


def _complete_login(
    page: Any,
    *,
    email: str,
    password: str,
    origin_base_url: str,
    timeout_ms: int,
    timeout_error: type[BaseException],
) -> None:
    deadline = time.monotonic() + timeout_ms / 1000
    email_selectors = [
        "#username",
        "input[name='username']",
        "input[type='email']",
        "#i0116",
        "input[name='loginfmt']",
    ]
    password_selectors = [
        "#password",
        "input[name='password']",
        "input[type='password']",
        "#i0118",
    ]
    submit_selectors = [
        "#login-submit",
        "#idSIButton9",
        "button[type='submit']",
        "input[type='submit']",
        "button:has-text('Continue')",
        "button:has-text('Next')",
    ]

    if _is_same_origin(page.url, origin_base_url):
        return

    if _fill_first_visible(
        page,
        selectors=email_selectors,
        value=email,
        timeout_ms=min(1_000, _remaining_ms(deadline)),
        timeout_error=timeout_error,
    ):
        if not _click_first_visible(
            page,
            selectors=submit_selectors,
            timeout_ms=min(1_000, _remaining_ms(deadline)),
            timeout_error=timeout_error,
        ):
            raise PlaywrightAuthenticationError(
                "Could not submit the Atlassian SSO email form."
            )

    while time.monotonic() < deadline:
        if _is_same_origin(page.url, origin_base_url):
            return
        if _is_post_login_atlassian_page(page.url):
            # SSO may land on home.atlassian.com; visit the site to obtain its cookies.
            page.goto(
                origin_base_url,
                wait_until="domcontentloaded",
                timeout=_remaining_ms(deadline),
            )
            continue

        _decline_stay_signed_in(page, timeout_ms=500, timeout_error=timeout_error)
        if _fill_first_visible(
            page,
            selectors=password_selectors,
            value=password,
            timeout_ms=min(1_000, _remaining_ms(deadline)),
            timeout_error=timeout_error,
        ):
            if not _click_first_visible(
                page,
                selectors=submit_selectors,
                timeout_ms=min(1_000, _remaining_ms(deadline)),
                timeout_error=timeout_error,
            ):
                raise PlaywrightAuthenticationError(
                    "Could not submit the Atlassian SSO password form."
                )
            continue

        time.sleep(0.5)

    error_message = (
        "Atlassian Playwright authentication did not complete before timeout. "
        f"Last page: {_safe_page_state(page)}"
    )
    raise PlaywrightAuthenticationError(error_message)


def _wait_for_session(
    context: Any,
    page: Any,
    *,
    service: ServiceName,
    service_url: str,
    timeout_seconds: int,
    timeout_error: type[BaseException],
    transient_errors: tuple[type[BaseException], ...],
) -> None:
    deadline = time.monotonic() + timeout_seconds
    endpoint = "/rest/api/3/myself" if service == "jira" else "/rest/api/user/current"
    session_url = f"{service_url.rstrip('/')}{endpoint}"

    while time.monotonic() < deadline:
        _decline_stay_signed_in(page, timeout_ms=500, timeout_error=timeout_error)
        try:
            response = context.request.get(session_url, timeout=5_000)
        except transient_errors as exc:
            logger.debug("Browser session check failed: %s", exc)
        else:
            response_path = urlsplit(response.url).path
            expected_path = urlsplit(session_url).path
            if (
                response.status == 200
                and _is_same_origin(response.url, service_url)
                and response_path == expected_path
            ):
                return
        time.sleep(1)

    error_message = (
        f"{service.title()} browser session was not established within "
        f"{timeout_seconds} seconds. Last page: {_safe_page_state(page)}"
    )
    raise PlaywrightAuthenticationError(error_message)


def _click_first_visible(
    page: Any,
    *,
    selectors: list[str],
    timeout_ms: int,
    timeout_error: type[BaseException],
) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            locator.wait_for(state="visible", timeout=timeout_ms)
            locator.click()
            return True
        except timeout_error:
            continue
    return False


def _fill_first_visible(
    page: Any,
    *,
    selectors: list[str],
    value: str,
    timeout_ms: int,
    timeout_error: type[BaseException],
) -> bool:
    for selector in selectors:
        try:
            locator = page.locator(selector).first
            locator.wait_for(state="visible", timeout=timeout_ms)
            locator.fill(value)
            return True
        except timeout_error:
            continue
    return False


def _decline_stay_signed_in(
    page: Any,
    *,
    timeout_ms: int,
    timeout_error: type[BaseException],
) -> bool:
    return _click_first_visible(
        page,
        selectors=[
            "#idBtn_Back",
            "input[value='No']",
            "button:has-text('No')",
        ],
        timeout_ms=timeout_ms,
        timeout_error=timeout_error,
    )


def _requests_session_from_browser_context(context: Any) -> requests.Session:
    session = requests.Session()
    for cookie in context.cookies():
        cookie_kwargs: dict[str, str] = {
            "name": cookie["name"],
            "value": cookie["value"],
            "path": cookie.get("path", "/"),
        }
        if cookie.get("domain"):
            cookie_kwargs["domain"] = cookie["domain"]
        session.cookies.set(**cookie_kwargs)
    return session


def _remaining_ms(deadline: float) -> int:
    return max(1, int((deadline - time.monotonic()) * 1000))


def _is_same_origin(url: str, base_url: str) -> bool:
    current = urlsplit(url)
    base = urlsplit(base_url)
    return current.scheme == base.scheme and current.netloc == base.netloc


_POST_LOGIN_ATLASSIAN_HOSTS = frozenset(
    {"home.atlassian.com", "start.atlassian.com", "admin.atlassian.com"}
)


def _is_post_login_atlassian_page(url: str) -> bool:
    return urlsplit(url).hostname in _POST_LOGIN_ATLASSIAN_HOSTS


def _safe_page_state(page: Any) -> str:
    parsed = urlsplit(page.url)
    safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    title = page.title()
    return f"url={safe_url!r}, title={title!r}"
