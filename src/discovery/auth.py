"""Best-effort authentication setup for the discovery browser."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from playwright.async_api import Browser, Page, async_playwright

from src.discovery.interactions import dismiss_common_overlays

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # Environment variables can still be supplied by the shell.
    pass

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = ROOT / "auth_state.json"
ERRORS_PATH = ROOT / "errors.log"
IDENTITY_SETTINGS = {
    "victim": ("VICTIM_USERNAME", "VICTIM_PASSWORD", "VICTIM_AUTH_STATE_PATH"),
    "attacker": ("ATTACKER_USERNAME", "ATTACKER_PASSWORD", "ATTACKER_AUTH_STATE_PATH"),
}


def write_auth_metadata(metadata_path: Path, origin: str) -> None:
    """Write target metadata next to a browser authentication state."""
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = metadata_path.with_suffix(metadata_path.suffix + ".tmp")
    metadata = {
        "origin": origin,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        temporary_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        temporary_path.replace(metadata_path)
    except OSError:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def get_identity_settings(identity: str = "victim") -> tuple[str | None, str | None, Path]:
    """Return credentials and state path for a configured test identity."""
    try:
        username_key, password_key, state_key = IDENTITY_SETTINGS[identity]
    except KeyError as exc:
        raise ValueError(f"Unknown authentication identity: {identity}") from exc

    username = os.getenv(username_key)
    password = os.getenv(password_key)
    if identity == "victim":
        username = username or os.getenv("LOGIN_USERNAME")
        password = password or os.getenv("LOGIN_PASSWORD")

    configured_path = os.getenv(state_key)
    state_path = Path(configured_path).expanduser() if configured_path else (
        ROOT / ("auth_state_victim.json" if identity == "victim" else "auth_state_attacker.json")
    )
    if not state_path.is_absolute():
        state_path = ROOT / state_path
    return username, password, state_path


def resolve_login_url(login_url: str, origin: str | None = None) -> str:
    """Resolve an absolute or origin-relative login URL."""
    if urlparse(login_url).scheme:
        return login_url
    if not origin:
        raise ValueError("A target origin is required for a relative LOGIN_URL")
    return urljoin(origin.rstrip("/") + "/", login_url.lstrip("/"))


def _log_failure(message: str, exc: Exception, errors_path: Path = ERRORS_PATH) -> None:
    logger.warning("%s: %s", message, exc)
    try:
        with errors_path.open("a", encoding="utf-8") as errors:
            errors.write(f"{message}: {exc}\n")
    except OSError:
        logger.exception("Could not write authentication failure to errors.log")


async def _restore_state(page: Page, state: dict[str, Any]) -> None:
    context = page.context
    cookies = state.get("cookies", [])
    if cookies:
        await context.add_cookies(cookies)

    # Playwright's storage_state is normally supplied when creating a context.
    # Person B receives an already-created Page, so navigate it to each origin
    # before restoring local storage.
    origins = state.get("origins", [])
    current_origin = urlparse(page.url)
    for origin in origins:
        origin_value = origin.get("origin", "")
        origin_url = urlparse(origin_value)
        if not origin_url.scheme or not origin_url.netloc:
            continue
        if current_origin.scheme and (
            origin_url.scheme != current_origin.scheme
            or origin_url.netloc != current_origin.netloc
        ):
            logger.warning(
                "Skipping localStorage restore for origin %s (page origin is %s)",
                origin_url.geturl(),
                current_origin.geturl(),
            )
            continue
        if not current_origin.scheme or not current_origin.netloc:
            await page.goto(origin_value, wait_until="domcontentloaded", timeout=15000)
        values = origin.get("localStorage", [])
        await page.evaluate(
            "items => { for (const item of items) localStorage.setItem(item.name, item.value); }",
            values,
        )


async def login_if_needed(
    page: Page,
    state_path: Path | None = None,
    errors_path: Path | None = None,
    identity: str = "victim",
    target_origin: str | None = None,
    force_login: bool = False,
) -> bool:
    """Restore a saved session or sign in with configured credentials."""
    state_file = state_path or STATE_PATH
    errors_file = errors_path or ERRORS_PATH
    try:
        if state_file.is_file() and not force_login:
            state = json.loads(state_file.read_text(encoding="utf-8"))
            await _restore_state(page, state)
            logger.info("Restored authentication state from %s", state_file)
            return bool(state.get("cookies") or state.get("origins"))

        login_url = os.getenv("LOGIN_URL")
        username, password, configured_state_path = get_identity_settings(identity)
        state_file = state_path or configured_state_path
        if not all((login_url, username, password)):
            logger.info("Login skipped: LOGIN_URL and credentials for %s are required", identity)
            return False

        await page.goto(
            resolve_login_url(login_url, target_origin),
            wait_until="domcontentloaded",
            timeout=15000,
        )
        await page.wait_for_timeout(500)
        await dismiss_common_overlays(page)
        user_field = page.locator(
            'input[autocomplete="username"], input[type="email"], input[name*="user" i], input[name*="email" i]'
        ).first
        password_field = page.locator('input[autocomplete="current-password"], input[type="password"]').first
        await user_field.fill(username, timeout=5000)
        await password_field.fill(password, timeout=5000)

        await dismiss_common_overlays(page)
        submit = page.locator(
            'button[type="submit"], input[type="submit"], button:has-text("Log in"), '
            'button:has-text("Login"), button:has-text("Sign in")'
        ).first
        await submit.click(timeout=5000)
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            logger.debug("Login did not trigger a full document navigation")

        error_banner = page.locator("[role=alert], .error, .alert-danger").first
        if await error_banner.count() > 0:
            text = (await error_banner.inner_text()).strip()
            raise RuntimeError(f"Login failed — page shows: {text!r}")

        state_file.parent.mkdir(parents=True, exist_ok=True)
        await page.context.storage_state(path=str(state_file))
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if not state.get("cookies") and not state.get("origins"):
            raise RuntimeError("Login completed without producing browser authentication state")
        logger.info("Login completed; saved session to %s", state_file)
        return True
    except Exception as exc:
        _log_failure("Authentication setup failed", exc, errors_file)
        return False


async def create_auth_state(
    browser: Browser,
    identity: str,
    state_path: Path,
    target_origin: str | None = None,
    errors_path: Path | None = None,
) -> bool:
    """Create a fresh browser state for one configured identity."""
    context = await browser.new_context()
    page = await context.new_page()
    try:
        return await login_if_needed(
            page,
            state_path=state_path,
            errors_path=errors_path,
            identity=identity,
            target_origin=target_origin,
            force_login=True,
        )
    finally:
        await context.close()


def refresh_auth_state(
    identity: str,
    state_path: Path,
    target_origin: str | None = None,
    errors_path: Path | None = None,
) -> bool:
    """Refresh one identity's state once using a browser login."""
    async def run() -> bool:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                return await create_auth_state(
                    browser,
                    identity,
                    state_path,
                    target_origin=target_origin,
                    errors_path=errors_path,
                )
            finally:
                await browser.close()

    return asyncio.run(run())