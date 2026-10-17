"""Best-effort authentication setup for the discovery browser."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Page

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # Environment variables can still be supplied by the shell.
    pass

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = ROOT / "auth_state.json"
ERRORS_PATH = ROOT / "errors.log"


def _log_failure(message: str, exc: Exception) -> None:
    logger.warning("%s: %s", message, exc)
    try:
        with ERRORS_PATH.open("a", encoding="utf-8") as errors:
            errors.write(f"{message}: {exc}\n")
    except OSError:
        logger.exception("Could not write authentication failure to errors.log")


async def _restore_state(page: Page, state: dict[str, Any]) -> None:
    context = page.context
    cookies = state.get("cookies", [])
    if cookies:
        await context.add_cookies(cookies)

    # Playwright's storage_state is normally supplied when creating a context.
    # Person B receives an already-created Page, so restore local storage in-place.
    origins = state.get("origins", [])
    current_origin = urlparse(page.url).netloc
    for origin in origins:
        origin_url = urlparse(origin.get("origin", ""))
        if origin_url.netloc != current_origin or not origin_url.scheme:
            continue
        values = origin.get("localStorage", [])
        await page.evaluate(
            "items => { for (const item of items) localStorage.setItem(item.name, item.value); }",
            values,
        )


async def login_if_needed(page: Page) -> None:
    """Restore a saved session or sign in with configured credentials; never raise."""
    try:
        if STATE_PATH.is_file():
            state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            await _restore_state(page, state)
            logger.info("Restored authentication state from %s", STATE_PATH)
            return

        login_url = os.getenv("LOGIN_URL")
        username = os.getenv("LOGIN_USERNAME")
        password = os.getenv("LOGIN_PASSWORD")
        if not all((login_url, username, password)):
            logger.info("Login skipped: LOGIN_URL, LOGIN_USERNAME, and LOGIN_PASSWORD are required")
            return

        await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
        user_field = page.locator(
            'input[autocomplete="username"], input[type="email"], input[name*="user" i], input[name*="email" i]'
        ).first
        password_field = page.locator('input[autocomplete="current-password"], input[type="password"]').first
        await user_field.fill(username, timeout=5000)
        await password_field.fill(password, timeout=5000)

        submit = page.locator(
            'button[type="submit"], input[type="submit"], button:has-text("Log in"), '
            'button:has-text("Login"), button:has-text("Sign in")'
        ).first
        await submit.click(timeout=5000)
        await page.wait_for_load_state("domcontentloaded", timeout=5000)
        await page.context.storage_state(path=str(STATE_PATH))
        logger.info("Login completed; saved session to %s", STATE_PATH)
    except Exception as exc:
        _log_failure("Authentication setup failed", exc)

