"""Focused checks for Person B's authentication and interaction hooks."""

import json

import pytest
from playwright.async_api import async_playwright

from src.discovery import auth
from src.discovery.interactions import trigger_page_interactions


@pytest.mark.asyncio
async def test_missing_credentials_is_noop(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for key in ("LOGIN_URL", "LOGIN_USERNAME", "LOGIN_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await auth.login_if_needed(page)
        assert page.url == "about:blank"
        await browser.close()


@pytest.mark.asyncio
async def test_existing_state_restores_cookies(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    auth.STATE_PATH = tmp_path / "auth_state.json"
    auth.STATE_PATH.write_text(json.dumps({"cookies": [{
        "name": "session", "value": "saved", "domain": "127.0.0.1",
        "path": "/", "expires": -1, "httpOnly": False, "secure": False,
        "sameSite": "Lax",
    }], "origins": []}), encoding="utf-8")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await auth.login_if_needed(page)
        cookies = await page.context.cookies()
        assert any(cookie["name"] == "session" and cookie["value"] == "saved" for cookie in cookies)
        await browser.close()


@pytest.mark.asyncio
async def test_clicks_safe_expander_and_skips_form_controls():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.set_content('''<button id="expand">Expand details</button>
          <form><button id="submit">Load more</button></form>
          <script>window.expanded = 0; document.querySelector('#expand').onclick = () => window.expanded++;</script>''')
        await trigger_page_interactions(page)
        assert await page.evaluate("window.expanded") == 1
        assert await page.evaluate("document.querySelector('#submit').form !== null")
        await browser.close()

