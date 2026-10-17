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
    monkeypatch.setattr(auth, "STATE_PATH", tmp_path / "auth_state.json")
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


def test_state_paths_are_anchored_to_repo_root(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert auth.STATE_PATH == auth.ROOT / "auth_state.json"
    assert auth.ERRORS_PATH == auth.ROOT / "errors.log"
    assert auth.STATE_PATH.is_absolute()
    assert auth.ERRORS_PATH.is_absolute()
    assert (auth.ROOT / "src" / "discovery" / "auth.py").is_file()


@pytest.mark.asyncio
async def test_clicks_lazy_show_more_exactly_once_and_cleans_tags():
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.set_content('''<button id="more">Show more</button>
          <div id="lazy"></div>
          <script>
            window.clicks = 0;
            document.querySelector('#more').addEventListener('click', () => {
              window.clicks++;
              document.querySelector('#more').remove();
              const p = document.createElement('p');
              p.textContent = 'lazy item';
              document.querySelector('#lazy').appendChild(p);
            });
          </script>''')
        await trigger_page_interactions(page)
        assert await page.evaluate("window.clicks") == 1
        assert await page.evaluate("document.querySelectorAll('#lazy p').length") == 1
        assert await page.evaluate("document.querySelectorAll('[data-idor-tag]').length") == 0
        await browser.close()


@pytest.mark.asyncio
async def test_clicked_never_exceeds_max_clickables():
    buttons = "".join('<button class="more">Load more</button>' for _ in range(10))
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.set_content(f'''{buttons}
          <script>
            window.clicks = 0;
            document.querySelectorAll('.more').forEach(
              (b) => b.addEventListener('click', () => window.clicks++));
          </script>''')
        await trigger_page_interactions(page)
        clicks = await page.evaluate("window.clicks")
        assert clicks <= 5
        assert clicks == 5
        assert await page.evaluate("document.querySelectorAll('[data-idor-tag]').length") == 0
        await browser.close()

