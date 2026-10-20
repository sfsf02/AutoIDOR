"""Trigger safe, common lazy-loading interactions on the current page."""

from __future__ import annotations

import logging

from playwright.async_api import Page

logger = logging.getLogger(__name__)
MAX_CLICKABLES = 5
ACTION_TIMEOUT_MS = 350

async def trigger_page_interactions(page: Page) -> None:
    """Scroll and activate up to five clearly safe expansion controls; never raise."""
    try:
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await page.wait_for_timeout(100)

        controls = page.locator("button, [role=button], a")
        safe_indices = await page.evaluate(
            """() => {
              const safe = ['load more', 'show more', 'see more', 'view more', 'expand', 'read more'];
              const unsafe = ['delete', 'remove', 'cancel', 'unsubscribe', 'purchase', 'buy',
                'checkout', 'pay', 'submit', 'save', 'confirm', 'send', 'logout', 'log out'];
              return [...document.querySelectorAll('button, [role=button], a')].slice(0, 500)
                .map((el, index) => ({el, index, text: (el.innerText || el.getAttribute('aria-label') || '').trim().toLowerCase()}))
                .filter(({el, text}) => text && !el.matches(':disabled,[aria-disabled=true]') &&
                  !el.closest('form') && !unsafe.some(word => text.includes(word)) &&
                  safe.some(word => text.includes(word)))
                .map(({index}) => index);
            }"""
        )
        clicked = 0
        for index in safe_indices:
            if clicked >= MAX_CLICKABLES:
                break
            control = controls.nth(index)
            try:
                await control.click(timeout=ACTION_TIMEOUT_MS)
                clicked += 1
            except Exception:
                continue
        logger.info("Page interactions complete (clicked %d safe controls)", clicked)
    except Exception as exc:
        logger.debug("Page interaction skipped after browser error: %s", exc)

