"""Trigger safe, common lazy-loading interactions on the current page."""

from __future__ import annotations

import logging
import re

from playwright.async_api import Page

logger = logging.getLogger(__name__)
MAX_CLICKABLES = 5
ACTION_TIMEOUT_MS = 2000

async def dismiss_common_overlays(page: Page) -> None:
    """Dismiss visible, non-destructive consent and welcome dialogs."""
    try:
        close_buttons = page.locator(
            '[role="dialog"] button[aria-label*="close" i], '
            '[aria-modal="true"] button[aria-label*="close" i], '
            'mat-dialog-container button[aria-label*="close" i]'
        )
        if await close_buttons.count() and await close_buttons.first.is_visible():
            await close_buttons.first.click(timeout=ACTION_TIMEOUT_MS)
            logger.info("Dismissed a page overlay")

        buttons = page.locator(
            '[role="dialog"] button, [role="dialog"] [role="button"], '
            '[aria-modal="true"] button, [aria-modal="true"] [role="button"], '
            'mat-dialog-container button, mat-dialog-container [role="button"], '
            '.cc-dismiss, [aria-label*="dismiss" i]'
        )
        dismiss_labels = re.compile(
            r"\b(close|dismiss|accept|allow|continue|no thanks|not now|got it|okay|ok)\b",
            re.IGNORECASE,
        )
        for index in range(await buttons.count()):
            button = buttons.nth(index)
            if not await button.is_visible():
                continue
            label = " ".join(
                value or ""
                for value in (
                    await button.get_attribute("aria-label"),
                    await button.inner_text(),
                )
            )
            if dismiss_labels.search(label):
                try:
                    await button.click(timeout=ACTION_TIMEOUT_MS)
                    logger.info("Dismissed a page overlay")
                    break
                except Exception as exc:
                    logger.debug("Overlay control was not clickable: %s", exc)
                    continue

        # Some consent banners are not dialogs and expose only a class/ARIA label.
        consent = page.locator(".cc-dismiss, [aria-label*='dismiss' i]").first
        if await consent.count() and await consent.is_visible():
            await consent.click(timeout=ACTION_TIMEOUT_MS)
            logger.info("Dismissed a consent banner")
    except Exception as exc:
        logger.debug("Overlay dismissal skipped after browser error: %s", exc)

async def trigger_page_interactions(page: Page) -> None:
    """Scroll and activate up to five clearly safe expansion controls; never raise."""
    try:
        await dismiss_common_overlays(page)
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await page.wait_for_timeout(100)

        await page.evaluate(
            """() => {
              const safe = ['load more', 'show more', 'see more', 'view more',
                            'expand', 'read more'];
              const unsafe = ['delete', 'remove', 'cancel', 'unsubscribe',
                'purchase', 'buy', 'checkout', 'pay', 'submit', 'save',
                'confirm', 'send', 'logout', 'log out'];
              document.querySelectorAll('[data-idor-tag]')
                .forEach(el => el.removeAttribute('data-idor-tag'));
              [...document.querySelectorAll('button, [role=button], a')]
                .slice(0, 500)
                .forEach((el) => {
                  const text = (el.innerText
                    || el.getAttribute('aria-label') || '')
                    .trim().toLowerCase();
                  if (!text) return;
                  if (el.matches(':disabled,[aria-disabled=true]')) return;
                  if (el.closest('form')) return;
                  if (unsafe.some(word => text.includes(word))) return;
                  if (!safe.some(word => text.includes(word))) return;
                  el.setAttribute('data-idor-tag', 'candidate');
                });
              return document.querySelectorAll('[data-idor-tag]').length;
            }"""
        )

        clicked = 0
        candidates = page.locator("[data-idor-tag]")
        count = await candidates.count()
        for i in range(min(count, MAX_CLICKABLES)):
            try:
                await candidates.nth(i).click(timeout=ACTION_TIMEOUT_MS)
                clicked += 1
            except Exception as exc:
                logger.debug("Safe interaction %d was not clicked: %s", i, exc)
                continue
        logger.info("Page interactions complete (clicked %d safe controls)", clicked)
    except Exception as exc:
        logger.debug("Page interaction skipped after browser error: %s", exc)
    finally:
        try:
            await page.evaluate(
                "() => document.querySelectorAll('[data-idor-tag]')"
                ".forEach(el => el.removeAttribute('data-idor-tag'))"
            )
        except Exception:
            pass