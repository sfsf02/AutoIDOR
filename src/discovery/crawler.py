"""
Phase 1 IDOR Endpoint Mapper - Crawler Module
Handles BFS traversal, link extraction, and state management.
"""

import asyncio
import argparse
import json
import logging
import os
import sys
from collections import deque
from datetime import datetime
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv
from playwright.async_api import async_playwright, Page, BrowserContext

try:
    from src.discovery.auth import login_if_needed
    from src.discovery.interactions import trigger_page_interactions
except ImportError:
    # Safe fallbacks if Two function has not implmented yet
    async def login_if_needed(page: Page) -> None: pass
    async def trigger_page_interactions(page: Page) -> None: pass

# Configure logging for progress and general info
logging.basicConfig(level=logging.INFO, format="%(message)s")

SKIP_EXTENSIONS = {
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".mp4", ".mp3",
    ".css", ".js", ".svg", ".woff", ".woff2", ".ico", ".xml"
}

def normalize_url(url: str) -> str:
    """
    Normalizes a URL by removing the fragment, lowercasing the domain,
    and stripping trailing slashes from the path (unless it's the root).
    """
    parsed = urlparse(url)
    
    # Remove fragment
    parsed = parsed._replace(fragment="")
    
    # Lowercase domain
    netloc = parsed.netloc.lower()
    
    # Strip trailing slash from path (but keep "/" if it's the root)
    path = parsed.path
    if path.endswith("/") and len(path) > 1:
        path = path.rstrip("/")
        
    parsed = parsed._replace(netloc=netloc, path=path)
    return urlunparse(parsed)

def get_dedup_key(url: str) -> str:
    """
    Extracts the scheme, domain, and path for deduplication, ignoring the query string.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def is_in_scope(url: str, scope: str) -> bool:
    """
    Checks if a given URL is within the target scope (allows subdomains).
    """
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    
    # Handle port numbers if present in the netloc
    if ":" in netloc:
        netloc = netloc.split(":")[0]
        
    scope = scope.lower()
    return netloc == scope or netloc.endswith("." + scope)

def should_skip(url: str, scope: str, visited_keys: Set[str]) -> bool:
    """
    Evaluates skip rules for a URL before adding it to the queue.
    """
    if len(url) > 2000:
        return True
        
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return True
        
    if not is_in_scope(url, scope):
        return True
        
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True
        
    dedup_key = get_dedup_key(url)
    if dedup_key in visited_keys:
        return True
        
    return False

async def crawl(start_url: str, scope: str, max_pages: int, max_depth: int, headful: bool, delay: float) -> None:
    """
    Executes the BFS crawl loop using Playwright.
    """
    proxy_host = os.getenv("PROXY_HOST")
    proxy_port = os.getenv("PROXY_PORT")
    proxy_settings = None
    if proxy_host and proxy_port:
        proxy_settings = {"server": f"http://{proxy_host}:{proxy_port}"}

    queue: deque[Tuple[str, int]] = deque()
    visited_keys: Set[str] = set()
    
    # Output structures
    results_urls: List[str] = []
    results_pages: List[Dict] = []
    errors: List[str] = []

    # Seed the queue
    normalized_start = normalize_url(start_url)
    queue.append((normalized_start, 0))
    visited_keys.add(get_dedup_key(normalized_start))

    pages_visited = 0

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=not headful)
        
        # Setup context with optional auth and proxy
        context_args = {}
        if proxy_settings:
            context_args["proxy"] = proxy_settings
            
        if os.path.exists("auth_state.json"):
            context_args["storage_state"] = "auth_state.json"
            
        context = await browser.new_context(**context_args)
        
        # Handle initial login if no auth state existed
        if not os.path.exists("auth_state.json"):
            login_page = await context.new_page()
            await login_if_needed(login_page)
            await login_page.close()

        try:
            while queue and pages_visited < max_pages:
                url, depth = queue.popleft()
                
                if depth > max_depth:
                    continue
                    
                # Strict scope assertion just before visiting
                if not is_in_scope(url, scope):
                    continue

                pages_visited += 1
                page = await context.new_page()
                
                try:
                    response = await page.goto(url, wait_until="load", timeout=15000)
                    status_code = response.status if response else 0
                    
                    # Trigger Person B's interaction hook
                    await trigger_page_interactions(page)
                    
                    # Extract links
                    raw_links = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                    
                    valid_links_count = 0
                    for raw_link in raw_links:
                        norm_link = normalize_url(raw_link)
                        if not should_skip(norm_link, scope, visited_keys):
                            visited_keys.add(get_dedup_key(norm_link))
                            queue.append((norm_link, depth + 1))
                            valid_links_count += 1
                            
                    # Record success
                    results_urls.append(url)
                    results_pages.append({
                        "url": url,
                        "depth": depth,
                        "status": status_code,
                        "links_found": len(raw_links)
                    })
                    
                    logging.info(f"[+] {pages_visited}/{max_pages} {url}")
                    
                except Exception as e:
                    timestamp = datetime.now().isoformat()
                    error_msg = f"{timestamp} | {url} | {str(e)}"
                    errors.append(error_msg)
                    logging.info(f"[!] failed: {url} ({type(e).__name__})")
                    
                finally:
                    await page.close()
                    await asyncio.sleep(delay)
                    
        except KeyboardInterrupt:
            logging.info("\n[!] KeyboardInterrupt detected. Saving partial progress...")
        finally:
            await browser.close()
            _save_outputs(results_urls, results_pages, errors)

def _save_outputs(urls: List[str], pages: List[Dict], errors: List[str]) -> None:
    """Helper to save crawl results to files."""
    with open("urls.txt", "w", encoding="utf-8") as f:
        for u in urls:
            f.write(f"{u}\n")
            
    with open("pages.json", "w", encoding="utf-8") as f:
        json.dump(pages, f, indent=2)
        
    with open("errors.log", "w", encoding="utf-8") as f:
        for e in errors:
            f.write(f"{e}\n")
    
    logging.info(f"Saved {len(urls)} URLs, {len(pages)} pages, {len(errors)} errors.")

def main() -> None:
    """CLI Entry Point"""
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Phase 1 IDOR Endpoint Mapper - Crawler Module")
    parser.add_argument("--url", required=True, help="Starting URL")
    parser.add_argument("--scope", required=True, help="Target domain to stay within (MANDATORY)")
    
    # Read defaults from env vars if available
    env_max_pages = int(os.getenv("MAX_PAGES", 500))
    env_max_depth = int(os.getenv("MAX_DEPTH", 5))
    env_delay = float(os.getenv("DELAY_SECONDS", 1.0))
    
    parser.add_argument("--max-pages", type=int, default=env_max_pages, help="Max pages to visit")
    parser.add_argument("--max-depth", type=int, default=env_max_depth, help="Max link depth")
    parser.add_argument("--headful", action="store_true", help="Show browser window")
    parser.add_argument("--delay", type=float, default=env_delay, help="Seconds between page visits")
    
    args = parser.parse_args()
    
    if not args.scope:
        logging.error("Error: --scope is mandatory.")
        sys.exit(1)

    asyncio.run(crawl(
        start_url=args.url,
        scope=args.scope,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        headful=args.headful,
        delay=args.delay
    ))

if __name__ == "__main__":
    main()