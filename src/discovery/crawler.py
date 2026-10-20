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
import re
from collections import deque
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Any, List, Dict, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from dotenv import load_dotenv
from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from src.capture.proxy import start_proxy
from src.discovery import auth
from src.discovery.interactions import trigger_page_interactions

# Configure logging for progress and general info
logging.basicConfig(level=logging.INFO, format="%(message)s")

ERRORS_PATH = auth.ERRORS_PATH
OUTPUT_DIR = ERRORS_PATH.parent
CRAWL_OUTPUTS_DIR = OUTPUT_DIR / "captures"
AUTH_STATE_MAX_AGE_SECONDS = 24 * 60 * 60

SKIP_EXTENSIONS = {
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".mp4", ".mp3",
    ".css", ".js", ".svg", ".woff", ".woff2", ".ico", ".xml"
}
SKIP_ACTION_PATHS = (
    "/logout",
    "/logout.php",
    "/log-out",
    "/log-out.php",
    "/signout",
    "/signout.php",
    "/sign-out",
    "/sign-out.php",
)
NETWORK_SETTLE_MS = 750
NETWORK_IDLE_TIMEOUT_MS = 3000
JS_URL_PATTERN = re.compile(
    r"""(?:"|')((?:https?://|/|\./|\.\./)[^"'<>\\\s]+)(?:"|')"""
)
JS_API_PATTERN = re.compile(
    r"""(?ix)
    (?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|open)
    \s*\(\s*["']((?:https?://|/|\./|\.\./)[^"'<>\s]+)["']
    """
)

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


def normalize_navigation_url(url: str) -> str:
    """Normalize a final browser URL while preserving a meaningful trailing slash."""
    parsed = urlparse(url)
    return urlunparse(
        parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            fragment="",
        )
    )


def get_origin(url: str) -> str:
    """Returns the normalized scheme, host, and port for a URL."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def get_auth_state_paths(origin: str) -> Tuple[Path, Path]:
    """Returns the state and metadata paths for an origin."""
    origin_dir = get_origin_output_dir(origin)
    filename = "auth_state"
    return (
        origin_dir / f"{filename}.json",
        origin_dir / f"{filename}.metadata.json",
    )


def get_origin_output_dir(origin: str) -> Path:
    """Returns the persistent output directory for an origin."""
    parsed = urlparse(origin)
    hostname = (parsed.hostname or "").replace(":", "-")
    origin_name = f"{parsed.scheme}_{hostname}"
    if parsed.port:
        origin_name = f"{origin_name}_{parsed.port}"
    return CRAWL_OUTPUTS_DIR / origin_name


def get_crawl_output_dir(origin: str, run_at: datetime | None = None) -> Path:
    """Returns a unique, origin-specific directory for one crawl run."""
    timestamp = (run_at or datetime.now()).strftime("%Y%m%d_%H%M%S_%f")
    return get_origin_output_dir(origin) / timestamp


def is_auth_state_valid(metadata_path: Path, origin: str, now: datetime) -> bool:
    """Checks whether saved authentication metadata matches and has not expired."""
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        created_at = datetime.fromisoformat(metadata["created_at"])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age_seconds = (now - created_at.astimezone(timezone.utc)).total_seconds()
        return (
            metadata.get("origin") == origin
            and 0 <= age_seconds <= AUTH_STATE_MAX_AGE_SECONDS
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False


def prepare_auth_state(start_url: str) -> Tuple[Path, Path, str]:
    """Selects a target-specific state file and removes invalid saved state."""
    origin = get_origin(start_url)
    if not origin:
        raise ValueError("The starting URL must include a valid HTTP or HTTPS origin")

    state_path, metadata_path = get_auth_state_paths(origin)
    state_is_valid = (
        state_path.is_file()
        and metadata_path.is_file()
        and is_auth_state_valid(metadata_path, origin, datetime.now(timezone.utc))
    )
    if not state_is_valid:
        for path in (state_path, metadata_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise OSError(f"Could not remove invalid authentication file {path}") from exc
    state_path.parent.mkdir(parents=True, exist_ok=True)
    return state_path, metadata_path, origin


def write_auth_metadata(metadata_path: Path, origin: str) -> None:
    """Writes metadata after a successful login using an atomic replacement."""
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


def discard_auth_state(state_path: Path, metadata_path: Path) -> None:
    """Removes the state files so the next login creates a fresh session."""
    for path in (state_path, metadata_path):
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise OSError(f"Could not remove authentication file {path}") from exc


async def is_login_page(page: Page) -> bool:
    """Detects common login pages after loading a saved browser state."""
    login_url = os.getenv("LOGIN_URL")
    if login_url:
        expected = urlparse(login_url)
        current = urlparse(page.url)
        if (
            expected.scheme == current.scheme
            and expected.netloc == current.netloc
            and expected.path.rstrip("/") == current.path.rstrip("/")
        ):
            return True

    password_fields = page.locator('input[type="password"]')
    username_fields = page.locator(
        'input[autocomplete="username"], input[type="email"], '
        'input[name*="user" i], input[name*="email" i]'
    )
    return await password_fields.count() > 0 and await username_fields.count() > 0


async def create_context(browser: Browser, proxy_settings: Dict[str, str] | None,
                         state_path: Path) -> BrowserContext:
    """Creates a browser context with an optional validated state file."""
    context_args: Dict[str, object] = {}
    if proxy_settings:
        context_args["proxy"] = proxy_settings
    if state_path.exists():
        context_args["storage_state"] = str(state_path)
    return await browser.new_context(**context_args)


async def extract_page_endpoints(page: Page) -> List[str]:
    """Extracts rendered DOM URL attributes in addition to anchor links."""
    return await page.eval_on_selector_all(
        "a[href], form[action], script[src], "
        "[data-url], [data-href], [data-endpoint], [data-api-url]",
        """els => els.map(el => {
            const value = el.href || el.action ||
              el.getAttribute('data-url') ||
              el.getAttribute('data-href') ||
              el.getAttribute('data-endpoint') ||
              el.getAttribute('data-api-url') || '';
            try {
              return new URL(value, window.location.href).href;
            } catch {
              return '';
            }
        }).filter(Boolean)""",
    )


async def extract_javascript_sources(page: Page) -> List[Tuple[str, str]]:
    """Returns inline script text and external script URLs from the rendered page."""
    return await page.evaluate(
        """() => [...document.scripts].map(script => ({
            url: script.src || '',
            text: script.src ? '' : (script.textContent || '')
        }))"""
    )


def get_runtime_discovery_settings() -> Tuple[int, int, bool]:
    """Read bounded network discovery settings from the environment."""
    try:
        settle_ms = max(0, int(os.getenv("NETWORK_SETTLE_MS", str(NETWORK_SETTLE_MS))))
    except ValueError:
        settle_ms = NETWORK_SETTLE_MS
    try:
        idle_timeout_ms = max(
            0,
            int(os.getenv("NETWORK_IDLE_TIMEOUT_MS", str(NETWORK_IDLE_TIMEOUT_MS))),
        )
    except ValueError:
        idle_timeout_ms = NETWORK_IDLE_TIMEOUT_MS
    reload_after_load = os.getenv(
        "RELOAD_AFTER_LISTENERS",
        "",
    ).strip().lower() in {"1", "true", "yes"}
    return settle_ms, idle_timeout_ms, reload_after_load


def get_configured_page_scripts() -> Dict[str, List[str]]:
    """Load explicit, user-configured page scripts from JSON if provided."""
    value = os.getenv("CRAWLER_PAGE_SCRIPTS", "").strip()
    if not value:
        return {}
    try:
        configured = json.loads(value)
    except json.JSONDecodeError as exc:
        logging.error("Invalid CRAWLER_PAGE_SCRIPTS JSON: %s", exc)
        return {}
    if not isinstance(configured, dict):
        logging.error("CRAWLER_PAGE_SCRIPTS must be a JSON object")
        return {}
    return {
        str(path): [str(script) for script in scripts if isinstance(script, str)]
        for path, scripts in configured.items()
        if isinstance(scripts, list)
    }


async def run_configured_page_scripts(page: Page) -> None:
    """Run only explicitly configured scripts for the current page path."""
    scripts = get_configured_page_scripts().get(urlparse(page.url).path, [])
    for script in scripts:
        try:
            await page.evaluate(script)
        except Exception as exc:
            logging.warning(
                "Configured page script failed on %s: %s",
                page.url,
                exc,
            )


def extract_urls_from_javascript(script: str, base_url: str) -> List[str]:
    """Extracts URL-like string literals from JavaScript source."""
    urls = []
    seen: Set[str] = set()

    def add_url(candidate: str) -> None:
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)

    for match in JS_URL_PATTERN.finditer(script):
        try:
            add_url(normalize_url(urljoin(base_url, match.group(1))))
        except ValueError:
            continue
    for match in JS_API_PATTERN.finditer(script):
        try:
            add_url(normalize_url(urljoin(base_url, match.group(1))))
        except ValueError:
            continue
    return urls


def add_discovered_endpoint(
    endpoints: List[Dict[str, str]],
    endpoint_keys: Set[Tuple[str, str]],
    url: str,
    source: str,
    scope: str,
) -> None:
    """Adds an in-scope endpoint candidate once with its discovery source."""
    if not url or not is_in_scope(url, scope):
        return
    key = (source, get_dedup_key(url))
    if key in endpoint_keys:
        return
    endpoint_keys.add(key)
    endpoints.append({"url": url, "source": source})


def get_dedup_key(url: str) -> str:
    """
    Extracts the scheme, domain, path, and query for deduplication.
    """
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))

def is_in_scope(url: str, scope: str) -> bool:
    """
    Checks if a given URL is within the target scope (allows subdomains).
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False

    scope_value = scope.strip()
    if "://" not in scope_value:
        scope_value = f"//{scope_value}"
    scope_hostname = urlparse(scope_value).hostname
    if not scope_hostname:
        return False

    hostname = hostname.lower().rstrip(".")
    scope_hostname = scope_hostname.lower().rstrip(".")
    return hostname == scope_hostname or hostname.endswith("." + scope_hostname)

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
    if any(path.rstrip("/").endswith(action) for action in SKIP_ACTION_PATHS):
        return True
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
    state_path, metadata_path, origin = prepare_auth_state(start_url)
    crawl_output_dir = get_crawl_output_dir(origin)
    crawl_output_dir.mkdir(parents=True, exist_ok=False)
    urls_path = crawl_output_dir / "urls.txt"
    pages_path = crawl_output_dir / "pages.json"
    errors_path = crawl_output_dir / "errors.log"
    network_path = crawl_output_dir / "network.json"
    discovered_path = crawl_output_dir / "discovered_endpoints.json"
    queue: deque[Tuple[str, int]] = deque()
    visited_keys: Set[str] = set()
    
    # Output structures
    results_urls: List[str] = []
    results_pages: List[Dict] = []
    errors: List[str] = []
    network_events: List[Dict[str, Any]] = []
    network_keys: Set[Tuple[str, str, int | None]] = set()
    discovered_endpoints: List[Dict[str, str]] = []
    discovered_keys: Set[Tuple[str, str]] = set()

    # Seed the queue
    normalized_start = normalize_url(start_url)
    queue.append((normalized_start, 0))
    visited_keys.add(get_dedup_key(normalized_start))

    pages_visited = 0
    settle_ms, idle_timeout_ms, reload_after_load = get_runtime_discovery_settings()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=not headful)
        context: BrowserContext | None = None
        proxy_context = None
        try:
            start_managed_proxy = os.getenv("START_PROXY", "").strip().lower() in {
                "1",
                "true",
                "yes",
            }
            if start_managed_proxy:
                configured_proxy_host = os.getenv("PROXY_HOST")
                configured_proxy_port = os.getenv("PROXY_PORT")
                managed_proxy_port = os.getenv("MANAGED_PROXY_PORT")
                if managed_proxy_port is None:
                    managed_proxy_port = (
                        "8081"
                        if configured_proxy_host
                        else (configured_proxy_port or "8080")
                    )
                proxy_context = start_proxy(
                    scope=scope,
                    capture_dir=crawl_output_dir,
                    port=int(managed_proxy_port),
                )
                managed_port = await proxy_context.__aenter__()
                proxy_settings = {"server": f"http://127.0.0.1:{managed_port}"}
            else:
                proxy_host = os.getenv("PROXY_HOST")
                proxy_port = os.getenv("PROXY_PORT")
                proxy_settings = None
                if proxy_host and proxy_port:
                    proxy_settings = {"server": f"http://{proxy_host}:{proxy_port}"}

            context = await create_context(browser, proxy_settings, state_path)

            if state_path.exists():
                validation_page = await context.new_page()
                try:
                    await validation_page.goto(
                        normalized_start,
                        wait_until="domcontentloaded",
                        timeout=15000,
                    )
                    session_is_valid = not await is_login_page(validation_page)
                finally:
                    await validation_page.close()

                if not session_is_valid:
                    logging.info("Saved authentication session was rejected; logging in again")
                    await context.close()
                    discard_auth_state(state_path, metadata_path)
                    context = await create_context(browser, proxy_settings, state_path)

            if not state_path.exists():
                login_page = await context.new_page()
                try:
                    await auth.login_if_needed(
                        login_page,
                        state_path=state_path,
                        errors_path=errors_path,
                    )
                finally:
                    await login_page.close()
                if not state_path.is_file():
                    raise RuntimeError(
                        "Authentication did not create a valid state file; "
                        "check the crawl errors.log"
                    )
                write_auth_metadata(metadata_path, origin)

            while queue and pages_visited < max_pages:
                url, depth = queue.popleft()
                
                if depth > max_depth:
                    continue
                    
                # Strict scope assertion just before visiting
                if not is_in_scope(url, scope):
                    continue

                pages_visited += 1
                page = await context.new_page()
                script_responses: Dict[str, Any] = {}
                popup_pages: List[Page] = []

                def record_request(request: Any) -> None:
                    event = {
                        "capture_source": "playwright",
                        "type": "request",
                        "method": request.method,
                        "url": normalize_url(request.url),
                        "resource_type": request.resource_type,
                    }
                    key = (event["method"], event["url"], None)
                    if key not in network_keys:
                        network_keys.add(key)
                        network_events.append(event)
                    if request.resource_type in {"document", "xhr", "fetch", "websocket"}:
                        add_discovered_endpoint(
                            discovered_endpoints,
                            discovered_keys,
                            event["url"],
                            "network",
                            scope,
                        )

                def record_response(response: Any) -> None:
                    request = response.request
                    event = {
                        "capture_source": "playwright",
                        "type": "response",
                        "method": request.method,
                        "url": normalize_url(response.url),
                        "resource_type": request.resource_type,
                        "status": response.status,
                    }
                    key = (event["method"], event["url"], event["status"])
                    if key not in network_keys:
                        network_keys.add(key)
                        network_events.append(event)
                    add_discovered_endpoint(
                        discovered_endpoints,
                        discovered_keys,
                        event["url"],
                        "network",
                        scope,
                    )
                    redirected_from = request.redirected_from
                    if redirected_from is not None:
                        add_discovered_endpoint(
                            discovered_endpoints,
                            discovered_keys,
                            normalize_url(redirected_from.url),
                            "redirect",
                            scope,
                        )
                    if request.resource_type == "script":
                        script_responses[normalize_url(response.url)] = response

                def record_websocket(websocket: Any) -> None:
                    event = {
                        "type": "websocket",
                        "capture_source": "playwright",
                        "method": "GET",
                        "url": normalize_url(websocket.url),
                        "resource_type": "websocket",
                    }
                    key = ("GET", event["url"], None)
                    if key not in network_keys:
                        network_keys.add(key)
                        network_events.append(event)
                    add_discovered_endpoint(
                        discovered_endpoints,
                        discovered_keys,
                        event["url"],
                        "network",
                        scope,
                    )

                page.on("request", record_request)
                page.on("response", record_response)
                page.on("websocket", record_websocket)

                def record_popup(popup: Page) -> None:
                    popup_pages.append(popup)

                page.on("popup", record_popup)
                
                try:
                    response = await page.goto(url, wait_until="load", timeout=15000)
                    status_code = response.status if response else 0
                    final_url = normalize_navigation_url(page.url)
                    if final_url and final_url != url:
                        add_discovered_endpoint(
                            discovered_endpoints,
                            discovered_keys,
                            final_url,
                            "redirect",
                            scope,
                        )
                        if not should_skip(final_url, scope, visited_keys):
                            visited_keys.add(get_dedup_key(final_url))
                            queue.append((final_url, depth))

                    if reload_after_load:
                        await page.reload(wait_until="load", timeout=15000)

                    # Trigger Person B's interaction hook
                    await trigger_page_interactions(page)
                    await run_configured_page_scripts(page)
                    try:
                        await page.wait_for_load_state(
                            "networkidle",
                            timeout=idle_timeout_ms,
                        )
                    except Exception:
                        logging.debug(
                            "Network idle was not reached for %s within %d ms",
                            page.url,
                            idle_timeout_ms,
                        )
                    await page.wait_for_timeout(settle_ms)
                    
                    # Extract links
                    raw_links = await extract_page_endpoints(page)
                    
                    for raw_link in raw_links:
                        norm_link = normalize_url(raw_link)
                        add_discovered_endpoint(
                            discovered_endpoints,
                            discovered_keys,
                            norm_link,
                            "dom",
                            scope,
                        )
                        if not should_skip(norm_link, scope, visited_keys):
                            visited_keys.add(get_dedup_key(norm_link))
                            queue.append((norm_link, depth + 1))

                    for script in await extract_javascript_sources(page):
                        script_url = normalize_url(script["url"]) if script["url"] else ""
                        if script_url:
                            add_discovered_endpoint(
                                discovered_endpoints,
                                discovered_keys,
                                script_url,
                                "script",
                                scope,
                            )
                        script_text = script["text"]
                        if script_text:
                            for candidate in extract_urls_from_javascript(
                                script_text,
                                page.url,
                            ):
                                add_discovered_endpoint(
                                    discovered_endpoints,
                                    discovered_keys,
                                    candidate,
                                    "javascript",
                                    scope,
                                )

                    for script_url, script_response in script_responses.items():
                        try:
                            script_text = (await script_response.body()).decode(
                                "utf-8",
                                errors="replace",
                            )
                        except Exception as exc:
                            logging.debug(
                                "Could not read script response %s: %s",
                                script_url,
                                exc,
                            )
                            continue
                        for candidate in extract_urls_from_javascript(
                            script_text,
                            script_url,
                        ):
                            add_discovered_endpoint(
                                discovered_endpoints,
                                discovered_keys,
                                candidate,
                                "javascript",
                                scope,
                            )

                    for popup in popup_pages:
                        if popup.url:
                            add_discovered_endpoint(
                                discovered_endpoints,
                                discovered_keys,
                                normalize_url(popup.url),
                                "popup",
                                scope,
                            )
                        await popup.close()
                            
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
            if context is not None:
                await context.close()
            await browser.close()
            _save_outputs(
                results_urls,
                results_pages,
                errors,
                urls_path,
                pages_path,
                errors_path,
                network_events,
                network_path,
                discovered_endpoints,
                discovered_path,
            )
            if proxy_context is not None:
                await proxy_context.__aexit__(None, None, None)

def _save_outputs(
    urls: List[str],
    pages: List[Dict],
    errors: List[str],
    urls_path: Path,
    pages_path: Path,
    errors_path: Path,
    network_events: List[Dict[str, Any]],
    network_path: Path,
    discovered_endpoints: List[Dict[str, str]],
    discovered_path: Path,
) -> None:
    """Helper to save crawl results to files."""
    with urls_path.open("w", encoding="utf-8") as f:
        for u in urls:
            f.write(f"{u}\n")
            
    with pages_path.open("w", encoding="utf-8") as f:
        json.dump(pages, f, indent=2)
        
    with errors_path.open("a", encoding="utf-8") as f:
        for e in errors:
            f.write(f"{e}\n")

    with network_path.open("w", encoding="utf-8") as f:
        json.dump(network_events, f, indent=2)

    with discovered_path.open("w", encoding="utf-8") as f:
        json.dump(discovered_endpoints, f, indent=2)
    
    logging.info(
        f"Saved {len(urls)} URLs, {len(pages)} pages, "
        f"{len(errors)} errors, {len(network_events)} network events."
        f" {len(discovered_endpoints)} discovered endpoints."
    )

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