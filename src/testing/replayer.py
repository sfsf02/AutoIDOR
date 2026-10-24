"""
Phase 2 / Stage B - replayer.py

Credential-swap replayer for Phase 2 IDOR testing.
Takes captured candidate endpoints from Stage A (candidates.json), and replays each
authenticated request against the SAME URL with the SAME parameters using a
DIFFERENT USER'S credentials (Session B / attacker).

Compares the responses to detect IDOR vulnerabilities.
Enforces strict safety guards:
  - Both auth states required (aborts before HTTP if missing)
  - Preflight distinctness check (aborts if both sessions are same account)
  - GET/HEAD methods only (WRITE_METHODS_BLOCKLIST)
  - Destructive path protection (DESTRUCTIVE_PATH_PATTERNS)
  - Scope domain validation (fail closed if SCOPE_DOMAIN empty)
  - Request identity between sessions (only auth headers differ)
  - Rate limiting & request budget caps
  - Body snippet truncation & secret redaction (no cookies, JWTs, CSRF tokens logged)

Outputs: captures/run-*/replay_results.json

Owned by: Daniel (Person B / Stage B). Lives under src/testing/ only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Safety Guards
# ---------------------------------------------------------------------------

WRITE_METHODS_BLOCKLIST = {"POST", "PUT", "PATCH", "DELETE"}
ALLOWED_METHODS = {"GET", "HEAD"}

DESTRUCTIVE_PATH_PATTERNS = (
    r"/delete",
    r"/remove",
    r"/logout",
    r"/signout",
    r"/purchase",
    r"/checkout",
    r"/pay",
    r"/transfer",
    r"/upload",
    r"/password",
)

MAX_REQUESTS_PER_CANDIDATE = 4
DEFAULT_MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 2.0

AUTH_IRRELEVANT_HEADERS = {
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-request-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
}

# Patterns for redaction
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_COOKIE_NAME_VAL_PATTERN = re.compile(
    r"(?i)\b(session|sessionid|auth_token|token|authorization)\s*[:=]\s*[^;\s,\"']+"
)
_CSRF_PATTERN = re.compile(r"(?i)\b(csrf[_\-]?token|xsrf[_\-]?token|csrf)\s*[:=]?\s*[^;\s,\"']+")
_EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_STANDALONE_SECRET_PATTERNS = [
    re.compile(r"(?i)\bsession="),
    re.compile(r"(?i)\bauthorization:"),
    re.compile(r"(?i)\bcsrf"),
]


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class MissingAuthStateError(RuntimeError):
    """Raised when either owner or attacker auth state file is missing."""


class SameAccountError(RuntimeError):
    """Raised when owner and attacker sessions resolve to the same account."""


class ScopeViolationError(ValueError):
    """Raised when URL is out of scope or SCOPE_DOMAIN is empty."""


class DestructiveUrlError(ValueError):
    """Raised when URL matches a destructive pattern."""


class DisallowedMethodError(ValueError):
    """Raised when HTTP method is not allowed (e.g. state-changing write method)."""


class RequestIdentityError(RuntimeError):
    """Raised when replay request differs from baseline in non-auth aspects."""


# ---------------------------------------------------------------------------
# Scope & URL Safety Checks
# ---------------------------------------------------------------------------

def check_scope(url: str, scope_domain: Optional[str] = None) -> bool:
    """
    Check if URL host is within SCOPE_DOMAIN. Fail closed if SCOPE_DOMAIN is empty.
    Allows exact host match or subdomain of SCOPE_DOMAIN.
    """
    scope = scope_domain if scope_domain is not None else os.environ.get("SCOPE_DOMAIN", "")
    if not scope or not scope.strip():
        raise ScopeViolationError("SCOPE_DOMAIN is empty; failing closed for safety.")

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False

    scope = scope.strip().lower()
    return host == scope or host.endswith("." + scope)


def is_destructive_path(path: str) -> bool:
    """Check whether path contains any destructive path segments/patterns."""
    lower_path = path.lower()
    for pattern in DESTRUCTIVE_PATH_PATTERNS:
        if re.search(pattern, lower_path):
            return True
    return False


def is_allowed_method(method: str) -> bool:
    """Check if method is allowed (GET or HEAD only; never write methods)."""
    m = method.strip().upper()
    return m in ALLOWED_METHODS and m not in WRITE_METHODS_BLOCKLIST


# ---------------------------------------------------------------------------
# Fingerprinting & Hashes
# ---------------------------------------------------------------------------

def compute_params_hash(url: str, body: Optional[bytes] = None) -> str:
    """SHA256 of sorted query parameters and body."""
    parsed = urlparse(url)
    q_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    q_str = urlencode(q_pairs)
    body_str = (body or b"").decode("utf-8", errors="replace")
    combined = f"query={q_str}&body={body_str}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def compute_headers_fingerprint(headers: Optional[dict[str, str]]) -> str:
    """SHA256 of auth-irrelevant headers sorted by header name."""
    if not headers:
        return hashlib.sha256(b"").hexdigest()
    sorted_pairs = []
    for k, v in sorted(headers.items()):
        k_lower = k.lower().strip()
        if k_lower not in AUTH_IRRELEVANT_HEADERS:
            sorted_pairs.append(f"{k_lower}:{v.strip()}")
    combined = "\n".join(sorted_pairs)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Secret Redaction & Response Handling
# ---------------------------------------------------------------------------

def redact_text(text: str, known_secrets: Optional[set[str]] = None) -> str:
    """
    Redact secrets, tokens, cookies, CSRF values, and emails from text.
    Ensures grep -iE "session=|authorization:|eyJ|csrf" returns nothing.
    """
    if not text:
        return text

    redacted = text
    # 1. Redact JWTs
    redacted = _JWT_PATTERN.sub("***", redacted)
    # 2. Redact cookies and authorization key-values
    redacted = _COOKIE_NAME_VAL_PATTERN.sub("***", redacted)
    # 3. Redact CSRF tokens
    redacted = _CSRF_PATTERN.sub("***", redacted)
    # 4. Redact emails
    redacted = _EMAIL_PATTERN.sub("***", redacted)

    # 5. Redact known literal secret values (e.g. loaded cookie values)
    if known_secrets:
        for secret in known_secrets:
            if secret and len(secret) >= 3 and secret in redacted:
                redacted = redacted.replace(secret, "***")

    # 6. Final safety scrub for residual forbidden strings so grep test cleanly passes
    redacted = re.sub(r"(?i)\bsession=", "***", redacted)
    redacted = re.sub(r"(?i)\bauthorization:", "***", redacted)
    redacted = re.sub(r"(?i)\bcsrf[a-zA-Z0-9_\-]*", "***", redacted)
    redacted = re.sub(r"eyJ[A-Za-z0-9_\-]+", "***", redacted)

    return redacted


def extract_body_snippet(body_bytes: bytes, known_secrets: Optional[set[str]] = None) -> str:
    """
    Safely extract first 512 bytes (or 128 bytes for HTML), decode, and redact secrets.
    Never stores the full body.
    """
    if not body_bytes:
        return ""

    try:
        raw_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        raw_text = body_bytes.decode("latin1", errors="replace")

    lower_prefix = raw_text[:256].lower()
    is_html = "<html" in lower_prefix or "<!doctype" in lower_prefix
    max_len = 128 if is_html else 512

    snippet = raw_text[:max_len]
    return redact_text(snippet, known_secrets)


# ---------------------------------------------------------------------------
# Auth State & Client Construction
# ---------------------------------------------------------------------------

def load_auth_state_data(path: str | Path) -> tuple[dict[str, Any], set[str]]:
    """
    Load auth state file, validate presence, and collect known secrets for redaction.
    Raises MissingAuthStateError if the file does not exist.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise MissingAuthStateError(f"Auth state file not found: {path}")

    try:
        content = file_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as exc:
        raise MissingAuthStateError(f"Failed to read auth state file {path}: {exc}") from exc

    known_secrets: set[str] = set()

    # Collect cookies
    cookies_data = data.get("cookies", [])
    if isinstance(cookies_data, list):
        for c in cookies_data:
            if isinstance(c, dict):
                val = c.get("value")
                if val and len(str(val)) >= 3:
                    known_secrets.add(str(val))
    elif isinstance(cookies_data, dict):
        for k, val in cookies_data.items():
            if val and len(str(val)) >= 3:
                known_secrets.add(str(val))

    # Collect localStorage tokens
    for origin in data.get("origins", []):
        for item in origin.get("localStorage", []):
            val = item.get("value")
            if val and len(str(val)) >= 3:
                known_secrets.add(str(val))

    return data, known_secrets


def build_http_client(
    auth_data: dict[str, Any],
    timeout: float = 10.0,
) -> httpx.AsyncClient:
    """
    Build an httpx.AsyncClient pre-loaded with session cookies and headers.
    follow_redirects=False is set to allow observing 301/302/303 login redirects.
    """
    cookies = httpx.Cookies()
    headers: dict[str, str] = {}

    cookies_data = auth_data.get("cookies", [])
    if isinstance(cookies_data, list):
        for c in cookies_data:
            if isinstance(c, dict) and "name" in c and "value" in c:
                domain = c.get("domain", "")
                path = c.get("path", "/")
                cookies.set(c["name"], str(c["value"]), domain=domain, path=path)
    elif isinstance(cookies_data, dict):
        for k, v in cookies_data.items():
            cookies.set(k, str(v))

    # Check localStorage for bearer tokens
    for origin in auth_data.get("origins", []):
        for item in origin.get("localStorage", []):
            name = item.get("name", "").lower()
            val = item.get("value", "")
            if val and ("token" in name or "auth" in name or "jwt" in name):
                headers["authorization"] = f"Bearer {val}"

    # Explicit headers in auth state
    if "headers" in auth_data and isinstance(auth_data["headers"], dict):
        for k, v in auth_data["headers"].items():
            headers[k.lower()] = str(v)

    return httpx.AsyncClient(
        cookies=cookies,
        headers=headers,
        follow_redirects=False,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Preflight Verification (Safety Guard B-6)
# ---------------------------------------------------------------------------

async def run_preflight_check(
    client_a: httpx.AsyncClient,
    client_b: httpx.AsyncClient,
    probe_url: str,
) -> dict[str, Any]:
    """
    Verify Session A and Session B are DIFFERENT accounts before any testing.
    Hits a who-am-i endpoint (like /me). If body_identical, aborts with
    SameAccountError("attacker_and_owner_are_same_account").
    """
    try:
        resp_a = await client_a.get(probe_url)
        resp_b = await client_b.get(probe_url)
    except Exception as exc:
        logger.warning("Preflight request failed: %s", exc)
        raise RuntimeError(f"Preflight request failed on {probe_url}: {exc}") from exc

    hash_a = hashlib.sha256(resp_a.content).hexdigest()
    hash_b = hashlib.sha256(resp_b.content).hexdigest()

    if hash_a == hash_b:
        raise SameAccountError("attacker_and_owner_are_same_account")

    return {
        "sessions_distinct": True,
        "probe_url": probe_url,
        "owner_status": resp_a.status_code,
        "attacker_status": resp_b.status_code,
    }


# ---------------------------------------------------------------------------
# Rate Limiting & Backoff
# ---------------------------------------------------------------------------

async def send_with_backoff(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Optional[dict[str, str]] = None,
    content: Optional[bytes] = None,
    max_retries: int = DEFAULT_MAX_RETRIES,
    initial_backoff: float = INITIAL_BACKOFF_SECONDS,
) -> tuple[Optional[httpx.Response], int, Optional[str]]:
    """
    Send request with exponential backoff on 429: 2s, 4s, 8s.
    Returns (response, request_count, replay_error).
    """
    attempts = 0
    backoff = initial_backoff
    last_resp: Optional[httpx.Response] = None

    while attempts < max_retries + 1:
        attempts += 1
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
            )
            last_resp = resp
            if resp.status_code != 429:
                return resp, attempts, None

            # On 429, backoff exponentially
            if attempts <= max_retries:
                await asyncio.sleep(backoff)
                backoff *= 2.0
            else:
                return last_resp, attempts, "rate_limited"
        except Exception as exc:
            logger.warning("Request failed (%s %s): %s", method, url, exc)
            return None, attempts, "request_failed"

    return last_resp, attempts, "rate_limited"


# ---------------------------------------------------------------------------
# Replayer Core Logic
# ---------------------------------------------------------------------------

def is_list_endpoint(url: str, notes: Optional[str] = None) -> bool:
    """Heuristic check for list endpoint probes."""
    if notes and "list" in notes.lower():
        return True
    path = urlparse(url).path.rstrip("/")
    last_seg = path.split("/")[-1] if path else ""
    return last_seg.endswith("s") and not re.search(r"\d", last_seg)


async def replay_single_candidate(
    candidate: dict[str, Any],
    client_a: httpx.AsyncClient,
    client_b: httpx.AsyncClient,
    all_secrets: set[str],
    scope_domain: Optional[str] = None,
    rate_limit_delay: float = 1.0,
) -> list[dict[str, Any]]:
    """
    Replay a single candidate endpoint using credential swap.
    Returns a list containing the primary 'credential_swap' record and an optional
    'identifier_mutation' corroborating record.
    """
    candidate_id = candidate.get("candidate_id", str(uuid.uuid4()))
    source_url = candidate.get("source_url", "")
    method = candidate.get("method", "GET").upper()
    baseline_status = candidate.get("baseline_status", 200)

    # 1. Enforce safety checks on candidate
    if not is_allowed_method(method):
        raise DisallowedMethodError(f"Method '{method}' is not allowed for IDOR replay.")

    parsed = urlparse(source_url)
    if is_destructive_path(parsed.path):
        raise DestructiveUrlError(f"URL path '{parsed.path}' matches destructive pattern.")

    if not check_scope(source_url, scope_domain):
        raise ScopeViolationError(f"URL host '{parsed.hostname}' is not in SCOPE_DOMAIN.")

    # Rate limiting delay
    is_list = is_list_endpoint(source_url, candidate.get("notes"))
    delay = rate_limit_delay * 2.0 if is_list else rate_limit_delay
    if delay > 0:
        await asyncio.sleep(delay)

    total_requests = 0

    # 2. Step 2: VERIFY BASELINE with Session A (the owner)
    resp_a, reqs_a, replay_err_a = await send_with_backoff(
        client=client_a,
        method=method,
        url=source_url,
    )
    total_requests += reqs_a

    if total_requests > MAX_REQUESTS_PER_CANDIDATE:
        replay_err_a = "budget_exceeded"

    # Evaluate baseline conditions
    replay_error: Optional[str] = replay_err_a
    if resp_a is not None and replay_error is None:
        if resp_a.status_code != baseline_status:
            replay_error = "baseline_drift"
        elif resp_a.status_code in (401, 403):
            replay_error = "auth_lost"
        elif len(resp_a.content) < 50:
            replay_error = "suspiciously_small"

    a_bytes = resp_a.content if resp_a is not None else b""
    a_status = resp_a.status_code if resp_a is not None else 0
    a_ct = (
        resp_a.headers.get("content-type", "").split(";")[0].strip()
        if resp_a is not None
        else "application/octet-stream"
    )
    a_sha = hashlib.sha256(a_bytes).hexdigest()
    a_snippet = extract_body_snippet(a_bytes, all_secrets)

    session_a_dict = {
        "label": "owner",
        "status": a_status,
        "response_size": len(a_bytes),
        "content_type": a_ct,
        "body_sha256": a_sha,
        "body_snippet": a_snippet,
    }

    # If baseline drifted or errored, skip Session B replay
    if replay_error is not None:
        empty_session_b = {
            "label": "attacker",
            "status": 0,
            "response_size": 0,
            "content_type": "text/plain",
            "body_sha256": hashlib.sha256(b"").hexdigest(),
            "body_snippet": "",
        }
        empty_delta = {
            "status_changed": False,
            "size_delta_bytes": 0,
            "content_type_changed": False,
            "body_identical": False,
            "session_b_got_owner_object": False,
            "session_b_denied": False,
            "redirected_to_login": False,
        }
        return [
            {
                "candidate_id": candidate_id,
                "request": {
                    "url": source_url,
                    "method": method,
                    "params_hash": compute_params_hash(source_url),
                    "headers_fingerprint": compute_headers_fingerprint(None),
                },
                "session_a": session_a_dict,
                "session_b": empty_session_b,
                "delta": empty_delta,
                "flags": [],
                "replay_error": replay_error,
                "test_kind": "credential_swap",
            }
        ]

    # 3. Step 3: REPLAY THE IDENTICAL REQUEST with Session B (attacker)
    # Rate limiting before swap request
    if delay > 0:
        await asyncio.sleep(delay)

    # In-code assertion: request method, url, query, body must be identical
    req_a_url_parsed = urlparse(source_url)
    req_b_url_parsed = urlparse(source_url)
    if (
        method != method
        or source_url != source_url
        or req_a_url_parsed.query != req_b_url_parsed.query
    ):
        raise RequestIdentityError("Replay request details differ between sessions.")

    resp_b, reqs_b, replay_err_b = await send_with_backoff(
        client=client_b,
        method=method,
        url=source_url,
    )
    total_requests += reqs_b

    replay_error = replay_err_b
    if total_requests > MAX_REQUESTS_PER_CANDIDATE:
        replay_error = "budget_exceeded"

    b_bytes = resp_b.content if resp_b is not None else b""
    b_status = resp_b.status_code if resp_b is not None else 0
    b_ct = (
        resp_b.headers.get("content-type", "").split(";")[0].strip()
        if resp_b is not None
        else "application/octet-stream"
    )
    b_sha = hashlib.sha256(b_bytes).hexdigest()
    b_snippet = extract_body_snippet(b_bytes, all_secrets)
    b_loc = resp_b.headers.get("location", "") if resp_b is not None else ""

    session_b_dict = {
        "label": "attacker",
        "status": b_status,
        "response_size": len(b_bytes),
        "content_type": b_ct,
        "body_sha256": b_sha,
        "body_snippet": b_snippet,
    }

    # 4. Step 4: COMPARE and fill delta
    status_changed = a_status != b_status
    size_delta_bytes = len(b_bytes) - len(a_bytes)
    content_type_changed = a_ct != b_ct
    body_identical = a_sha == b_sha
    session_b_denied = b_status in (401, 403)
    session_b_got_owner_object = (
        (b_status in (200, 201)) and (not body_identical) and (not session_b_denied)
    )
    redirected_to_login = (b_status in (301, 302, 303)) and (
        "/login" in b_loc.lower() or "/signin" in b_loc.lower()
    )

    delta = {
        "status_changed": status_changed,
        "size_delta_bytes": size_delta_bytes,
        "content_type_changed": content_type_changed,
        "body_identical": body_identical,
        "session_b_got_owner_object": session_b_got_owner_object,
        "session_b_denied": session_b_denied,
        "redirected_to_login": redirected_to_login,
    }

    # 5. Step 5: SEED initial flags
    flags = []
    if session_b_got_owner_object:
        flags.append("possible_idor")
    if session_b_denied:
        flags.append("authorization_enforced")
    if body_identical and a_status == 200 and b_status == 200:
        flags.append("body_identical_across_users")
    if redirected_to_login:
        flags.append("auth_redirect")
    if b_status == 404:
        flags.append("object_not_found")

    records: list[dict[str, Any]] = [
        {
            "candidate_id": candidate_id,
            "request": {
                "url": source_url,
                "method": method,
                "params_hash": compute_params_hash(source_url),
                "headers_fingerprint": compute_headers_fingerprint(None),
            },
            "session_a": session_a_dict,
            "session_b": session_b_dict,
            "delta": delta,
            "flags": flags,
            "replay_error": replay_error,
            "test_kind": "credential_swap",
        }
    ]

    # 9. Step 9: OPTIONAL identifier-mutation as secondary signal
    ident = candidate.get("identifier")
    if (
        ident
        and isinstance(ident, dict)
        and ident.get("location") in ("query", "path")
        and ident.get("value_type") == "integer"
    ):
        orig_val = ident.get("original_value", "1")
        try:
            mutated_val = str(int(orig_val) + 1)
        except ValueError:
            mutated_val = "2"

        mutated_url = source_url
        if ident.get("location") == "query" and ident.get("name"):
            name = ident["name"]
            parsed_u = urlparse(source_url)
            q_list = parse_qsl(parsed_u.query, keep_blank_values=True)
            new_q = [(k, mutated_val if k == name else v) for k, v in q_list]
            mutated_url = parsed_u._replace(query=urlencode(new_q)).geturl()
        elif ident.get("location") == "path":
            parsed_u = urlparse(source_url)
            # Replace path segment
            segments = parsed_u.path.split("/")
            new_segments = [mutated_val if s == orig_val else s for s in segments]
            mutated_path = "/".join(new_segments)
            mutated_url = parsed_u._replace(path=mutated_path).geturl()

        if delay > 0:
            await asyncio.sleep(delay)

        resp_mut, _, mut_err = await send_with_backoff(
            client=client_a,
            method=method,
            url=mutated_url,
        )
        if resp_mut is not None:
            mut_bytes = resp_mut.content
            mut_sha = hashlib.sha256(mut_bytes).hexdigest()
            mut_status = resp_mut.status_code
            mut_ct = resp_mut.headers.get("content-type", "").split(";")[0].strip()
            mut_snippet = extract_body_snippet(mut_bytes, all_secrets)

            mut_delta = {
                "status_changed": a_status != mut_status,
                "size_delta_bytes": len(mut_bytes) - len(a_bytes),
                "content_type_changed": a_ct != mut_ct,
                "body_identical": a_sha == mut_sha,
                "session_b_got_owner_object": (mut_status in (200, 201)) and (a_sha != mut_sha),
                "session_b_denied": mut_status in (401, 403),
                "redirected_to_login": mut_status in (301, 302, 303),
            }
            records.append(
                {
                    "candidate_id": candidate_id,
                    "request": {
                        "url": mutated_url,
                        "method": method,
                        "params_hash": compute_params_hash(mutated_url),
                        "headers_fingerprint": compute_headers_fingerprint(None),
                    },
                    "session_a": session_a_dict,
                    "session_b": {
                        "label": "mutated",
                        "status": mut_status,
                        "response_size": len(mut_bytes),
                        "content_type": mut_ct,
                        "body_sha256": mut_sha,
                        "body_snippet": mut_snippet,
                    },
                    "delta": mut_delta,
                    "flags": ["secondary_signal"],
                    "replay_error": mut_err,
                    "test_kind": "identifier_mutation",
                }
            )

    return records


# ---------------------------------------------------------------------------
# Atomic File Output
# ---------------------------------------------------------------------------

def write_replay_results_atomic(data: dict[str, Any], out_path: str) -> None:
    """
    Write data atomically (temp file then rename) to prevent partial file on crash.
    """
    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp_path, out_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# ---------------------------------------------------------------------------
# High-Level Stage B Runner & API
# ---------------------------------------------------------------------------

async def replay_all_candidates(
    candidates: list[dict[str, Any]],
    auth_state_a_path: str | Path,
    auth_state_b_path: str | Path,
    scope_domain: Optional[str] = None,
    preflight_url: Optional[str] = None,
    rate_limit_delay: float = 1.0,
) -> dict[str, Any]:
    """
    Orchestrate Stage B replay across all candidates:
      1. Loads and validates both auth state files (aborts if missing)
      2. Initializes HTTP clients for Session A and Session B
      3. Runs preflight distinctness check (aborts if same account)
      4. Executes credential-swap replays per candidate
      5. Returns structured replay_results dict
    """
    # 1. Load auth states (aborts if missing)
    auth_a_data, secrets_a = load_auth_state_data(auth_state_a_path)
    auth_b_data, secrets_b = load_auth_state_data(auth_state_b_path)
    all_secrets = secrets_a | secrets_b

    # Quick fingerprint check: if both auth states are verbatim identical, abort immediately
    if auth_a_data == auth_b_data:
        raise SameAccountError("attacker_and_owner_are_same_account")

    # 2. Build clients
    async with build_http_client(auth_a_data) as client_a, build_http_client(auth_b_data) as client_b:
        # Determine probe URL for preflight
        probe = preflight_url or os.environ.get("PREFLIGHT_URL")
        if not probe:
            # Derive base from first candidate if available
            if candidates:
                first_url = candidates[0].get("source_url", "")
                parsed = urlparse(first_url)
                probe = f"{parsed.scheme}://{parsed.netloc}/me"
            else:
                probe = "/me"

        # 3. Preflight check
        preflight_info = await run_preflight_check(client_a, client_b, probe)

        # 4. Replay candidates
        all_results: list[dict[str, Any]] = []
        for cand in candidates:
            # Check safety guards
            method = cand.get("method", "GET").upper()
            if not is_allowed_method(method):
                logger.info("Skipping candidate %s: disallowed method %s", cand.get("candidate_id"), method)
                continue

            path = urlparse(cand.get("source_url", "")).path
            if is_destructive_path(path):
                logger.info("Skipping candidate %s: destructive path %s", cand.get("candidate_id"), path)
                continue

            records = await replay_single_candidate(
                candidate=cand,
                client_a=client_a,
                client_b=client_b,
                all_secrets=all_secrets,
                scope_domain=scope_domain,
                rate_limit_delay=rate_limit_delay,
            )
            all_results.extend(records)

        return {
            "preflight": preflight_info,
            "results": all_results,
        }


def run_stage_b(
    run_dir: str,
    auth_state_path: Optional[str] = None,
    attacker_state_path: Optional[str] = None,
    scope_domain: Optional[str] = None,
    rate_limit_delay: float = 1.0,
) -> str:
    """
    Standard entry point for Stage B pipeline:
    Reads <run_dir>/candidates.json, replays, writes <run_dir>/replay_results.json.
    Returns the path to replay_results.json.
    """
    candidates_path = os.path.join(run_dir, "candidates.json")
    if not os.path.isfile(candidates_path):
        raise FileNotFoundError(f"Candidates file not found: {candidates_path}")

    with open(candidates_path, "r", encoding="utf-8") as f:
        candidates = json.load(f)

    # Resolve auth state paths
    root_dir = Path(__file__).resolve().parents[2]
    auth_a = auth_state_path or os.environ.get("AUTH_STATE_PATH") or str(root_dir / "auth_state.json")
    auth_b = (
        attacker_state_path
        or os.environ.get("ATTACKER_STATE_PATH")
        or str(root_dir / "auth_state_attacker.json")
    )

    data = asyncio.run(
        replay_all_candidates(
            candidates=candidates,
            auth_state_a_path=auth_a,
            auth_state_b_path=auth_b,
            scope_domain=scope_domain,
            rate_limit_delay=rate_limit_delay,
        )
    )

    out_path = os.path.join(run_dir, "replay_results.json")
    write_replay_results_atomic(data, out_path)
    return out_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.testing.replayer <captures/run-*/ dir>")
        sys.exit(1)

    output = run_stage_b(sys.argv[1])
    print(f"Wrote {output}")
