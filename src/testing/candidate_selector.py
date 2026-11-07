"""Stage A candidate selector for Phase 2 IDOR testing.

Pure parsing and ranking. Makes ZERO network requests.
See docs/PHASE2_SPEC.md, Stage A section.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from urllib.parse import parse_qsl, urlparse


log = logging.getLogger(__name__)


# --- Constants -------------------------------------------------------------

WRITE_METHODS_BLOCKLIST = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_METHODS = {"GET", "HEAD"}

DESTRUCTIVE_PATH_PATTERNS = (
    r"/delete", r"/remove", r"/logout", r"/signout",
    r"/purchase", r"/checkout", r"/pay", r"/transfer",
    r"/upload", r"/password",
)

IDENTIFIER_PARAM_ALLOWLIST = {
    "id", "user_id", "userid", "account_id", "accountid",
    "file_id", "fileid", "document_id", "documentid",
    "order_id", "orderid", "project_id", "projectid",
    "page_id", "pageid", "tenant_id", "tenantid",
}

HEADER_IDENTIFIER_ALLOWLIST = {
    "x-user-id", "x-userid", "x-user",
    "x-account-id", "x-accountid",
    "x-tenant-id", "x-tenantid", "x-tenant",
    "x-org-id", "x-orgid", "x-organization-id",
    "x-resource-id", "x-resourceid",
    "x-owner-id", "x-ownerid",
    "x-customer-id", "x-customerid",
}

# Hard-coded so a future allowlist edit cannot accidentally admit auth
# headers.
HEADER_BLOCKLIST = {
    "authorization", "cookie", "set-cookie", "host", "origin", "referer",
    "x-real-ip", "x-request-id", "x-csrf-token",
}
HEADER_BLOCKLIST_PREFIXES = ("x-forwarded-",)

# Words that are common REST resource/collection nouns and must NOT be
# mistaken for slug identifiers (e.g. /api/documents, /about).
SLUG_STOPLIST = {
    "api", "v1", "v2", "v3", "v4",
    "about", "documents", "users", "admin", "internal",
    "login", "logout", "signin", "signup", "signout",
    "health", "status", "search", "list", "index", "home",
    "page", "help", "faq", "contact", "terms", "privacy",
    "settings", "profile", "account", "dashboard",
    "static", "assets", "public", "private",
    "auth", "oauth", "callback", "docs",
}
PATH_STRUCTURE_SEGMENTS = {"v", "version", "versions", "api"}

INT_RE = re.compile(r"^\d+$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
FILENAME_RE = re.compile(r"^file\d+\.\w+$")
SLUG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]*$")
SHA256_REDACTED_RE = re.compile(r"^sha256\(([^)]+)\)")

HEADER_WARNING_MSG = (
    "Stage A: header-IDOR detection disabled — "
    "request headers not captured by Phase 1"
)


# --- Exceptions ------------------------------------------------------------

class ScopeConfigError(RuntimeError):
    """Raised when SCOPE_DOMAIN is missing or empty."""


# --- Env / scope helpers ---------------------------------------------------

def get_scope() -> str:
    """Return SCOPE_DOMAIN, or raise if unset/blank.

    Fail closed: a missing env var must never silently disable scope
    enforcement.
    """
    scope = os.environ.get("SCOPE_DOMAIN", "").strip()
    if not scope:
        raise ScopeConfigError(
            "SCOPE_DOMAIN environment variable is required and must not be empty"
        )
    return scope.lower()


def get_owner_session() -> str:
    return os.environ.get("OWNER_SESSION_LABEL", "owner").strip() or "owner"


def is_in_scope(host: str, scope: str) -> bool:
    if not host:
        return False
    host = host.lower()
    if "://" in scope:
        scope = urlparse(scope).hostname or ""
    return host == scope or host.endswith("." + scope)


def normalize_url(url: str, scope: str, flows: list[dict] | None = None) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if not url.startswith("/"):
        url = "/" + url
    if flows:
        relative = urlparse(url)
        for flow in flows:
            flow_url = flow.get("url")
            if not isinstance(flow_url, str):
                continue
            parsed_flow = urlparse(flow_url)
            if (
                parsed_flow.scheme in {"http", "https"}
                and parsed_flow.netloc
                and parsed_flow.path == relative.path
                and parsed_flow.query == relative.query
                and is_in_scope(parsed_flow.hostname or "", scope)
            ):
                return f"{parsed_flow.scheme}://{parsed_flow.netloc}{url}"
    return f"https://{scope}{url}"


# --- Guard helpers ---------------------------------------------------------

def is_method_allowed(method: str) -> bool:
    m = (method or "").upper()
    return m in SAFE_METHODS and m not in WRITE_METHODS_BLOCKLIST


def is_destructive_path(path: str) -> bool:
    low = (path or "").lower()
    return any(re.search(pat, low) for pat in DESTRUCTIVE_PATH_PATTERNS)


def is_blocked_header(name: str) -> bool:
    lname = (name or "").lower()
    if lname in HEADER_BLOCKLIST:
        return True
    return any(lname.startswith(p) for p in HEADER_BLOCKLIST_PREFIXES)


def is_valid_status_code(status_code) -> bool:
    return (
        isinstance(status_code, int)
        and not isinstance(status_code, bool)
        and 100 <= status_code <= 599
    )


# --- Value classification --------------------------------------------------

def _unwrap_redacted(value: str) -> str:
    """Return `raw` from `sha256(raw)…`, else the input.

    Person C's logger redacts header values as `sha256(<raw>)<hash>`.
    We recover the raw form ONLY for classification; the value stored
    in candidates.json is always what was captured (raw or redacted).
    """
    m = SHA256_REDACTED_RE.match(value)
    if m:
        return m.group(1)
    return value


def classify_value(value) -> str | None:
    if not isinstance(value, str):
        return None
    raw = _unwrap_redacted(value)
    if INT_RE.match(raw):
        return "integer"
    if UUID_RE.match(raw):
        return "uuid"
    if FILENAME_RE.match(raw):
        return "filename"
    if SLUG_RE.match(raw) and len(raw) >= 2 and raw.lower() not in SLUG_STOPLIST:
        return "slug"
    return None


def is_slug(value: str) -> bool:
    return classify_value(value) == "slug"


# --- Identifier extraction -------------------------------------------------

def _is_structural_numeric_segment(segments: list[str], index: int) -> bool:
    segment = segments[index]
    if len(segment) == 4 and 1900 <= int(segment) <= 2100:
        return True
    return index > 0 and segments[index - 1].lower() in PATH_STRUCTURE_SEGMENTS


def extract_path_identifier(path: str) -> dict | None:
    """Priority: integer > UUID > slug. Only the first match is used."""
    segments = [s for s in (path or "").split("/") if s]
    for index, seg in enumerate(segments):
        if INT_RE.match(seg) and not _is_structural_numeric_segment(segments, index):
            return {"location": "path", "name": None,
                    "original_value": seg, "value_type": "integer"}
    for seg in segments:
        if UUID_RE.match(seg):
            return {"location": "path", "name": None,
                    "original_value": seg, "value_type": "uuid"}
    for seg in segments:
        if is_slug(seg):
            return {"location": "path", "name": None,
                    "original_value": seg, "value_type": "slug"}
    return None


def extract_query_identifier(query_string: str) -> dict | None:
    if not query_string:
        return None
    occurrence_counts: dict[str, int] = {}
    for name, value in parse_qsl(query_string, keep_blank_values=False):
        occurrence = occurrence_counts.get(name, 0)
        occurrence_counts[name] = occurrence + 1
        # Filename pattern is strong enough to accept regardless of name
        # (fixture: /report?page=file1.php).
        if FILENAME_RE.match(value):
            return {"location": "query", "name": name,
                    "original_value": value, "value_type": "filename",
                    "occurrence": occurrence}
        if name not in IDENTIFIER_PARAM_ALLOWLIST:
            continue
        vtype = classify_value(value)
        if vtype in ("integer", "uuid", "filename"):
            return {"location": "query", "name": name,
                    "original_value": value, "value_type": vtype,
                    "occurrence": occurrence}
    return None


def extract_header_identifier(headers: dict | None) -> dict | None:
    if not headers:
        return None
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if is_blocked_header(name):
            continue
        if name.lower() not in HEADER_IDENTIFIER_ALLOWLIST:
            continue
        vtype = classify_value(value)
        if vtype is None:
            continue
        return {"location": "header", "name": name,
                "original_value": value, "value_type": vtype}
    return None


def extract_body_identifier(body, encoding: str | None = None) -> dict | None:
    """Extract an identifier from a dictionary or captured JSON body."""
    if isinstance(body, str):
        body_text = body
        if encoding == "base64":
            try:
                body_text = base64.b64decode(body, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return None
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            return None
    if not isinstance(body, dict):
        return None
    for name, value in body.items():
        hit = _body_value_to_ident(name, value)
        if hit:
            return hit
        if isinstance(value, dict):
            for sub_name, sub_value in value.items():
                hit = _body_value_to_ident(sub_name, sub_value)
                if hit:
                    return hit
    return None


def request_body_validity(body, encoding: str | None = None) -> tuple[bool, str | None]:
    """Validate the captured body representation without changing its bytes."""
    if body in (None, ""):
        return True, None
    if isinstance(body, bytes):
        return True, None
    if not isinstance(body, str):
        return False, "unsupported_body_type"
    if encoding in (None, "", "utf-8"):
        return True, None
    if encoding == "base64":
        try:
            base64.b64decode(body, validate=True)
        except (ValueError, TypeError):
            return False, "invalid_base64"
        return True, None
    return False, "unsupported_body_encoding"


def _body_value_to_ident(name, value):
    if not isinstance(name, str) or name not in IDENTIFIER_PARAM_ALLOWLIST:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return {"location": "body", "name": name,
                "original_value": str(value), "value_type": "integer"}
    if isinstance(value, str):
        vtype = classify_value(value)
        if vtype:
            return {"location": "body", "name": name,
                    "original_value": value, "value_type": vtype}
    return None


# --- Flow matching ---------------------------------------------------------

def flow_id(flow: dict) -> str:
    captured_id = flow.get("flow_id")
    if captured_id:
        return str(captured_id)
    key = f"{flow.get('method', '')}:{flow.get('url', '')}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def pick_safe_flow(url: str, flows: list) -> dict | None:
    """Return the best complete safe request/response flow for ``url``.

    The proxy writes request and response events separately.  When a real
    ``flow_id`` is present, only a pair with both events is eligible.  A
    record without ``flow_id`` is treated as a legacy combined fixture.
    A captured flow must contain exactly one request and one response, with
    the request occurring first and matching the response method and URL.
    """
    grouped: dict[str, list[tuple[int, dict]]] = {}
    legacy: list[dict] = []
    for index, record in enumerate(flows):
        if record.get("url") != url:
            continue
        captured_id = record.get("flow_id")
        if captured_id:
            grouped.setdefault(str(captured_id), []).append((index, record))
        else:
            legacy.append(record)

    candidates: list[dict] = []
    for records in grouped.values():
        requests = [(index, record) for index, record in records
                    if record.get("event") == "request"]
        responses = [(index, record) for index, record in records
                     if record.get("event") == "response"]
        if len(requests) != 1 or len(responses) != 1:
            continue
        request_index, request = requests[0]
        response_index, response = responses[0]
        if request_index >= response_index:
            continue
        if (
            (request.get("method") or "").upper()
            != (response.get("method") or "").upper()
            or request.get("url") != response.get("url")
        ):
            continue
        status_code = response.get("status_code")
        if not is_valid_status_code(status_code):
            continue
        method = (request.get("method") or "").upper()
        if method not in SAFE_METHODS:
            continue
        merged = dict(request)
        for key, value in response.items():
            if key not in {"method", "url", "flow_id"}:
                merged[key] = value
        merged["flow_id"] = str(request["flow_id"])
        candidates.append(merged)

    candidates.extend(
        record for record in legacy
        if (record.get("method") or "").upper() in SAFE_METHODS
        and is_valid_status_code(record.get("status_code"))
    )
    candidates.sort(
        key=lambda record: (
            0 if (record.get("method") or "").upper() == "GET" else 1,
            flow_id(record),
        )
    )
    return candidates[0] if candidates else None


# --- Ranking ---------------------------------------------------------------

def assign_rank(url_path: str, identifier: dict, flow: dict) -> int:
    low_path = (url_path or "").lower()
    if "/admin/" in low_path or "/internal/" in low_path:
        return 99
    if identifier["location"] == "body":
        return 9

    status = flow.get("status_code") or 0
    if 400 <= status < 500:
        return 5

    ctype = (flow.get("response_content_type") or "").lower()
    is_json = "json" in ctype
    is_html = "html" in ctype
    vtype = identifier["value_type"]
    loc = identifier["location"]

    if vtype == "integer" and status == 200 and is_json:
        if loc in ("path", "header"):
            return 1
        if loc == "query":
            return 2
    if status == 200 and is_html and loc in ("path", "query"):
        return 3
    if vtype in ("slug", "uuid", "filename"):
        return 4
    return 4


# --- Candidate assembly ----------------------------------------------------

def build_candidate(url: str, flow: dict, identifier: dict) -> dict:
    parsed = urlparse(url)
    candidate_key = "\x1f".join(
        (
            (flow.get("flow_id") or flow_id(flow)),
            (flow.get("method") or "").upper(),
            url,
            identifier["location"],
            identifier["name"] or "",
            identifier["original_value"],
        )
    )
    candidate_id = hashlib.sha256(candidate_key.encode("utf-8")).hexdigest()[:16]
    body = flow.get("request_body")
    body_encoding = flow.get("request_body_encoding")
    body_valid, body_validation_error = request_body_validity(body, body_encoding)
    request_metadata = {
        "headers_redacted": flow.get("request_headers_redacted", {}),
        "body": body,
        "body_encoding": body_encoding,
        "body_truncated": flow.get("request_body_truncated", False),
        "body_present": bool(flow.get("request_body_present")),
        "content_type": flow.get("request_content_type"),
        "body_valid": body_valid,
        "body_validation_error": body_validation_error,
    }
    return {
        "candidate_id": candidate_id,
        "source_url": url,
        "method": (flow.get("method") or "").upper(),
        "matched_flow_id": flow_id(flow),
        "provenance": (
            "fallback_discovered_endpoint"
            if str(flow.get("flow_id", "")).startswith("network:")
            else "captured_api_flow"
        ),
        "request": request_metadata,
        "baseline_status": flow.get("status_code"),
        "baseline_response_size": flow.get("response_size"),
        "baseline_content_type": flow.get("response_content_type"),
        "identifier": {
            "location": identifier["location"],
            "name": identifier["name"],
            "original_value": identifier["original_value"],
            "occurrence": identifier.get("occurrence"),
            "owner_session": get_owner_session(),
            "value_type": identifier["value_type"],
        },
        "risk_rank": assign_rank(parsed.path, identifier, flow),
        "notes": identifier_notes(identifier),
    }


def identifier_notes(identifier: dict) -> str:
    loc = identifier["location"]
    if loc == "header":
        return f"header identifier {identifier['name']}"
    if loc == "query":
        return f"query parameter {identifier['name']}"
    if loc == "body":
        return f"body key {identifier['name']}"
    return f"path segment {identifier['original_value']}"


# --- Loaders ---------------------------------------------------------------

def _endpoint_to_url(item) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return item.get("url") or item.get("endpoint") or item.get("path")
    return None


def load_discovered_endpoints(path: str) -> list[str]:
    """Handle both shapes:
       - {"urls": [...], "pages": [...]}
       - flat list of URLs (or dicts with a url key)
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    urls: list[str] = []
    if isinstance(data, dict):
        for key in ("urls", "pages"):
            for item in data.get(key) or []:
                u = _endpoint_to_url(item)
                if u:
                    urls.append(u)
    elif isinstance(data, list):
        for item in data:
            u = _endpoint_to_url(item)
            if u:
                urls.append(u)
    else:
        raise ValueError(
            f"Unexpected discovered_endpoints shape: {type(data).__name__}"
        )
    return urls


def load_api_flows(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("api_flows.json must be a JSON list")
    return data


def load_network_events(path: str) -> list[dict]:
    """Load Playwright network events for URL-only candidate fallback."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("network.json must be a JSON list")
    return data


def build_network_fallbacks(events: list[dict]) -> dict[str, dict]:
    """Build minimal safe flows from captured response events."""
    fallbacks: dict[str, dict] = {}
    for event in events:
        url = event.get("url")
        status = event.get("status")
        method = (event.get("method") or "").upper()
        if (
            not isinstance(url, str)
            or method not in SAFE_METHODS
            or not is_valid_status_code(status)
            or event.get("type") != "response"
        ):
            continue
        fallbacks.setdefault(
            url,
            {
                "flow_id": f"network:{method}:{url}",
                "method": method,
                "url": url,
                "status_code": status,
                "response_content_type": "",
                "request_headers_redacted": {},
                "request_body_present": False,
            },
        )
    return fallbacks


# --- Logging helpers -------------------------------------------------------

def _append_log(path: str | None, msg: str) -> None:
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def warn_if_no_headers(flows: list[dict], errors_log: str | None = None) -> bool:
    """Log a single warning if no flow carries request_headers_redacted.

    Returns True if the warning was issued.
    """
    if any("request_headers_redacted" in f for f in flows):
        return False
    log.warning(HEADER_WARNING_MSG)
    _append_log(errors_log, HEADER_WARNING_MSG)
    return True


# --- Main API --------------------------------------------------------------

def select_candidates(
    discovered_path: str,
    flows_path: str,
    max_candidates: int = 200,
    errors_log: str | None = None,
    network_path: str | None = None,
) -> list[dict]:
    """Run Stage A.

    Returns candidates sorted by ``(risk_rank, candidate_id)``. Candidate IDs
    are deterministic hashes of the captured flow and identifier metadata, so
    repeated runs with the same inputs produce the same ordering.
    """
    scope = get_scope()  # raises ScopeConfigError if unset
    urls = load_discovered_endpoints(discovered_path)
    flows = load_api_flows(flows_path)
    if network_path is None:
        sibling_network_path = os.path.join(os.path.dirname(flows_path), "network.json")
        network_path = sibling_network_path if os.path.isfile(sibling_network_path) else None
    network_fallbacks = (
        build_network_fallbacks(load_network_events(network_path))
        if network_path
        else {}
    )

    warn_if_no_headers(flows, errors_log)

    candidates: list[dict] = []
    dropped_no_flow = 0
    seen_urls: set[str] = set()

    for raw_url in urls:
        if not raw_url:
            continue
        url = normalize_url(raw_url, scope, flows + list(network_fallbacks.values()))
        if url in seen_urls:
            continue
        seen_urls.add(url)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not is_in_scope(host, scope):
            continue

        flow = pick_safe_flow(url, flows)
        if flow is None:
            flow = network_fallbacks.get(url)
        if flow is None:
            dropped_no_flow += 1
            continue

        method = (flow.get("method") or "").upper()
        if not is_method_allowed(method):
            continue
        if is_destructive_path(parsed.path):
            continue

        # Priority: path > query > header > body
        identifier = (
            extract_path_identifier(parsed.path)
            or extract_query_identifier(parsed.query)
            or extract_header_identifier(flow.get("request_headers_redacted"))
            or extract_body_identifier(
                flow.get("request_body"),
                flow.get("request_body_encoding"),
            )
        )
        if identifier is None:
            continue

        # Defence in depth: header identifiers must pass the allowlist.
        if identifier["location"] == "header":
            if is_blocked_header(identifier["name"]):
                continue
            if identifier["name"].lower() not in HEADER_IDENTIFIER_ALLOWLIST:
                continue

        candidates.append(build_candidate(url, flow, identifier))

    if dropped_no_flow:
        _append_log(
            errors_log,
            f"Stage A: dropped {dropped_no_flow} candidates with no matching api_flow",
        )

    candidates.sort(key=lambda c: (c["risk_rank"], c["candidate_id"]))

    if len(candidates) > max_candidates:
        dropped = len(candidates) - max_candidates
        candidates = candidates[:max_candidates]
        _append_log(
            errors_log,
            f"Stage A: capped output at {max_candidates} candidates "
            f"({dropped} dropped)",
        )

    return candidates


def write_candidates_atomic(path: str, candidates: list[dict]) -> None:
    """Serialize to <path>.tmp, fsync, then os.replace."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(candidates, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def run(
    discovered_path: str,
    flows_path: str,
    output_path: str,
    max_candidates: int = 200,
    errors_log: str | None = None,
    network_path: str | None = None,
) -> list[dict]:
    """Select candidates and write candidates.json atomically."""
    candidates = select_candidates(
        discovered_path, flows_path,
        max_candidates=max_candidates,
        errors_log=errors_log,
        network_path=network_path,
    )
    write_candidates_atomic(output_path, candidates)
    return candidates
