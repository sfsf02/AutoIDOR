import json
import os
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import http

ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = ROOT / "captures"
OUTPUT_FILE = CAPTURE_DIR / "api_flows.json"
ERROR_FILE = ROOT / "errors.log"

SCOPE_DOMAIN = os.getenv("SCOPE_DOMAIN", "").lower().strip()
API_PREFIXES = tuple(
    prefix.strip()
    for prefix in os.getenv("API_PREFIXES", "/api").split(",")
    if prefix.strip()
)

STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"
}


def in_scope(host: str, scope: str) -> bool:
    """Return True only for the exact scope host or one of its subdomains."""
    host = host.lower().split(":")[0].rstrip(".")
    scope = scope.lower().strip().split(":")[0].rstrip(".")
    return bool(scope) and (host == scope or host.endswith("." + scope))


def is_api_request(url: str, prefixes=API_PREFIXES) -> bool:
    """Keep paths starting with configured API prefixes, excluding common assets."""
    path = urlparse(url).path.lower()
    if Path(path).suffix in STATIC_EXTENSIONS:
        return False
    return any(path.startswith(prefix.lower()) for prefix in prefixes)


class CaptureLogger:
    """mitmproxy addon that saves low-sensitivity metadata for in-scope API flows."""

    def __init__(self):
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        self.records = []

    def response(self, flow: http.HTTPFlow):
        try:
            if not SCOPE_DOMAIN:
                return

            if not in_scope(flow.request.pretty_host, SCOPE_DOMAIN):
                return

            if not is_api_request(flow.request.pretty_url):
                return

            request = flow.request
            response = flow.response
            record = {
                "method": request.method,
                "url": request.pretty_url,
                "status_code": response.status_code if response else None,
                "request_content_type": request.headers.get("content-type", ""),
                "response_content_type": (
                    response.headers.get("content-type", "") if response else ""
                ),
                "request_body_present": bool(request.raw_content),
                "response_body_present": bool(response and response.raw_content),
            }
            self.records.append(record)
            self._save()
        except Exception as exc:
            self._log_error(f"Capture error: {exc}")

    def _save(self):
        temporary = OUTPUT_FILE.with_suffix(".tmp")
        try:
            temporary.write_text(
                json.dumps(self.records, indent=2),
                encoding="utf-8",
            )
            temporary.replace(OUTPUT_FILE)
        except Exception as exc:
            self._log_error(f"Save error: {exc}")

    @staticmethod
    def _log_error(message: str):
        try:
            with ERROR_FILE.open("a", encoding="utf-8") as file:
                file.write(message + "\n")
        except OSError:
            pass


addons = [CaptureLogger()]
