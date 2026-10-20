import base64
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import http

ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = ROOT / "captures"
DEFAULT_OUTPUT_FILE = CAPTURE_DIR / "api_flows.json"
DEFAULT_ERROR_FILE = ROOT / "errors.log"
DEFAULT_API_PREFIXES = (
    "/api",
    "/ajax",
    "/graphql",
    "/rest",
    "/rpc",
    "/service",
    "/services",
)

STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"
}
API_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".do", ".action", ".jsp",
    ".json", ".xml",
}
DEFAULT_MAX_BODY_BYTES = 64 * 1024
DEFAULT_CHECKPOINT_INTERVAL = 25


def _normalize_host(value: str) -> str:
    """Extract a normalized hostname from a host, authority, or URL value."""
    value = value.strip()
    if not value:
        return ""

    if "://" not in value:
        if value.count(":") > 1 and not value.startswith("["):
            value = f"http://[{value}]"
        else:
            value = f"http://{value}"

    try:
        hostname = urlparse(value).hostname
    except ValueError:
        return ""
    return (hostname or "").rstrip(".").lower()


def in_scope(host: str, scope: str) -> bool:
    """Return True for the exact scope host or one of its subdomains."""
    normalized_host = _normalize_host(host)
    normalized_scope = _normalize_host(scope)
    return bool(normalized_scope) and (
        normalized_host == normalized_scope
        or normalized_host.endswith("." + normalized_scope)
    )


def is_api_request(
    url: str,
    prefixes=DEFAULT_API_PREFIXES,
    method: str = "GET",
    response_content_type: str = "",
) -> bool:
    """Identify likely API/backend requests without capturing ordinary pages."""
    parsed_url = urlparse(url)
    path = parsed_url.path.lower()
    if Path(path).suffix in STATIC_EXTENSIONS:
        return False

    normalized_prefixes = tuple(
        prefix.lower().rstrip("/") or "/"
        for prefix in prefixes
    )
    if any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in normalized_prefixes
    ):
        return True

    if Path(path).suffix in API_EXTENSIONS:
        return True

    if parsed_url.query or method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        return True

    content_type = response_content_type.lower().split(";", 1)[0].strip()
    return content_type in {
        "application/json",
        "application/graphql-response+json",
        "application/xml",
        "text/xml",
    }


def finalize_spool(output_file: Path) -> None:
    """Atomically finalize a JSONL spool into the public JSON array output."""
    output_file = Path(output_file)
    spool_file = output_file.with_name(f"{output_file.name}.records.jsonl")
    temporary = output_file.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        output.write("[")
        first = True
        if spool_file.exists():
            with spool_file.open("r", encoding="utf-8") as spool:
                for line in spool:
                    record = line.strip()
                    if not record:
                        continue
                    if not first:
                        output.write(",")
                    output.write(f"\n  {record}")
                    first = False
        output.write("\n]\n")
    temporary.replace(output_file)
    try:
        spool_file.unlink()
    except FileNotFoundError:
        pass


class CaptureLogger:
    """mitmproxy addon that saves low-sensitivity metadata for in-scope API flows."""

    def __init__(
        self,
        scope: str | None = None,
        output_file: Path | None = None,
        error_file: Path | None = None,
        api_prefixes: tuple[str, ...] | None = None,
        configure_from_environment: bool = True,
    ):
        self.scope_domain = ""
        self.capture_bodies = False
        self.max_body_bytes = DEFAULT_MAX_BODY_BYTES
        self.checkpoint_interval = DEFAULT_CHECKPOINT_INTERVAL
        self.records_since_checkpoint = 0
        self.output_file = Path(output_file or DEFAULT_OUTPUT_FILE)
        self.error_file = Path(error_file or DEFAULT_ERROR_FILE)
        self.api_prefixes = (
            tuple(api_prefixes)
            if api_prefixes is not None
            else DEFAULT_API_PREFIXES
        )
        self._set_output_paths()
        if configure_from_environment:
            self._configure(
                scope=scope,
                output_file=output_file,
                error_file=error_file,
                api_prefixes=api_prefixes,
            )

    def load(self, loader):
        """Load environment configuration after mitmproxy starts the addon."""
        self._configure()

    def _configure(
        self,
        scope: str | None = None,
        output_file: Path | None = None,
        error_file: Path | None = None,
        api_prefixes: tuple[str, ...] | None = None,
    ) -> None:
        self.scope_domain = (
            os.getenv("SCOPE_DOMAIN", "") if scope is None else scope
        ).strip().lower()
        self.output_file = Path(
            os.getenv("CAPTURE_OUT", str(self.output_file))
            if output_file is None
            else output_file
        )
        self.error_file = Path(
            os.getenv("CAPTURE_ERROR_OUT", str(self.error_file))
            if error_file is None
            else error_file
        )
        configured_prefixes = os.getenv("API_PREFIXES") if api_prefixes is None else None
        if configured_prefixes is not None:
            self.api_prefixes = tuple(
                prefix.strip()
                for prefix in configured_prefixes.split(",")
                if prefix.strip()
            )
        elif api_prefixes is not None:
            self.api_prefixes = tuple(api_prefixes)
        self.capture_bodies = os.getenv(
            "CAPTURE_BODIES",
            "",
        ).strip().lower() in {"1", "true", "yes"}
        try:
            self.max_body_bytes = max(
                0,
                int(os.getenv("MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES))),
            )
        except ValueError:
            invalid_value = os.getenv("MAX_BODY_BYTES", "")
            self.max_body_bytes = DEFAULT_MAX_BODY_BYTES
            self._log_error(
                "Invalid MAX_BODY_BYTES value "
                f"{invalid_value!r}; using {DEFAULT_MAX_BODY_BYTES}"
            )
        try:
            self.checkpoint_interval = max(
                0,
                int(os.getenv(
                    "CAPTURE_CHECKPOINT_INTERVAL",
                    str(DEFAULT_CHECKPOINT_INTERVAL),
                )),
            )
        except ValueError:
            self.checkpoint_interval = DEFAULT_CHECKPOINT_INTERVAL
            self._log_error(
                "Invalid CAPTURE_CHECKPOINT_INTERVAL value; "
                f"using {DEFAULT_CHECKPOINT_INTERVAL}"
            )
        self._set_output_paths()

    def _set_output_paths(self) -> None:
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.error_file.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print(
                f"Could not create error log directory {self.error_file.parent}: {exc}",
                file=sys.stderr,
                flush=True,
            )
        self.spool_file = self.output_file.with_name(
            f"{self.output_file.name}.records.jsonl"
        )

    def request(self, flow: http.HTTPFlow):
        try:
            if not self._is_in_scope(flow):
                return

            if not is_api_request(
                flow.request.pretty_url,
                prefixes=self.api_prefixes,
                method=flow.request.method,
            ):
                return

            self._append_record(self._build_record(flow, "request"))
        except Exception as exc:
            self._log_error(f"Request capture error: {exc}")

    def response(self, flow: http.HTTPFlow):
        try:
            if not self._is_in_scope(flow):
                return

            response = flow.response
            if not is_api_request(
                flow.request.pretty_url,
                prefixes=self.api_prefixes,
                method=flow.request.method,
                response_content_type=(
                    response.headers.get("content-type", "")
                    if response
                    else ""
                ),
            ):
                return

            self._append_record(self._build_record(flow, "response"))
        except Exception as exc:
            self._log_error(f"Response capture error: {exc}")

    def error(self, flow: http.HTTPFlow):
        try:
            if not self._is_in_scope(flow):
                return
            if not is_api_request(
                flow.request.pretty_url,
                prefixes=self.api_prefixes,
                method=flow.request.method,
            ):
                return

            record = self._build_record(flow, "error")
            record["error"] = flow.error.message if flow.error else "unknown flow error"
            self._append_record(record)
        except Exception as exc:
            self._log_error(f"Flow error capture failed: {exc}")

    def _is_in_scope(self, flow: http.HTTPFlow) -> bool:
        return bool(self.scope_domain) and in_scope(
            flow.request.pretty_host,
            self.scope_domain,
        )

    @staticmethod
    def _body_value(content: bytes, max_bytes: int) -> tuple[str, str, bool]:
        truncated = len(content) > max_bytes
        captured_content = content[:max_bytes]
        try:
            return captured_content.decode("utf-8"), "utf-8", truncated
        except UnicodeDecodeError:
            return (
                base64.b64encode(captured_content).decode("ascii"),
                "base64",
                truncated,
            )

    def _build_record(self, flow: http.HTTPFlow, event: str) -> dict:
        request = flow.request
        response = flow.response
        record = {
            "capture_source": "mitmproxy",
            "flow_id": str(getattr(flow, "id", id(flow))),
            "event": event,
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
        if self.capture_bodies:
            if request.raw_content:
                body, encoding, truncated = self._body_value(
                    request.raw_content,
                    self.max_body_bytes,
                )
                record["request_body"] = body
                record["request_body_encoding"] = encoding
                record["request_body_truncated"] = truncated
            if response and response.raw_content:
                body, encoding, truncated = self._body_value(
                    response.raw_content,
                    self.max_body_bytes,
                )
                record["response_body"] = body
                record["response_body_encoding"] = encoding
                record["response_body_truncated"] = truncated
        return record

    def done(self):
        """Persist the complete capture once mitmproxy has finished."""
        self._save()

    def _save(self):
        try:
            finalize_spool(self.output_file)
        except Exception as exc:
            self._log_error(f"Save error: {exc}")

    def _append_record(self, record: dict) -> None:
        """Append one record to disk so capture size does not consume memory."""
        with self.spool_file.open("a", encoding="utf-8") as spool:
            spool.write(json.dumps(record, separators=(",", ":")) + "\n")
        self.records_since_checkpoint += 1
        if (
            self.checkpoint_interval > 0
            and self.records_since_checkpoint >= self.checkpoint_interval
        ):
            self._save()
            self.records_since_checkpoint = 0

    def _log_error(self, message: str):
        """Write an error to the capture log and always expose it on stderr."""
        try:
            with self.error_file.open("a", encoding="utf-8") as file:
                file.write(message + "\n")
        except OSError as exc:
            print(
                f"{message} (could not write {self.error_file}: {exc})",
                file=sys.stderr,
                flush=True,
            )


addons = [CaptureLogger(configure_from_environment=False)]