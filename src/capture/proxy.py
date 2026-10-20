import asyncio
import os
import signal
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from src.capture.logger import finalize_spool


ROOT = Path(__file__).resolve().parents[2]
ADDON = ROOT / "src" / "capture" / "logger.py"
CAPTURE_DIR = ROOT / "captures"


def _report_proxy_error(message: str, error_file: Path | None = None) -> None:
    """Persist a proxy error when possible and always report it on stderr."""
    if error_file is not None:
        try:
            error_file.parent.mkdir(parents=True, exist_ok=True)
            with error_file.open("a", encoding="utf-8") as file:
                file.write(message + "\n")
            return
        except OSError as exc:
            message = f"{message} (could not write {error_file}: {exc})"

    print(message, file=sys.stderr, flush=True)


def _scope_url(scope: str) -> str:
    """Return a parseable URL for a domain, authority, or IPv6 scope."""
    scope = scope.strip()
    if "://" in scope:
        return scope
    if scope.count(":") > 1 and not scope.startswith("["):
        scope = f"[{scope}]"
    return f"http://{scope}"


def get_capture_origin_dir(scope: str) -> Path:
    """Return the persistent capture directory for a target origin/scope."""
    parsed = urlparse(_scope_url(scope))
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("scope must contain a valid host and port") from exc
    hostname = (hostname or "").replace(":", "-").rstrip(".").lower()
    if not hostname:
        raise ValueError("scope must contain a valid host")

    origin_name = f"{parsed.scheme.lower()}_{hostname}"
    if port:
        origin_name = f"{origin_name}_{port}"
    return CAPTURE_DIR / origin_name


def get_proxy_run_dir(scope: str, run_at: datetime | None = None) -> Path:
    """Return a unique capture directory for one standalone proxy run."""
    timestamp = (run_at or datetime.now()).strftime("%Y%m%d_%H%M%S_%f")
    return get_capture_origin_dir(scope) / timestamp


async def _wait_until_ready(
    process: asyncio.subprocess.Process,
    port: int,
    timeout: float = 20.0,
) -> None:
    """Wait until mitmdump is accepting connections on the proxy port."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    while loop.time() < deadline:
        if process.returncode is not None:
            raise RuntimeError(
                "mitmdump exited before becoming ready "
                f"(exit code {process.returncode})"
            )

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port),
                timeout=0.25,
            )

            writer.close()
            await writer.wait_closed()
            return

        except (
            ConnectionRefusedError,
            OSError,
            asyncio.TimeoutError,
        ):
            await asyncio.sleep(0.05)

    raise TimeoutError(
        f"mitmdump did not start listening on port {port} "
        f"within {timeout} seconds"
    )


@asynccontextmanager
async def start_proxy(
    scope: str,
    capture_dir: Path,
    port: int = 8080,
) -> AsyncIterator[int]:
    """
    Launch mitmdump as a managed subprocess.

    Args:
        scope:
            Authorized target domain/scope.

        capture_dir:
            Directory where capture files are stored.

        port:
            Local proxy port. Defaults to 8080.

    Yields:
        The integer port mitmdump is listening on.

    Guarantees:
        - capture_dir is created if necessary.
        - scope is passed to the capture addon.
        - mitmdump is stopped when the context exits.
        - capture output is written inside capture_dir.
    """
    scope = scope.strip()

    if not scope:
        raise ValueError("scope must not be empty")

    capture_dir = Path(capture_dir)
    capture_dir.mkdir(parents=True, exist_ok=True)

    raw_capture = capture_dir / "raw_flows.mitm"
    api_capture = capture_dir / "api_flows.json"
    error_capture = capture_dir / "proxy_errors.log"

    command = [
        sys.executable,
        "-u",
        "-c",
        (
            "import sys; "
            "from mitmproxy.tools.main import mitmdump; "
            "sys.argv = ['mitmdump'] + sys.argv[1:]; "
            "mitmdump()"
        ),
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        str(port),
        "-s",
        str(ADDON),
        "--save-stream-file",
        str(raw_capture),
    ]

    env = os.environ.copy()
    env["SCOPE_DOMAIN"] = scope
    env["CAPTURE_OUT"] = str(api_capture)
    env["CAPTURE_ERROR_OUT"] = str(error_capture)

    creationflags = 0

    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(ROOT),
        env=env,
        creationflags=creationflags,
    )

    try:
        await _wait_until_ready(
            process=process,
            port=port,
        )

        yield port

    finally:
        if process.returncode is None:
            if sys.platform == "win32":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGINT)

            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=5.0,
                )

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        try:
            finalize_spool(api_capture)
        except OSError as exc:
            _report_proxy_error(
                f"Could not finalize proxy capture {api_capture}: {exc}",
                error_capture,
            )


async def _run_cli() -> int:
    """Run the capture proxy until interrupted."""
    load_dotenv(ROOT / ".env")
    scope = os.getenv("SCOPE_DOMAIN", "").strip()

    if not scope:
        print(
            "Set SCOPE_DOMAIN to your authorized "
            "test domain first."
        )
        return 1

    capture_dir = get_proxy_run_dir(scope)
    error_file = capture_dir / "proxy_errors.log"

    try:
        port = int(
            os.getenv(
                "PROXY_PORT",
                "8080",
            )
        )

    except ValueError:
        print("PROXY_PORT must be an integer.")
        return 1

    try:
        async with start_proxy(
            scope=scope,
            capture_dir=capture_dir,
            port=port,
        ):
            print(
                f"Capture proxy running on "
                f"127.0.0.1:{port}; output: {capture_dir}"
            )

            await asyncio.Event().wait()

    except KeyboardInterrupt:
        print("Proxy stopped.")

    except Exception as exc:
        _report_proxy_error(
            f"Proxy startup/runtime error: {exc}",
            error_file,
        )
        print(f"Proxy error: {exc}")
        return 1

    return 0


def main() -> int:
    """CLI entry point."""
    try:
        return asyncio.run(_run_cli())

    except KeyboardInterrupt:
        print("Proxy stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())