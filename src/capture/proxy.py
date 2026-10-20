import asyncio
import os
import signal
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ADDON = ROOT / "src" / "capture" / "logger.py"
CAPTURE_DIR = ROOT / "captures"
ERROR_FILE = ROOT / "errors.log"


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
        "--set",
        f"capture_out={api_capture}",
        "--save-stream-file",
        str(raw_capture),
    ]

    env = os.environ.copy()
    env["SCOPE_DOMAIN"] = scope

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


async def _run_cli() -> int:
    """Run the capture proxy until interrupted."""
    scope = os.getenv("SCOPE_DOMAIN", "").strip()

    if not scope:
        print(
            "Set SCOPE_DOMAIN to your authorized "
            "test domain first."
        )
        return 1

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
            capture_dir=CAPTURE_DIR,
            port=port,
        ):
            print(
                f"Capture proxy running on "
                f"127.0.0.1:{port}"
            )

            await asyncio.Event().wait()

    except KeyboardInterrupt:
        print("Proxy stopped.")

    except Exception as exc:
        try:
            with ERROR_FILE.open(
                "a",
                encoding="utf-8",
            ) as file:
                file.write(
                    f"Proxy startup/runtime error: {exc}\n"
                )

        except OSError:
            pass

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