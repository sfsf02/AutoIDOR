import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADDON = ROOT / "src" / "capture" / "logger.py"
CAPTURE_DIR = ROOT / "captures"
ERROR_FILE = ROOT / "errors.log"


def main() -> int:
    if not os.getenv("SCOPE_DOMAIN", "").strip():
        print("Set SCOPE_DOMAIN to your authorized test domain first.")
        return 1

    executable = shutil.which("mitmdump")
    if not executable:
        print("mitmdump not found. Activate your virtual environment and install requirements.")
        return 1

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    command = [
        executable,
        "--listen-host", "127.0.0.1",
        "--listen-port", os.getenv("PROXY_PORT", "8080"),
        "-s", str(ADDON),
        "--save-stream-file", str(CAPTURE_DIR / "raw_flows.mitm"),
    ]

    try:
        subprocess.run(command, cwd=ROOT, check=True)
    except KeyboardInterrupt:
        print("Proxy stopped.")
    except (OSError, subprocess.CalledProcessError) as exc:
        try:
            with ERROR_FILE.open("a", encoding="utf-8") as file:
                file.write(f"Proxy startup/runtime error: {exc}\n")
        except OSError:
            pass
        print(f"Proxy error: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
