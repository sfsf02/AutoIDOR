"""Start the local training target and run AutoIDOR against it."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def wait_for_server(host: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Demo server did not start on {host}:{port}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--headful", action="store_true")
    args = parser.parse_args()

    origin = f"http://127.0.0.1:{args.port}"
    server = subprocess.Popen(
        [sys.executable, str(ROOT / "demo" / "vulnerable_app.py"), "--port", str(args.port)],
        cwd=ROOT,
    )
    try:
        wait_for_server("127.0.0.1", args.port)
        env = os.environ.copy()
        env.update({
            "SCOPE_DOMAIN": origin,
            "LOGIN_URL": "/login",
            "VICTIM_USERNAME": "alice",
            "VICTIM_PASSWORD": "alice-demo-password",
            "ATTACKER_USERNAME": "bob",
            "ATTACKER_PASSWORD": "bob-demo-password",
            "IDENTITY_URL": "/api/me",
            "MAX_PAGES": "5",
            "MAX_DEPTH": "2",
            "DELAY_SECONDS": "0",
            "NETWORK_SETTLE_MS": "250",
            "NETWORK_IDLE_TIMEOUT_MS": "1000",
        })
        command = [sys.executable, str(ROOT / "AutoIDOR.py"), "--url", f"{origin}/"]
        if args.headful:
            command.append("--headful")
        return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == "__main__":
    raise SystemExit(main())
