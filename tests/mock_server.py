"""
Mock server fixture for Phase 2 IDOR testing.

Satisfies all fixture route requirements from Phase 2 spec:
  - Session A ("alice") can GET /users/1, gets alice's data.
  - Session B ("bob") can GET /users/2, gets bob's data.
  - /users/1 with bob's credentials -> 200 with alice's data (INTENTIONALLY BROKEN - known positive).
  - /users/2 with alice's credentials -> 200 with bob's data (same).
  - /public/info?id=1 and ?id=2 -> identical body for both sessions (known negative).
  - /admin/users/1 -> 403 for bob (known negative).
  - /me -> returns different data per session (preflight: distinct).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Optional
from urllib.parse import parse_qs, urlparse


ALICE_COOKIE = "alice_test_cookie"
BOB_COOKIE = "bob_test_cookie"


class MockIDORHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy standard HTTP logs in test runner
        pass

    def _get_authenticated_user(self) -> Optional[str]:
        cookie_header = self.headers.get("Cookie", "")
        auth_header = self.headers.get("Authorization", "")
        if f"session={ALICE_COOKIE}" in cookie_header or f"Bearer {ALICE_COOKIE}" in auth_header:
            return "alice"
        if f"session={BOB_COOKIE}" in cookie_header or f"Bearer {BOB_COOKIE}" in auth_header:
            return "bob"
        return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        user = self._get_authenticated_user()

        # 1. Preflight who-am-i: /me
        if path == "/me":
            if user == "alice":
                self._send_json(200, {
                    "user": "alice",
                    "account_id": 1,
                    "role": "admin",
                    "name": "Alice Smith",
                    "email": "alice@example.internal",
                })
            elif user == "bob":
                self._send_json(200, {
                    "user": "bob",
                    "account_id": 2,
                    "role": "user",
                    "name": "Bob Jones",
                    "email": "bob@example.internal",
                })
            else:
                self._send_json(401, {"error": "Unauthorized"})
            return

        # 2. Public info endpoint: identical body across all users
        if path == "/public/info":
            # Response is >= 50 bytes and identical for everyone
            self._send_json(200, {
                "service": "AutoIDOR Public Service",
                "status": "operational",
                "version": "2.0.0",
                "public_content": "This endpoint is open to all users identically.",
            })
            return

        # 3. /admin/users/1: Forbidden for non-admin Bob
        if path == "/admin/users/1":
            if user == "alice":
                self._send_json(200, {
                    "admin_audit": "Sensitive admin console for user 1",
                    "role_required": "admin",
                    "status": "active",
                })
            elif user == "bob":
                self._send_json(403, {
                    "error": "Forbidden: Requires administrator privileges",
                })
            else:
                self._send_json(401, {"error": "Unauthorized"})
            return

        # 4. /users/1: Alice's record. Intentionally vulnerable to Bob (IDOR)
        if path == "/users/1":
            if user in ("alice", "bob"):
                # Returns Alice's record regardless, with request context
                self._send_json(200, {
                    "id": 1,
                    "owner": "alice",
                    "profile_secret": "alice_secret_financial_profile_record_1",
                    "viewer": user,
                    "details": "User 1 private record returned successfully.",
                })
            else:
                self._send_json(401, {"error": "Unauthorized"})
            return

        # 5. /users/2: Bob's record. Intentionally vulnerable to Alice (IDOR)
        if path == "/users/2":
            if user in ("alice", "bob"):
                self._send_json(200, {
                    "id": 2,
                    "owner": "bob",
                    "profile_secret": "bob_secret_financial_profile_record_2",
                    "viewer": user,
                    "details": "User 2 private record returned successfully.",
                })
            else:
                self._send_json(401, {"error": "Unauthorized"})
            return

        # 404 for other endpoints
        self._send_json(404, {"error": "Not found", "path": path})

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.server = ThreadingHTTPServer((host, port), MockIDORHandler)
        self.host, self.port = self.server.server_address
        self.base_url = f"http://{self.host}:{self.port}"
        self.thread: Optional[Thread] = None

    def start(self):
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
