"""Small intentionally vulnerable web app for local AutoIDOR demonstrations."""

from __future__ import annotations

import argparse
import json
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


USERS = {
    "alice": {"password": "alice-demo-password", "id": 1, "name": "Alice"},
    "bob": {"password": "bob-demo-password", "id": 2, "name": "Bob"},
}
DOCUMENTS = {
    101: {"id": 101, "owner": "alice", "title": "IEEE Elevate proposal", "classification": "private"},
    202: {"id": 202, "owner": "bob", "title": "Presentation notes", "classification": "private"},
}
SESSIONS: dict[str, str] = {}


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "AutoIDORDemo/1.0"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[demo] {self.address_string()} - {format % args}")

    def _user(self) -> str | None:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        session = jar.get("demo_session")
        return SESSIONS.get(session.value) if session else None

    def _send(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, object]) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode(), "application/json")

    def _redirect(self, location: str, session: str | None = None) -> None:
        headers = {"Location": location}
        if session:
            headers["Set-Cookie"] = f"demo_session={session}; Path=/; HttpOnly; SameSite=Lax"
        self._send(303, b"Redirecting", "text/plain", headers)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/login":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if username not in USERS or USERS[username]["password"] != password:
            self._send(401, LOGIN_PAGE.replace("</form>", "</form><p role='alert'>Invalid credentials</p>").encode(), "text/html")
            return
        session = secrets.token_urlsafe(24)
        SESSIONS[session] = username
        self._redirect("/", session)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            self._send(200, LOGIN_PAGE.encode(), "text/html")
            return
        user = self._user()
        if not user:
            if path.startswith("/api/"):
                self._json(401, {"error": "authentication required"})
            else:
                self._redirect("/login")
            return
        if path == "/":
            document_id = 101 if user == "alice" else 202
            page = DASHBOARD.replace("{{user}}", user).replace("{{document_id}}", str(document_id))
            self._send(200, page.encode(), "text/html")
            return
        if path == "/api/me":
            profile = USERS[user]
            self._json(200, {"id": profile["id"], "username": user, "name": profile["name"]})
            return
        if path.startswith("/api/documents/"):
            self._document(path, user, enforce_owner=False)
            return
        if path.startswith("/api/secure-documents/"):
            self._document(path, user, enforce_owner=True)
            return
        self._json(404, {"error": "not found"})

    def _document(self, path: str, user: str, enforce_owner: bool) -> None:
        try:
            document_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            self._json(400, {"error": "invalid document id"})
            return
        document = DOCUMENTS.get(document_id)
        if not document:
            self._json(404, {"error": "document not found"})
            return
        if enforce_owner and document["owner"] != user:
            self._json(403, {"error": "access denied", "requested_id": document_id})
            return
        # Intentional IDOR: /api/documents/<id> omits this ownership check.
        self._json(200, document)


LOGIN_PAGE = """<!doctype html><html><head><title>AutoIDOR Demo Login</title></head>
<body><main><h1>Document Vault</h1><p>Intentionally vulnerable local training target.</p>
<form method="post" action="/login"><label>Username <input name="username" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></main></body></html>"""

DASHBOARD = """<!doctype html><html><head><title>Document Vault</title></head>
<body><main><p class="eyebrow">IEEE Elevate security lab</p><h1>Welcome, {{user}}</h1>
<p>The vulnerable and protected APIs below return the same document for the owner.</p>
<section><h2>Vulnerable document API</h2><pre id="vulnerable">Loading...</pre></section>
<section><h2>Protected document API</h2><pre id="secure">Loading...</pre></section></main>
<script>
fetch('/api/documents/{{document_id}}').then(r => r.json()).then(v => vulnerable.textContent = JSON.stringify(v, null, 2));
fetch('/api/secure-documents/{{document_id}}').then(r => r.json()).then(v => secure.textContent = JSON.stringify(v, null, 2));
</script></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(f"Intentionally vulnerable demo running at http://{args.host}:{args.port}")
    print("Victim: alice / alice-demo-password")
    print("Attacker: bob / bob-demo-password")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
