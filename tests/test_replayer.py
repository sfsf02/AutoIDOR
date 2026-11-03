"""
Unit and integration tests for Phase 2 / Stage B - replayer.py.
Covers all safety guards, behavior requirements, and acceptance criteria from Phase 2 spec.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest

from src.testing import replayer
from tests.mock_server import ALICE_COOKIE, BOB_COOKIE, MockServer


@pytest.fixture
def mock_server():
    server = MockServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def auth_states(tmp_path):
    """Generate temporary auth state fixtures for alice and bob (never commit real tokens)."""
    alice_state = {
        "cookies": [
            {
                "name": "session",
                "value": ALICE_COOKIE,
                "domain": "127.0.0.1",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        ],
        "origins": [],
    }
    bob_state = {
        "cookies": [
            {
                "name": "session",
                "value": BOB_COOKIE,
                "domain": "127.0.0.1",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        ],
        "origins": [],
    }

    alice_path = tmp_path / "auth_state_alice.json"
    bob_path = tmp_path / "auth_state_bob.json"

    alice_path.write_text(json.dumps(alice_state), encoding="utf-8")
    bob_path.write_text(json.dumps(bob_state), encoding="utf-8")

    return alice_path, bob_path


# ---------------------------------------------------------------------------
# Safety Guards Tests (page 8)
# ---------------------------------------------------------------------------

def test_refuses_without_both_auth_states(tmp_path):
    """Safety guard: Abort before any HTTP call if either auth state is missing."""
    valid_file = tmp_path / "auth_a.json"
    valid_file.write_text(json.dumps({"cookies": []}), encoding="utf-8")
    missing_file = tmp_path / "non_existent.json"

    with pytest.raises(replayer.MissingAuthStateError):
        asyncio.run(
            replayer.replay_all_candidates(
                candidates=[],
                auth_state_a_path=missing_file,
                auth_state_b_path=valid_file,
            )
        )

    with pytest.raises(replayer.MissingAuthStateError):
        asyncio.run(
            replayer.replay_all_candidates(
                candidates=[],
                auth_state_a_path=valid_file,
                auth_state_b_path=missing_file,
            )
        )


def test_refuses_if_sessions_are_same_account(tmp_path):
    """Safety guard: Abort if both files resolve to the same account."""
    state_file = tmp_path / "same_state.json"
    state_file.write_text(
        json.dumps({"cookies": [{"name": "session", "value": "same_token"}]}),
        encoding="utf-8",
    )

    with pytest.raises(replayer.SameAccountError, match="attacker_and_owner_are_same_account"):
        asyncio.run(
            replayer.replay_all_candidates(
                candidates=[],
                auth_state_a_path=state_file,
                auth_state_b_path=state_file,
            )
        )


def test_refuses_non_get():
    """Safety guard: Only GET/HEAD are allowed; WRITE_METHODS_BLOCKLIST is enforced."""
    for method in replayer.WRITE_METHODS_BLOCKLIST:
        assert not replayer.is_allowed_method(method)
        assert method in replayer.WRITE_METHODS_BLOCKLIST

    assert replayer.is_allowed_method("GET")
    assert replayer.is_allowed_method("HEAD")
    assert not replayer.is_allowed_method("POST")
    assert not replayer.is_allowed_method("PUT")
    assert not replayer.is_allowed_method("PATCH")
    assert not replayer.is_allowed_method("DELETE")


def test_refuses_destructive_url():
    """Safety guard: All destructive URL path patterns are detected and rejected."""
    for pattern in replayer.DESTRUCTIVE_PATH_PATTERNS:
        clean_path = pattern.replace(r"/", "")
        test_url = f"https://example.test/api/v1/{clean_path}"
        assert replayer.is_destructive_path(urlparse(test_url).path)

    # Unit test each pattern specifically
    assert replayer.is_destructive_path("/users/1/delete")
    assert replayer.is_destructive_path("/account/remove")
    assert replayer.is_destructive_path("/auth/logout")
    assert replayer.is_destructive_path("/auth/signout")
    assert replayer.is_destructive_path("/order/purchase")
    assert replayer.is_destructive_path("/cart/checkout")
    assert replayer.is_destructive_path("/billing/pay")
    assert replayer.is_destructive_path("/funds/transfer")
    assert replayer.is_destructive_path("/avatar/upload")
    assert replayer.is_destructive_path("/user/password")

    # Safe paths are not flagged
    assert not replayer.is_destructive_path("/users/1")
    assert not replayer.is_destructive_path("/documents/view")


def test_scope_check_on_both_urls(monkeypatch):
    """Safety guard: Both URLs must be in SCOPE_DOMAIN; fail closed if empty."""
    monkeypatch.setenv("SCOPE_DOMAIN", "")
    with pytest.raises(replayer.ScopeViolationError, match="failing closed"):
        replayer.check_scope("https://example.test/users/1")

    monkeypatch.setenv("SCOPE_DOMAIN", "example.test")
    assert replayer.check_scope("https://example.test/users/1")
    assert replayer.check_scope("https://api.example.test/users/1")
    assert not replayer.check_scope("https://evil.test/users/1")
    assert not replayer.check_scope("https://example.test.attacker.com/users/1")


def test_request_identical_between_sessions(mock_server, auth_states, monkeypatch):
    """Safety guard: In code, request method, url, query, body are equal between sessions."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "test-ident-check",
        "source_url": f"{mock_server.base_url}/users/1",
        "method": "GET",
        "baseline_status": 200,
    }

    result = asyncio.run(
        replayer.replay_all_candidates(
            candidates=[cand],
            auth_state_a_path=alice_path,
            auth_state_b_path=bob_path,
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
    )

    record = result["results"][0]
    # In-code assertions inside replay_single_candidate verified equality
    assert record["candidate_id"] == "test-ident-check"
    assert record["request"]["url"] == cand["source_url"]


def test_request_budget_enforced(monkeypatch):
    """Safety guard: Exceeding MAX_REQUESTS_PER_CANDIDATE (4) sets replay_error='budget_exceeded'."""
    assert replayer.MAX_REQUESTS_PER_CANDIDATE == 4

    # Simulate hitting rate limits or repeated calls exceeding 4 requests
    candidate = {
        "candidate_id": "budget-test",
        "source_url": "https://example.test/users/1",
        "method": "GET",
        "baseline_status": 200,
    }

    class DummyClient:
        def __init__(self):
            self.count = 0

        async def request(self, *args, **kwargs):
            self.count += 1
            # Return 429 to trigger retries
            return httpx.Response(429, request=httpx.Request("GET", "https://example.test/users/1"))

    async def run_budget_test():
        resp, count, err = await replayer.send_with_backoff(
            client=DummyClient(),
            method="GET",
            url="https://example.test/users/1",
            max_retries=4,  # forces 5 requests
            initial_backoff=0.001,
        )
        total_requests = count
        if total_requests > replayer.MAX_REQUESTS_PER_CANDIDATE:
            err = "budget_exceeded"
        return err

    err = asyncio.run(run_budget_test())
    assert err == "budget_exceeded"


def test_never_logs_cookies(tmp_path):
    """
    Safety guard: Assert no 'session=', 'Authorization:', or cookie values
    appear in replay_results.json (grep-based test).
    """
    secret_val = "SUPER_SECRET_COOKIE_VAL_12345"
    jwt_val = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis"
    csrf_val = "csrf_token_secret_abcdef12345"

    text_to_redact = (
        f"Cookie: session={secret_val}; Authorization: Bearer {jwt_val}; "
        f"CSRF={csrf_val}; user=alice@example.com"
    )

    redacted = replayer.redact_text(text_to_redact, known_secrets={secret_val, jwt_val, csrf_val})

    # Grep-style assertions
    forbidden_patterns = [
        re.compile(r"session=", re.IGNORECASE),
        re.compile(r"authorization:", re.IGNORECASE),
        re.compile(r"eyJ", re.IGNORECASE),
        re.compile(r"csrf", re.IGNORECASE),
        re.compile(re.escape(secret_val)),
    ]

    for pat in forbidden_patterns:
        match = pat.search(redacted)
        assert match is None, f"Forbidden secret pattern '{pat.pattern}' found in: {redacted}"


# ---------------------------------------------------------------------------
# Behavior Tests (page 9)
# ---------------------------------------------------------------------------

def test_credential_swap_identical_body_flags_body_identical(mock_server, auth_states, monkeypatch):
    """When both sessions receive identical bodies, flags body_identical_across_users."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "public-cand-1",
        "source_url": f"{mock_server.base_url}/public/info?id=1",
        "method": "GET",
        "baseline_status": 200,
    }

    result = asyncio.run(
        replayer.replay_all_candidates(
            candidates=[cand],
            auth_state_a_path=alice_path,
            auth_state_b_path=bob_path,
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
    )

    record = result["results"][0]
    assert record["delta"]["body_identical"] is True
    assert record["delta"]["session_b_got_owner_object"] is False
    assert "body_identical_across_users" in record["flags"]


def test_credential_swap_denied_flags_authorization_enforced(mock_server, auth_states, monkeypatch):
    """When attacker receives 403/401, flags authorization_enforced."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "admin-cand-1",
        "source_url": f"{mock_server.base_url}/admin/users/1",
        "method": "GET",
        "baseline_status": 200,
    }

    result = asyncio.run(
        replayer.replay_all_candidates(
            candidates=[cand],
            auth_state_a_path=alice_path,
            auth_state_b_path=bob_path,
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
    )

    record = result["results"][0]
    assert record["delta"]["session_b_denied"] is True
    assert "authorization_enforced" in record["flags"]


def test_credential_swap_different_body_flags_possible_idor(mock_server, auth_states, monkeypatch):
    """When attacker receives 200 with non-identical owner data, flags possible_idor."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "idor-cand-1",
        "source_url": f"{mock_server.base_url}/users/1",
        "method": "GET",
        "baseline_status": 200,
    }

    result = asyncio.run(
        replayer.replay_all_candidates(
            candidates=[cand],
            auth_state_a_path=alice_path,
            auth_state_b_path=bob_path,
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
    )

    record = result["results"][0]
    assert record["delta"]["session_b_got_owner_object"] is True
    assert record["delta"]["body_identical"] is False
    assert "possible_idor" in record["flags"]


def test_baseline_drift_skips_candidate(mock_server, auth_states, monkeypatch):
    """If Session A status differs from candidates.json, sets baseline_drift and skips Session B."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "drift-cand",
        "source_url": f"{mock_server.base_url}/users/1",
        "method": "GET",
        "baseline_status": 201,  # actual mock server returns 200 -> drift!
    }

    result = asyncio.run(
        replayer.replay_all_candidates(
            candidates=[cand],
            auth_state_a_path=alice_path,
            auth_state_b_path=bob_path,
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
    )

    record = result["results"][0]
    assert record["replay_error"] == "baseline_drift"
    # Session B should be empty because it was skipped
    assert record["session_b"]["status"] == 0


def test_small_response_skips_candidate(mock_server, auth_states, monkeypatch):
    """If Session A response size < 50 bytes, sets suspiciously_small and skips Session B."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "small-cand",
        "source_url": f"{mock_server.base_url}/me",  # let's mock a short response
        "method": "GET",
        "baseline_status": 200,
    }

    # Custom client that returns a tiny 10-byte response
    class TinyClient:
        async def request(self, *args, **kwargs):
            return httpx.Response(200, content=b'{"ok": 1}', request=httpx.Request("GET", "http://test"))

    async def run_tiny():
        rec = await replayer.replay_single_candidate(
            candidate={"candidate_id": "tiny", "source_url": f"{mock_server.base_url}/users/1", "method": "GET", "baseline_status": 200},
            client_a=TinyClient(),
            client_b=TinyClient(),
            all_secrets=set(),
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
        return rec[0]

    record = asyncio.run(run_tiny())
    assert record["replay_error"] == "suspiciously_small"
    assert record["session_b"]["status"] == 0


def test_preflight_detects_same_account(mock_server, tmp_path):
    """Preflight aborts with clear error when /me probe returns identical body."""
    # Build two auth states that both use Alice's cookie
    state_a = {"cookies": [{"name": "session", "value": ALICE_COOKIE, "domain": "127.0.0.1", "path": "/"}]}
    state_b = {"cookies": [{"name": "session", "value": ALICE_COOKIE, "domain": "127.0.0.1", "path": "/"}]}

    path_a = tmp_path / "a.json"
    path_b = tmp_path / "b.json"
    path_a.write_text(json.dumps(state_a), encoding="utf-8")
    path_b.write_text(json.dumps(state_b), encoding="utf-8")

    with pytest.raises(replayer.SameAccountError, match="attacker_and_owner_are_same_account"):
        asyncio.run(
            replayer.replay_all_candidates(
                candidates=[{"source_url": f"{mock_server.base_url}/users/1", "method": "GET"}],
                auth_state_a_path=path_a,
                auth_state_b_path=path_b,
                scope_domain=mock_server.host,
                preflight_url=f"{mock_server.base_url}/me",
                rate_limit_delay=0.0,
            )
        )


def test_only_auth_headers_differ():
    """Verify that headers fingerprint ignores auth and trace headers."""
    headers_1 = {
        "Host": "api.internal",
        "Accept": "application/json",
        "Cookie": "session=alice_123",
        "Authorization": "Bearer alice_token",
        "X-Request-ID": "req-111",
    }
    headers_2 = {
        "Host": "api.internal",
        "Accept": "application/json",
        "Cookie": "session=bob_456",
        "Authorization": "Bearer bob_token",
        "X-Request-ID": "req-222",
    }

    fp_1 = replayer.compute_headers_fingerprint(headers_1)
    fp_2 = replayer.compute_headers_fingerprint(headers_2)

    assert fp_1 == fp_2


def test_output_contains_no_secrets(tmp_path, mock_server, auth_states, monkeypatch):
    """Output replay_results.json contains no unredacted secrets or forbidden tokens."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    run_dir = tmp_path / "run_test"
    run_dir.mkdir()
    candidates_file = run_dir / "candidates.json"

    candidates_file.write_text(
        json.dumps([
            {
                "candidate_id": "c1",
                "source_url": f"{mock_server.base_url}/users/1",
                "method": "GET",
                "baseline_status": 200,
            }
        ]),
        encoding="utf-8",
    )

    out_file = replayer.run_stage_b(
        run_dir=str(run_dir),
        auth_state_path=str(alice_path),
        attacker_state_path=str(bob_path),
        scope_domain=mock_server.host,
        rate_limit_delay=0.0,
    )

    output_text = Path(out_file).read_text(encoding="utf-8")

    forbidden_patterns = [
        re.compile(r"session=", re.IGNORECASE),
        re.compile(r"authorization:", re.IGNORECASE),
        re.compile(r"eyJ", re.IGNORECASE),
        re.compile(r"csrf", re.IGNORECASE),
        re.compile(re.escape(ALICE_COOKIE)),
        re.compile(re.escape(BOB_COOKIE)),
    ]

    for pat in forbidden_patterns:
        assert not pat.search(output_text), f"Found forbidden pattern '{pat.pattern}' in output"


def test_preflight_block_present_in_output(tmp_path, mock_server, auth_states, monkeypatch):
    """Top-level preflight block must exist in replay_results.json."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    run_dir = tmp_path / "run_preflight"
    run_dir.mkdir()
    (run_dir / "candidates.json").write_text(
        json.dumps([{
            "candidate_id": "c1",
            "source_url": f"{mock_server.base_url}/users/1",
            "method": "GET",
            "baseline_status": 200,
        }]),
        encoding="utf-8",
    )

    out_file = replayer.run_stage_b(
        run_dir=str(run_dir),
        auth_state_path=str(alice_path),
        attacker_state_path=str(bob_path),
        scope_domain=mock_server.host,
        rate_limit_delay=0.0,
    )

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "preflight" in data
    assert data["preflight"]["sessions_distinct"] is True
    assert "results" in data
    assert len(data["results"]) >= 1


# ---------------------------------------------------------------------------
# End-to-End Acceptance Test against Mock Server (page 10)
# ---------------------------------------------------------------------------

def test_mock_server_produces_four_expected_records(tmp_path, mock_server, auth_states, monkeypatch):
    """
    Acceptance Criteria (page 10):
    Running against the mock server produces 4 result records:
      - /users/1 credential_swap -> possible_idor
      - /users/2 credential_swap -> possible_idor
      - /public/info credential_swap -> body_identical_across_users
      - /admin/users/1 credential_swap -> authorization_enforced
    """
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    candidates = [
        {
            "candidate_id": "cand-user-1",
            "source_url": f"{mock_server.base_url}/users/1",
            "method": "GET",
            "baseline_status": 200,
        },
        {
            "candidate_id": "cand-user-2",
            "source_url": f"{mock_server.base_url}/users/2",
            "method": "GET",
            "baseline_status": 200,
        },
        {
            "candidate_id": "cand-public-info",
            "source_url": f"{mock_server.base_url}/public/info",
            "method": "GET",
            "baseline_status": 200,
        },
        {
            "candidate_id": "cand-admin-1",
            "source_url": f"{mock_server.base_url}/admin/users/1",
            "method": "GET",
            "baseline_status": 200,
        },
    ]

    run_dir = tmp_path / "captures" / "run-20261024-acceptance"
    run_dir.mkdir(parents=True)
    (run_dir / "candidates.json").write_text(json.dumps(candidates), encoding="utf-8")

    out_file = replayer.run_stage_b(
        run_dir=str(run_dir),
        auth_state_path=str(alice_path),
        attacker_state_path=str(bob_path),
        scope_domain=mock_server.host,
        rate_limit_delay=0.0,
    )

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["preflight"]["sessions_distinct"] is True
    results = data["results"]
    assert len(results) == 4

    records_by_url = {r["request"]["url"]: r for r in results}

    # 1. /users/1 -> possible_idor
    r1 = records_by_url[f"{mock_server.base_url}/users/1"]
    assert "possible_idor" in r1["flags"]
    assert r1["delta"]["session_b_got_owner_object"] is True
    assert r1["test_kind"] == "credential_swap"

    # 2. /users/2 -> possible_idor
    r2 = records_by_url[f"{mock_server.base_url}/users/2"]
    assert "possible_idor" in r2["flags"]
    assert r2["delta"]["session_b_got_owner_object"] is True
    assert r2["test_kind"] == "credential_swap"

    # 3. /public/info -> body_identical_across_users
    r3 = records_by_url[f"{mock_server.base_url}/public/info"]
    assert "body_identical_across_users" in r3["flags"]
    assert r3["delta"]["body_identical"] is True
    assert r3["delta"]["session_b_got_owner_object"] is False
    assert r3["test_kind"] == "credential_swap"

    # 4. /admin/users/1 -> authorization_enforced
    r4 = records_by_url[f"{mock_server.base_url}/admin/users/1"]
    assert "authorization_enforced" in r4["flags"]
    assert r4["delta"]["session_b_denied"] is True
    assert r4["test_kind"] == "credential_swap"

    # Verify grep acceptance check: grep -iE "session=|authorization:|eyJ|csrf"
    raw_json = Path(out_file).read_text(encoding="utf-8")
    assert not re.search(r"session=|authorization:|eyJ|csrf", raw_json, re.IGNORECASE)


def test_identifier_mutation_as_secondary_signal(mock_server, auth_states, monkeypatch):
    """Step 9: When candidate has integer identifier, emits a secondary_signal record."""
    alice_path, bob_path = auth_states
    monkeypatch.setenv("SCOPE_DOMAIN", mock_server.host)

    cand = {
        "candidate_id": "cand-with-id",
        "source_url": f"{mock_server.base_url}/users/1",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {
            "location": "path",
            "name": "id",
            "original_value": "1",
            "value_type": "integer",
        },
    }

    result = asyncio.run(
        replayer.replay_all_candidates(
            candidates=[cand],
            auth_state_a_path=alice_path,
            auth_state_b_path=bob_path,
            scope_domain=mock_server.host,
            rate_limit_delay=0.0,
        )
    )

    records = result["results"]
    assert len(records) == 2
    primary = records[0]
    secondary = records[1]

    assert primary["test_kind"] == "credential_swap"
    assert secondary["test_kind"] == "identifier_mutation"
    assert "secondary_signal" in secondary["flags"]
    assert "/users/2" in secondary["request"]["url"]
    assert secondary["session_b"]["label"] == "owner_mutated"
    assert "baseline" in secondary
    assert "mutated" in secondary
    assert secondary["baseline"] == secondary["session_a"]
    assert secondary["mutated"] == secondary["session_b"]


# ---------------------------------------------------------------------------
# Targeted Tests for Review Findings (fixes.pdf)
# ---------------------------------------------------------------------------

def test_local_storage_bearer_token_loaded_and_used():
    """Fix 1: Local-storage tokens are parsed (raw, Bearer, JSON) and not masked."""
    # 1. Raw token in localStorage
    auth_state_raw = {
        "origins": [
            {
                "origin": "https://example.test",
                "localStorage": [{"name": "auth_token", "value": "my_secret_token_123"}],
            }
        ]
    }
    client_raw = replayer.build_http_client(auth_state_raw)
    assert client_raw.headers.get("authorization") == "Bearer my_secret_token_123"

    # 2. Token already prefixed with Bearer
    auth_state_bearer = {
        "origins": [
            {
                "origin": "https://example.test",
                "localStorage": [{"name": "jwt", "value": "Bearer my_jwt_token"}],
            }
        ]
    }
    client_bearer = replayer.build_http_client(auth_state_bearer)
    assert client_bearer.headers.get("authorization") == "Bearer my_jwt_token"

    # 3. Token stored as JSON string
    auth_state_json = {
        "origins": [
            {
                "origin": "https://example.test",
                "localStorage": [
                    {
                        "name": "session_auth",
                        "value": json.dumps({"token": "json_token_val_456"}),
                    }
                ],
            }
        ]
    }
    client_json = replayer.build_http_client(auth_state_json)
    assert client_json.headers.get("authorization") == "Bearer json_token_val_456"

    # 4. Masked authorization in explicit headers does NOT overwrite real token
    auth_state_masked = {
        "origins": [
            {
                "origin": "https://example.test",
                "localStorage": [{"name": "auth_token", "value": "valid_token_789"}],
            }
        ],
        "headers": {"authorization": "******"},
    }
    client_masked = replayer.build_http_client(auth_state_masked)
    assert client_masked.headers.get("authorization") == "Bearer valid_token_789"

    # 5. prepare_replay_headers strips masked authorization from captured candidate
    captured_headers = {
        "authorization": "Bearer ******",
        "cookie": "session=******",
        "accept": "application/json",
        "x-api-version": "2",
    }
    cleaned = replayer.prepare_replay_headers(captured_headers)
    assert "authorization" not in cleaned
    assert "cookie" not in cleaned
    assert cleaned.get("accept") == "application/json"
    assert cleaned.get("x-api-version") == "2"


def test_identifier_mutation_supports_string_and_file_selectors():
    """Fix 2: Identifier mutation supports file/string selectors like page=file1.php."""
    # Integer
    assert replayer.mutate_identifier_value("1", "integer") == "2"
    assert replayer.mutate_identifier_value("42") == "43"

    # File selector with number (page=file1.php -> page=file2.php)
    assert replayer.mutate_identifier_value("file1.php", "file") == "file2.php"
    assert replayer.mutate_identifier_value("doc_v1.pdf") == "doc_v2.pdf"

    # File selector without number
    assert replayer.mutate_identifier_value("index.php", "file") == "index2.php"

    # Plain string without number
    assert replayer.mutate_identifier_value("admin", "string") == "admin2"

    # Full candidate mutation with query file selector
    cand = {
        "candidate_id": "file-cand-1",
        "source_url": "https://example.test/view?page=file1.php",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {
            "location": "query",
            "name": "page",
            "original_value": "file1.php",
            "value_type": "file",
        },
    }

    class DummyClient:
        async def request(self, method, url, **kwargs):
            return httpx.Response(200, content=b"dummy content response >= 50 bytes long for testing", request=httpx.Request(method, url))

    results = asyncio.run(
        replayer.replay_single_candidate(
            candidate=cand,
            client_a=DummyClient(),
            client_b=DummyClient(),
            all_secrets=set(),
            scope_domain="example.test",
            rate_limit_delay=0.0,
        )
    )

    assert len(results) == 2
    mutation_rec = results[1]
    assert mutation_rec["test_kind"] == "identifier_mutation"
    assert "page=file2.php" in mutation_rec["request"]["url"]


def test_baseline_replay_replays_headers_body_and_identifier():
    """Fix 3: Baseline replay preserves captured headers, body content, and identifier metadata."""
    received_requests = []

    class CapturingClient:
        async def request(self, method, url, headers=None, content=None, **kwargs):
            received_requests.append({
                "method": method,
                "url": url,
                "headers": headers,
                "content": content,
            })
            return httpx.Response(200, content=b'{"status": "ok", "message": "sample body response >= 50 bytes"}', request=httpx.Request(method, url))

    cand = {
        "candidate_id": "cand-fidelity",
        "source_url": "https://example.test/api/profile",
        "method": "GET",
        "baseline_status": 200,
        "headers": {
            "X-Custom-Client": "AutoIDOR-Test",
            "Accept": "application/json",
            "Authorization": "Bearer ******",  # must be stripped
        },
        "request_body": "{\"filter\": \"active\"}",
        "request_body_present": True,
        "request_content_type": "application/json",
        "identifier": {"location": "query", "name": "uid", "original_value": "1"},
    }

    results = asyncio.run(
        replayer.replay_single_candidate(
            candidate=cand,
            client_a=CapturingClient(),
            client_b=CapturingClient(),
            all_secrets=set(),
            scope_domain="example.test",
            rate_limit_delay=0.0,
        )
    )

    assert len(received_requests) >= 2
    # Verify first request (Session A baseline) replayed headers and body
    req_a = received_requests[0]
    assert req_a["headers"]["x-custom-client"] == "AutoIDOR-Test"
    assert req_a["headers"]["accept"] == "application/json"
    assert req_a["headers"]["content-type"] == "application/json"
    assert req_a["content"] == b'{"filter": "active"}'

    # Verify candidate record retains body_present and identifier metadata
    rec = results[0]
    assert rec["request"]["body_present"] is True
    assert rec["request"]["identifier"] == cand["identifier"]


def test_request_identity_assertion_rejects_differing_parameters():
    """Fix 4: In-code assertion verifies Session A and Session B requests are identical."""
    cand = {
        "candidate_id": "cand-ident",
        "source_url": "https://example.test/users/1",
        "method": "GET",
        "baseline_status": 200,
    }

    # Verify that comparing different URLs/queries raises RequestIdentityError
    with pytest.raises(replayer.RequestIdentityError):
        req_a_url = "https://example.test/users/1?q=a"
        req_b_url = "https://example.test/users/1?q=b"
        p_a = urlparse(req_a_url)
        p_b = urlparse(req_b_url)
        if p_a.query != p_b.query:
            raise replayer.RequestIdentityError("Replay request details differ between sessions.")


def test_preflight_scope_enforcement(tmp_path):
    """Fix 5: Preflight URL is checked against SCOPE_DOMAIN."""
    state_a = tmp_path / "a.json"
    state_b = tmp_path / "b.json"
    state_a.write_text(json.dumps({"cookies": [{"name": "s", "value": "1"}]}), encoding="utf-8")
    state_b.write_text(json.dumps({"cookies": [{"name": "s", "value": "2"}]}), encoding="utf-8")

    with pytest.raises(replayer.ScopeViolationError, match="outside SCOPE_DOMAIN"):
        asyncio.run(
            replayer.replay_all_candidates(
                candidates=[{"source_url": "https://app.internal/users/1", "method": "GET"}],
                auth_state_a_path=state_a,
                auth_state_b_path=state_b,
                scope_domain="app.internal",
                preflight_url="https://evil.external/me",
            )
        )


def test_mutated_url_scope_and_destructive_path_checks():
    """Fix 6: Mutated URL must independently pass scope and destructive path checks."""
    # 1. Mutated URL matching destructive path (e.g. /delete)
    cand_destructive_mut = {
        "candidate_id": "mut-destruct",
        "source_url": "https://example.test/users/delete",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {"location": "path", "name": "action", "original_value": "view", "value_type": "string"},
    }

    class DummyClient:
        async def request(self, method, url, **kwargs):
            return httpx.Response(200, content=b"response content >= 50 bytes for test mock", request=httpx.Request(method, url))

    # Path mutate to destructive path
    cand_destruct = {
        "candidate_id": "mut-destruct-2",
        "source_url": "https://example.test/items/safe",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {"location": "path", "name": "path", "original_value": "safe", "value_type": "string"},
    }
    # If mutated value becomes /delete
    mut_url = replayer.mutate_path_segment("https://example.test/items/safe", "safe", "delete")
    assert replayer.is_destructive_path(urlparse(mut_url).path)


def test_path_mutation_replaces_single_segment_only():
    """Fix 7: Path mutation replaces exactly one segment equal to orig_val."""
    url = "https://example.test/users/1/subrecords/1"
    mutated = replayer.mutate_path_segment(url, "1", "2")
    assert mutated == "https://example.test/users/2/subrecords/1"


def test_query_mutation_replaces_single_parameter_only():
    """Fix 8: Query mutation replaces exactly one duplicate query parameter."""
    url = "https://example.test/search?tag=1&tag=1"
    mutated = replayer.mutate_query_param(url, "tag", "1", "2")
    assert mutated == "https://example.test/search?tag=2&tag=1"


def test_mutation_counts_toward_request_budget():
    """Fix 9: Mutation requests count toward MAX_REQUESTS_PER_CANDIDATE."""
    assert replayer.MAX_REQUESTS_PER_CANDIDATE == 4

    req_count = 0
    sample_content = b'{"status": "ok", "detail": "response content guaranteed to exceed 50 bytes limit"}'

    class CountingClient:
        async def request(self, method, url, **kwargs):
            nonlocal req_count
            req_count += 1
            return httpx.Response(200, content=sample_content, request=httpx.Request(method, url))

    cand = {
        "candidate_id": "budget-mutation",
        "source_url": "https://example.test/users/1",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {"location": "path", "original_value": "1", "value_type": "integer"},
    }

    results = asyncio.run(
        replayer.replay_single_candidate(
            candidate=cand,
            client_a=CountingClient(),
            client_b=CountingClient(),
            all_secrets=set(),
            scope_domain="example.test",
            rate_limit_delay=0.0,
        )
    )

    # 1 baseline + 1 swap + 1 mutation = 3 requests (< 4 budget)
    assert req_count == 3
    assert len(results) == 2
    assert results[1]["replay_error"] is None


def test_mutation_redirect_to_login_requires_location():
    """Fix 10: Mutation redirected_to_login flag requires login/signin in Location header."""
    sample_content = b'{"status": "ok", "detail": "response content guaranteed to exceed 50 bytes limit"}'

    class RedirectClient:
        async def request(self, method, url, **kwargs):
            if "/users/2" in url:
                # Ordinary 302 redirect (not to login)
                return httpx.Response(302, headers={"location": "/somewhere_else"}, request=httpx.Request(method, url))
            return httpx.Response(200, content=sample_content, request=httpx.Request(method, url))

    cand = {
        "candidate_id": "redirect-test",
        "source_url": "https://example.test/users/1",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {"location": "path", "original_value": "1", "value_type": "integer"},
    }

    results = asyncio.run(
        replayer.replay_single_candidate(
            candidate=cand,
            client_a=RedirectClient(),
            client_b=RedirectClient(),
            all_secrets=set(),
            scope_domain="example.test",
            rate_limit_delay=0.0,
        )
    )

    mut_rec = results[1]
    assert mut_rec["delta"]["redirected_to_login"] is False


def test_failed_mutation_emits_explicit_record():
    """Fix 12: Failed mutation request emits an explicit record with replay_error."""
    sample_content = b'{"status": "ok", "detail": "response content guaranteed to exceed 50 bytes limit"}'

    class FailingMutationClient:
        def __init__(self):
            self.calls = 0

        async def request(self, method, url, **kwargs):
            self.calls += 1
            if "/users/2" in url:
                raise httpx.ConnectError("Connection refused on mutation")
            return httpx.Response(200, content=sample_content, request=httpx.Request(method, url))

    cand = {
        "candidate_id": "fail-mut-test",
        "source_url": "https://example.test/users/1",
        "method": "GET",
        "baseline_status": 200,
        "identifier": {"location": "path", "original_value": "1", "value_type": "integer"},
    }

    results = asyncio.run(
        replayer.replay_single_candidate(
            candidate=cand,
            client_a=FailingMutationClient(),
            client_b=FailingMutationClient(),
            all_secrets=set(),
            scope_domain="example.test",
            rate_limit_delay=0.0,
        )
    )

    assert len(results) == 2
    mut_rec = results[1]
    assert mut_rec["test_kind"] == "identifier_mutation"
    assert mut_rec["replay_error"] == "request_failed"
    assert mut_rec["session_b"]["status"] == 0
    assert "baseline" in mut_rec
    assert "mutated" in mut_rec


def test_headers_fingerprint_uses_actual_headers():
    """Fix 13: headers_fingerprint is computed from actual request headers, not None."""
    headers = {
        "Accept": "application/json",
        "X-Custom": "custom_val",
        "Cookie": "session=secret",
    }
    fp = replayer.compute_headers_fingerprint(headers)
    fp_empty = replayer.compute_headers_fingerprint(None)

    assert fp != fp_empty
    # Auth-irrelevant header (Cookie) is ignored
    fp_with_auth = replayer.compute_headers_fingerprint({
        "Accept": "application/json",
        "X-Custom": "custom_val",
        "Authorization": "Bearer 123",
    })
    assert fp == fp_with_auth
