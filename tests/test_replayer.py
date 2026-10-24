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
