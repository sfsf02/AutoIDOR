# Testing Person B (Phase 2: Stage B Credential-Swap Replayer)

Clean-run testing guide for Person B's Phase 2 implementation (`src/testing/replayer.py`, `tests/mock_server.py`, `tests/test_replayer.py`).

## 1. Prerequisites

- Python 3.11+
- Dependencies installed:
  ```bash
  python -m pip install -r requirements.txt
  ```

## 2. Automated Test Suite

Run the full Stage B test suite:

```bash
python -m pytest tests/test_replayer.py -v
```

Expected result: **19 passed**.

Run the entire test suite across all modules:

```bash
python -m pytest tests/ -v
```

Expected result: **34 passed** (8 Person B Phase 1 tests + 7 Person C Phase 1 tests + 19 Person B Phase 2 tests).

### Breakdown of the 19 Person B Phase 2 Tests

| Category | Test Function | Purpose / Safety Guard Verified |
|---|---|---|
| **Safety Guard** | `test_refuses_without_both_auth_states` | Aborts before any HTTP call if either auth state is missing (`MissingAuthStateError`). |
| **Safety Guard** | `test_refuses_if_sessions_are_same_account` | Aborts if both sessions resolve to the same account (`SameAccountError`). |
| **Safety Guard** | `test_refuses_non_get` | Enforces `WRITE_METHODS_BLOCKLIST = {"POST", "PUT", "PATCH", "DELETE"}` (GET/HEAD only). |
| **Safety Guard** | `test_refuses_destructive_url` | Checks and rejects all patterns in `DESTRUCTIVE_PATH_PATTERNS` (`/delete`, `/remove`, `/logout`, etc.). |
| **Safety Guard** | `test_scope_check_on_both_urls` | Both URLs must be in `SCOPE_DOMAIN`; fails closed if `SCOPE_DOMAIN` is empty. |
| **Safety Guard** | `test_request_identical_between_sessions` | In-code assertion verifies request method, url, query, and body are identical between sessions. |
| **Safety Guard** | `test_request_budget_enforced` | Capped at `MAX_REQUESTS_PER_CANDIDATE = 4`. Exceeding sets `replay_error="budget_exceeded"`. |
| **Safety Guard** | `test_never_logs_cookies` | Grep-based test asserts no `session=`, `Authorization:`, `csrf`, `eyJ`, or raw cookie values leak. |
| **Behavior** | `test_credential_swap_identical_body_flags_body_identical` | When attacker gets identical body, sets `body_identical=True` and seeds `body_identical_across_users`. |
| **Behavior** | `test_credential_swap_denied_flags_authorization_enforced` | When attacker gets 401/403, sets `session_b_denied=True` and seeds `authorization_enforced`. |
| **Behavior** | `test_credential_swap_different_body_flags_possible_idor` | When attacker gets 200 with non-identical owner data, sets `session_b_got_owner_object=True` and seeds `possible_idor`. |
| **Behavior** | `test_baseline_drift_skips_candidate` | Status mismatch against baseline sets `replay_error="baseline_drift"` and skips Session B. |
| **Behavior** | `test_small_response_skips_candidate` | Response size < 50 bytes sets `replay_error="suspiciously_small"` and skips Session B. |
| **Behavior** | `test_preflight_detects_same_account` | Aborts with `SameAccountError` when `/me` probe returns identical body. |
| **Behavior** | `test_only_auth_headers_differ` | Header fingerprinting ignores auth and trace headers. |
| **Behavior** | `test_output_contains_no_secrets` | Output `replay_results.json` contains no unredacted secret tokens. |
| **Behavior** | `test_preflight_block_present_in_output` | Top-level `preflight` block with `sessions_distinct: True` is present in output. |
| **Acceptance** | `test_mock_server_produces_four_expected_records` | End-to-end against mock server produces 4 records matching specification. |
| **Secondary** | `test_identifier_mutation_as_secondary_signal` | Emits secondary corroborating record when integer identifier is present. |

## 3. Acceptance Criteria Verification

### Criterion 1: Mock server produces 4 expected records
Run:
```bash
python -m pytest tests/test_replayer.py -k test_mock_server_produces_four_expected_records -v
```
Produces:
- `/users/1` credential_swap → `possible_idor`
- `/users/2` credential_swap → `possible_idor`
- `/public/info` credential_swap → `body_identical_across_users`
- `/admin/users/1` credential_swap → `authorization_enforced`

### Criterion 2: Secret leak check
Run grep check on generated replay results:
```bash
grep -iE "session=|authorization:|eyJ|csrf" captures/run-*/*.json
```
Expected result: **returns nothing**.

### Criterion 3: Git clean check
```bash
git diff --stat | grep auth_state
```
Expected result: **returns nothing** (zero modifications to auth_state*.json).

### Criterion 4: Stage C Compatibility
The output schema of `replay_results.json` strictly conforms to the Stage C contract required by `src/testing/classifier.py` and `src/testing/report.py`.
Feeding Stage B's output into Stage C generates `phase2_results.json` and `phase2_report.md` seamlessly.

## 4. Manual Execution

To run Stage B on a capture folder containing `candidates.json`:

```bash
# Set environment variables:
export SCOPE_DOMAIN="example.com"
export AUTH_STATE_PATH="./auth_state.json"
export ATTACKER_STATE_PATH="./auth_state_attacker.json"

# Run Stage B:
python -m src.testing.replayer captures/run-20261024-001/
```

Wrote `captures/run-20261024-001/replay_results.json`.
