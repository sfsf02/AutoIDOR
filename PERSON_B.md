# Person B: Phase 2 — Credential-Swap Replayer (Stage B)

## Overview

Person B (Daniel) owns Stage B of Phase 2 IDOR testing: **`src/testing/replayer.py`**.
Takes candidate endpoints discovered in Stage A (`captures/run-*/candidates.json`), verifies the baseline response with Session A ("owner"), then replays the identical request using Session B ("attacker") credentials to detect Broken Object Level Authorization / IDOR vulnerabilities.

The output `captures/run-*/replay_results.json` strictly adheres to the Phase 2 contract and feeds directly into Stage C (`classifier.py` and `report.py`).

## What Changed in Phase 2

- **`src/testing/replayer.py`**:
  - `replay_all_candidates`: Core async orchestration loop.
  - `run_stage_b(run_dir)`: Standard pipeline entry point. Reads `<run_dir>/candidates.json`, performs credential swap, and atomically writes `<run_dir>/replay_results.json`.
  - **Preflight distinctness verification**: Performs a `/me` who-am-i probe using both sessions. If bodies match, aborts immediately with `SameAccountError("attacker_and_owner_are_same_account")` to avoid false negatives.
  - **Enforces all blocking safety guards**:
    - Aborts before any HTTP call if either `auth_state.json` or `auth_state_attacker.json` is missing (`MissingAuthStateError`).
    - GET/HEAD only: enforces `WRITE_METHODS_BLOCKLIST = {"POST", "PUT", "PATCH", "DELETE"}` to protect against unauthorized state changes.
    - Destructive path protection: skips any URL matching `DESTRUCTIVE_PATH_PATTERNS` (`/delete`, `/remove`, `/logout`, `/signout`, `/purchase`, `/checkout`, `/pay`, `/transfer`, `/upload`, `/password`).
    - Scope enforcement: fails closed if `SCOPE_DOMAIN` is empty; ensures both URLs reside in `SCOPE_DOMAIN`.
    - In-code request identity assertions: asserts request method, url, query, and body are byte-identical between sessions (only auth headers differ).
    - Rate limiting & budget caps: 1 req/sec globally, 1 req/2sec on list endpoints; exponential backoff on 429 (2s, 4s, 8s); hard cap `MAX_REQUESTS_PER_CANDIDATE = 4`.
    - Secret scrubbing and snippet truncation: trims body snippets to 512 bytes (or 128 bytes for HTML); scrubs JWTs, cookies, CSRF tokens, session keys, and email addresses. Never writes unredacted secrets to disk.
    - Secondary signal: supports optional integer identifier mutation probes on Session A when configured (`test_kind="identifier_mutation"`).
- **`tests/mock_server.py`**:
  - Standalone threaded HTTP mock server implementing the Phase 2 specification routes (`/me`, `/users/1`, `/users/2`, `/public/info`, `/admin/users/1`) for automated and harness testing.
- **`tests/test_replayer.py`**:
  - 19 automated tests covering all 8 blocking safety guards, behavior cases (baseline drift, small response, denied, identical body, possible IDOR), and the end-to-end acceptance criteria against the mock server.

## Phase 1 Changes (Reference)

- `src/discovery/auth.py`: `login_if_needed(page)` restores saved session or signs in.
- `src/discovery/interactions.py`: `trigger_page_interactions(page)` scrolls and clicks safe expanders.
- `tests/test_interactions.py`: covers interaction and auth restoration.

## How to Test

See [`TESTING_PERSON_B.md`](file:///C:/Users/user/Desktop/Daniel/Projects/AutoIDOR/TESTING_PERSON_B.md) for the complete clean-run testing guide and acceptance evidence.
