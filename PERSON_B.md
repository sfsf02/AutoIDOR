# Person B: authentication and page interactions

Owner: Person B (`src/discovery/auth.py`, `src/discovery/interactions.py`,
`tests/test_interactions.py`).

The two public hook signatures are frozen and unchanged:

```python
async def login_if_needed(page: Page) -> None
async def trigger_page_interactions(page: Page) -> None
```

## What changed

### Base implementation (`feature/B-interactions`)

- `src/discovery/auth.py` implements `login_if_needed(page)`: it restores a
  saved Playwright storage state when present, otherwise signs in using
  `LOGIN_URL`, `LOGIN_USERNAME`, and `LOGIN_PASSWORD`, then saves
  `auth_state.json`. Failures are caught and appended to `errors.log`.
- `src/discovery/interactions.py` implements `trigger_page_interactions(page)`:
  it scrolls to the bottom and clicks at most five clearly labelled safe
  expansion controls. It skips form controls and labels associated with
  destructive or consequential actions. Both hooks log actions and contain
  browser errors.

### Harness integration fixes (`fix/discovery-harness-integration`)

- **B-1 — paths anchored to repo root.** `auth.py` now derives the repo root
  from its own location and resolves state files against it:

  ```python
  ROOT = Path(__file__).resolve().parents[2]
  STATE_PATH = ROOT / "auth_state.json"
  ERRORS_PATH = ROOT / "errors.log"
  ```

  Previously these were CWD-relative, so the same code wrote session state to
  different locations depending on where it was invoked. This now matches the
  convention already used by `src/capture/logger.py` and
  `src/capture/proxy.py`.

- **B-2 — session state is never committed.** `.gitignore` already lists
  `auth_state.json` and `.env`. `auth_state.json`/`errors.log` were never
  tracked in any commit, so no `git rm --cached` or history purge is required.

- **B-3 — deterministic element selection.** `interactions.py` now tags safe
  candidates in a single `page.evaluate` pass (`data-idor-tag`) and then clicks
  them via a matching Playwright locator. This removes the previous race where
  indices from `document.querySelectorAll` were resolved against a separate
  locator that could re-render or be filtered differently. The tags are cleared
  before selection and again in a `finally` block, so no `data-idor-tag`
  attributes survive the call.

- **Test harness.** `tests/conftest.py` adds the repo root to `sys.path` so
  `pytest` behaves identically when invoked from the repo root or from `tests/`.
  This is test-only infrastructure; no module code is affected.

### Follow-ups (`fix/discovery-followups`)

- **B-4 — warn on localStorage origin mismatch.** `_restore_state` logs a
  warning when a saved origin's netloc does not match the current page origin,
  so a silent localStorage drop (e.g. login on `app.internal`, SPA on
  `www.app.internal`) becomes visible instead of failing silently.
- **B-5 — surface silent login failure.** After the submit click and load-state
  wait, `login_if_needed` inspects `[role=alert], .error, .alert-danger`. If an
  error banner is present it raises `RuntimeError("Login failed — page shows: …")`
  inside the existing `try/except`, so `_log_failure` records it in `errors.log`
  and `auth_state.json` is **not** written for an unauthenticated session.

## Files touched

| File | Change |
| --- | --- |
| `src/discovery/auth.py` | B-1: anchored state paths; B-4: origin-mismatch warning; B-5: login-failure detection |
| `src/discovery/interactions.py` | B-3: tag-then-click selection, DOM cleanup |
| `tests/test_interactions.py` | B-1/B-3/B-4/B-5 regression tests; fixed state leak in existing test |
| `tests/conftest.py` | Repo root importable regardless of CWD |
| `PERSON_B.md` | This document |

## How to test

1. Install dependencies: `python -m pip install -r requirements.txt`.
2. Install the Playwright browser once: `python -m playwright install chromium`.

### Automated checks

```bash
# From the repo root
python -m pytest tests -v

# From tests/ — must behave identically
cd tests && python -m pytest . -v
```

Both invocations run the same 8 Person B tests:

- `test_missing_credentials_is_noop`
- `test_existing_state_restores_cookies`
- `test_clicks_safe_expander_and_skips_form_controls`
- `test_state_paths_are_anchored_to_repo_root` (B-1)
- `test_clicks_lazy_show_more_exactly_once_and_cleans_tags` (B-3)
- `test_clicked_never_exceeds_max_clickables` (B-3)
- `test_restore_state_warns_when_origin_does_not_match` (B-4)
- `test_login_failure_banner_skips_state_and_logs` (B-5)

### B-1: verify state location is CWD-independent

Delete the repo-root state file, run a login from any CWD, and confirm the file
appears in exactly one place (the repo root):

```bash
rm -f auth_state.json
# with LOGIN_URL/LOGIN_USERNAME/LOGIN_PASSWORD set, trigger a login from
# either the repo root or tests/; then:
ls auth_state.json            # present at <repo>/auth_state.json
ls tests/auth_state.json      # absent
```

### B-2: verify ignore rules

```bash
git check-ignore -v auth_state.json   # matches .gitignore
git status                            # no auth_state.json listed
```

### B-3: verify deterministic clicking

The unit tests above cover a lazy "Show more" button (clicked exactly once,
tags cleaned up) and the five-click ceiling. The scrolling/skip rules are
unchanged from the base implementation.

### B-4: verify origin-mismatch warning

`test_restore_state_warns_when_origin_does_not_match` saves an origin for
`https://app.internal`, loads a page at `https://www.app.internal/`, and asserts
exactly one `Skipping localStorage restore for origin …` warning is logged with
no exception.

### B-5: verify silent login failure is surfaced

`test_login_failure_banner_skips_state_and_logs` runs `login_if_needed` against
a page containing `<div role="alert">Invalid credentials</div>` and asserts that
`errors.log` contains a `Login failed` line and that `auth_state.json` was not
written.

### Manual login smoke check

Set `LOGIN_URL`, `LOGIN_USERNAME`, and `LOGIN_PASSWORD` in the environment,
then call `await login_if_needed(page)` from an async Playwright session. The
generated `auth_state.json` contains session credentials; keep it private.

The login selectors target common username/email and password fields and common
sign-in buttons. Sites with custom authentication widgets may need selector
adjustments.
