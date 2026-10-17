# Testing Person B (authentication + interactions)

Clean-run guide for the Person B changes so the Phase 1 harness can be signed
off without surprises.

- **PR #2** (`fix/discovery-harness-integration` → `feature/B-interactions`):
  B-1, B-2, B-3 — adds 3 tests (6 Person B tests on this branch).
- **PR #3** (`fix/discovery-followups` → `fix/discovery-harness-integration`):
  B-4, B-5 — adds 2 tests (8 Person B tests on this branch).

Owner of these files: Person B (`src/discovery/auth.py`,
`src/discovery/interactions.py`, `tests/test_interactions.py`). The two public
signatures are frozen and must not change:

```python
async def login_if_needed(page: Page) -> None
async def trigger_page_interactions(page: Page) -> None
```

## 1. Prerequisites

- Python 3.11+ (verified on 3.11.9).
- Install dependencies:

  ```bash
  python -m pip install -r requirements.txt
  ```

- Install the Playwright browser once (the tests launch headless Chromium):

  ```bash
  python -m playwright install chromium
  ```

- Optional, only for the Person C integration check: `mitmproxy` (already in
  `requirements.txt`).

> The repo has **no CI**. GitHub will not run these tests automatically; they
> must be run locally. The results below are the acceptance evidence.

## 2. Automated test suite

Run the suite from both locations — behaving identically from either CWD is
part of the B-1 fix.

From the repository root:

```bash
python -m pytest tests -v
```

From `tests/`:

```bash
cd tests
python -m pytest . -v
```

Expected results depend on which branch you are on:

| Branch | Person B tests |
| --- | --- |
| `fix/discovery-harness-integration` (PR #2) | **6 passed** |
| `fix/discovery-followups` (PR #3, stacked on #2) | **8 passed** |
| `feature/B-interactions` after merging #2 and #3 | **8 passed** |

The 8 Person B tests and what they prove:

| Test | PR | Proves |
| --- | --- | --- |
| `test_missing_credentials_is_noop` | #2 | No credentials configured → no-op, no crash |
| `test_existing_state_restores_cookies` | #2 | Saved state restores cookies |
| `test_clicks_safe_expander_and_skips_form_controls` | #2 | Only safe expanders clicked; form controls skipped |
| `test_state_paths_are_anchored_to_repo_root` | #2 | **B-1** paths are absolute and rooted at the repo |
| `test_clicks_lazy_show_more_exactly_once_and_cleans_tags` | #2 | **B-3** lazy "Show more" clicked once; no `data-idor-tag` left |
| `test_clicked_never_exceeds_max_clickables` | #2 | **B-3** click count capped at `MAX_CLICKABLES` (5) |
| `test_restore_state_warns_when_origin_does_not_match` | #3 | **B-4** one warning on origin mismatch, no exception |
| `test_login_failure_banner_skips_state_and_logs` | #3 | **B-5** failure logged, `auth_state.json` not written |

> If pytest is invoked from `tests/` and reports `ModuleNotFoundError: No module
> named 'src'`, the import harness (`tests/conftest.py`) is missing or was not
> checked out. That file is part of PR #2.

## 3. Per-fix acceptance checks

### B-1 — State paths anchored to the repo root

**Automated:** `test_state_paths_are_anchored_to_repo_root`.

**Manual / end-to-end:**

1. Make sure credentials are available (`LOGIN_URL`, `LOGIN_USERNAME`,
   `LOGIN_PASSWORD`) and delete any existing state:

   ```bash
   rm -f auth_state.json
   ```

2. Trigger a login from the **repo root**, then repeat from **`tests/`**.

3. Confirm the file appears in exactly one place — the repo root:

   ```bash
   ls auth_state.json          # present
   ls tests/auth_state.json    # absent
   ```

Pass criteria: both invocations write `<repo>/auth_state.json`; nothing lands
in `tests/`.

### B-2 — Session credentials are never committed

```bash
git check-ignore -v auth_state.json   # must print a .gitignore match
git status                            # auth_state.json must NOT be listed
```

Also verified: `auth_state.json` and `errors.log` were **never committed** in
any commit on any branch, so there is no old blob to purge with
`git filter-repo`. `git log --all -- auth_state.json` returns nothing.

### B-3 — Deterministic element selection

**Automated:** the two `data-idor-tag` tests above (PR #2).

**Manual check on a real page:** after `trigger_page_interactions(page)`
returns, assert no tags survive:

```python
leftover = await page.evaluate(
    "() => document.querySelectorAll('[data-idor-tag]').length")
assert leftover == 0
```

Pass criteria: a lazy "Show more" is clicked exactly once per visit;
`clicked <= MAX_CLICKABLES`; no `data-idor-tag` attributes remain.

### B-4 — Warn when localStorage origin does not match (PR #3)

**Automated:** `test_restore_state_warns_when_origin_does_not_match`.

**Manual:** save state with an origin of `https://app.internal`, load a page at
`https://www.app.internal/`, and confirm exactly one log line:

```
Skipping localStorage restore for origin app.internal (page origin is www.app.internal)
```

Pass criteria: one warning, no exception.

### B-5 — Surface silent login failure (PR #3)

**Automated:** `test_login_failure_banner_skips_state_and_logs`.

**Manual:** point `LOGIN_URL` at your own test app and log in with wrong
credentials. Then confirm:

- `errors.log` contains a line beginning `Authentication setup failed: Login
  failed — page shows: …`
- `auth_state.json` was **not** created (or was not overwritten).

Pass criteria: failure is visible in `errors.log`; no logged-out session is
saved.

## 4. Integration with the other contributors

The three modules are independent, but run this once before hand-off so the
branches are known to compose cleanly.

```bash
git fetch --all
git checkout -b tmp/integration-check fix/discovery-followups
git merge --no-edit origin/feature/C-capture
python -m pytest tests -v        # expected: 15 passed (8 Person B + 7 Person C)
git checkout fix/discovery-harness-integration
git branch -D tmp/integration-check
```

Expected: clean merge, no conflicts, **15 passed**.

If you run the same trial from `fix/discovery-harness-integration` (PR #2 only),
the expected total is **13 passed** (6 Person B + 7 Person C).

- Person C (`src/capture/logger.py`, `src/capture/proxy.py`) uses the same
  `ROOT = Path(__file__).resolve().parents[2]` convention as B-1, so the state
  and capture files all resolve to the repo root.
- Person A (`src/discovery/crawler.py`) is not committed yet. When it lands,
  the end-to-end check is: run the crawler with mitmproxy active and confirm
  it (a) logs in, (b) triggers interactions on each page, and (c) produces
  `urls.txt`, `pages.json`, and `captures/api_flows.json`.

## 5. Branch / PR layout and merge order

| PR | Head branch | Base branch | Contents |
| --- | --- | --- | --- |
| #2 | `fix/discovery-harness-integration` | `feature/B-interactions` | B-1, B-2, B-3 + this guide |
| #3 | `fix/discovery-followups` | `fix/discovery-harness-integration` | B-4, B-5 |

- **Merge order:** merge **#2 first**, then **#3** (PR #3 is stacked on #2's
  branch). If #2's branch is deleted on merge, retarget #3 before merging it.
- **Target note:** PR #2 merges into `feature/B-interactions`, not `main`. To
  get these fixes into `main`, a follow-up `feature/B-interactions → main` PR is
  still required. Confirm with the repo owner which branch is the integration
  point.
- Only Person B-owned files and test harness/docs are touched:
  `src/discovery/auth.py`, `src/discovery/interactions.py`,
  `tests/test_interactions.py`, `tests/conftest.py`, `PERSON_B.md`, and this
  file.

## 6. Sign-off checklist

- [ ] `python -m pytest tests -v` → 6 passed on PR #2, 8 passed on PR #3
- [ ] `cd tests; python -m pytest . -v` → same counts
- [ ] Login from repo root and `tests/` writes `auth_state.json` to the repo
      root only (B-1)
- [ ] `git check-ignore -v auth_state.json` matches; not tracked/history-clean
      (B-2)
- [ ] Lazy "Show more" clicked once; no `data-idor-tag` left (B-3)
- [ ] Origin mismatch logs one warning (B-4)
- [ ] Bad login logs `Login failed`; no `auth_state.json` written (B-5)
- [ ] Integration merge with `feature/C-capture` → 15 passed

## 7. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `ModuleNotFoundError: No module named 'src'` | Run from repo root, or ensure `tests/conftest.py` is present, or use `python -m pytest` |
| Playwright "Executable doesn't exist" | `python -m playwright install chromium` |
| `LF will be replaced by CRLF` warnings | Harmless on Windows; line endings only |
| `auth_state.json` shows as untracked | It should not — confirm `.gitignore` line `auth_state.json` (B-2) |
