# AutoIDOR

AutoIDOR is an authorized security-testing tool for discovering and
evaluating potential Insecure Direct Object Reference (IDOR) and broken object
level authorization issues.

The project uses a staged workflow:

1. **Discovery** — crawl a target and capture discovered URLs and network
   activity.
2. **Candidate selection** — identify safe, identifier-bearing `GET` and
   `HEAD` requests.
3. **Credential-swap replay** — replay the same request with a victim account
   and a distinct attacker account.
4. **Classification** — classify each comparison as `POSSIBLE_IDOR`,
   `NOT_VULNERABLE`, or `INCONCLUSIVE`.
5. **Reporting** — generate machine-readable results and a Markdown report.

> **Authorization:** Use AutoIDOR only against applications and accounts you
> own or are explicitly authorized to test. The replay stage is intentionally
> restricted to read-only methods and includes scope and destructive-path
> safeguards.

## Requirements

- Python 3.11 or newer.
- Two distinct test accounts for authenticated IDOR testing:
  - a victim/owner account;
  - an attacker/second account.
- Playwright browser binaries.
- An in-scope target URL.

## Installation

From the repository root, create and activate a virtual environment using the
standard method for your shell:

```text
python -m venv .venv
python -m pip install -r requirements.txt
python -m playwright install chromium
```

If you activate the virtual environment, use the `python` command shown
below. Otherwise, invoke the Python executable from the environment directly.

## Configuration

Copy `.env.example` to `.env` using your operating system's file-copy
command or file manager:

```text
.env.example -> .env
```

Edit `.env` and set the target and account values:

```env
SCOPE_DOMAIN=http://example.test
LOGIN_URL=/login

VICTIM_USERNAME=alice
VICTIM_PASSWORD=<victim-password>

ATTACKER_USERNAME=bob
ATTACKER_PASSWORD=<attacker-password>

IDENTITY_URLS=/me,/api/me,/user,/api/user,/profile
```

### Important configuration values

| Variable | Purpose |
|---|---|
| `SCOPE_DOMAIN` | Required scope boundary for crawling, selection, and replay. |
| `LOGIN_URL` | Login page used to create browser authentication states. |
| `VICTIM_USERNAME` / `VICTIM_PASSWORD` | Account that owns the original object. |
| `ATTACKER_USERNAME` / `ATTACKER_PASSWORD` | Separate account used for the credential swap. |
| `IDENTITY_URLS` | Comma-separated endpoints used to prove the accounts are distinct. |
| `MAX_PAGES` | Maximum number of pages visited by the crawler. |
| `MAX_DEPTH` | Maximum BFS link depth. |
| `DELAY_SECONDS` | Delay between crawler page visits. |
| `NO_LOGIN` | Makes the crawler skip login for public discovery. |
| `CAPTURE_BODIES` | Enables body capture; keep `false` unless needed and authorized. |
| `MAX_BODY_BYTES` | Maximum captured body size. |
| `API_PREFIXES` | Comma-separated path prefixes treated as API-like traffic. |
| `START_PROXY` | Starts the managed capture proxy when enabled. |
| `PROXY_PORT` / `MANAGED_PROXY_PORT` | Standalone and managed proxy ports. |

`AutoIDOR.py` derives authentication-state paths per target. Do not normally
set `VICTIM_AUTH_STATE_PATH` or `ATTACKER_AUTH_STATE_PATH` manually.

The older `LOGIN_USERNAME`, `LOGIN_PASSWORD`, `AUTH_STATE_PATH`,
`ATTACKER_STATE_PATH`, and `PREFLIGHT_URL` variables are retained only for
backward compatibility. New configurations should use the identity-specific
settings above.

Never commit `.env`, credentials, cookies, or browser state files.

## Recommended directory layout

```text
AutoIDOR/
├── AutoIDOR.py                 # End-to-end command-line runner
├── .env.example                # Documented safe configuration template
├── .env                        # Local configuration; never commit
├── requirements.txt            # Python dependencies
├── src/
│   ├── capture/
│   ├── discovery/
│   └── testing/
└── captures/
    └── http_example.test/
        ├── auth_state_victim.json
        ├── auth_state_victim.metadata.json
        ├── auth_state_attacker.json
        ├── auth_state_attacker.metadata.json
        └── <run-id>/
            ├── discovered_endpoints.json
            ├── network.json
            ├── api_flows.json
            ├── candidates.json
            ├── replay_results.json
            ├── phase2_results.json
            └── phase2_report.md
```

## What each folder does

### `src/discovery/`

Browser-based discovery and authentication:

- `crawler.py` — breadth-first crawl, page interaction, endpoint discovery,
  network capture, and optional login.
- `auth.py` — victim/attacker credentials, browser state creation, state
  restoration, and metadata.
- `auth_setup.py` — standalone command for creating one identity's state.
- `interactions.py` — generic overlay, consent, and page interaction helpers.

### `src/capture/`

Network capture support:

- `proxy.py` — managed proxy lifecycle and capture directory handling.
- `logger.py` — filters and writes API-flow records, with body-size and
  redaction controls.

### `src/testing/`

IDOR testing and analysis:

- `candidate_selector.py` — selects safe identifier-bearing URLs and uses
  captured API flows or safe network fallbacks.
- `replayer.py` — performs victim/attacker read-only replay and identifier
  mutation checks.
- `classifier.py` — converts replay evidence into classifications and
  confidence levels.
- `report.py` — writes `phase2_results.json` and `phase2_report.md`.

### `captures/`

Per-target authentication states and timestamped discovery/test outputs.
Authentication states contain sensitive session data and must not be shared.

## Main command: URL to report

This is the recommended command. It creates both authentication states,
crawls the URL, selects candidates, replays them, classifies the results, and
writes the report:

```text
python AutoIDOR.py --url "http://example.test/"
```

The target-specific state files are created under a directory similar to:

```text
captures/http_example.test/
```

The new timestamped run directory contains the discovery and testing output.

### Run URL mode with visible browser

```text
python AutoIDOR.py --url "http://example.test/" --headful
```

URL mode requires two distinct authenticated accounts. `--no-login` is not
accepted in the full `AutoIDOR.py` pipeline because an unauthenticated crawl
cannot perform a meaningful victim-versus-attacker credential swap.

## Run a public crawl only

For public endpoint discovery without login, run the crawler directly:

```text
python -m src.discovery.crawler --url "http://example.test/" --scope "http://example.test" --no-login
```

This produces discovery files, but it does not provide the two authenticated
states required for credential-swap IDOR testing.

## Run the pipeline from an existing capture

If discovery has already completed:

```text
python AutoIDOR.py --run-directory "captures/http_example.test/<run-id>"
```

The runner will regenerate candidates, run replay, classify the results, and
write the report.

### Reuse existing candidates

```text
python AutoIDOR.py --run-directory "captures/http_example.test/<run-id>" --skip-candidate-selection
```

Use this only when `candidates.json` is already known to be current.

## Create authentication states manually

The normal URL workflow does this automatically. To create states manually:

```text
python -m src.discovery.auth_setup --identity victim --origin "http://example.test"
python -m src.discovery.auth_setup --identity attacker --origin "http://example.test"
```

To override an output path explicitly:

```text
python -m src.discovery.auth_setup --identity victim --origin "http://example.test" --output "captures/http_example.test/auth_state_victim.json"
```

## Run individual stages

### Candidate selection

Candidate selection is normally run automatically by `AutoIDOR.py`. To run
the individual stage, invoke `src.testing.candidate_selector.run()` from a
Python session with the paths for your capture directory:

```python
from src.testing.candidate_selector import run

run_dir = "captures/http_example.test/<run-id>"
run(
    run_dir + "/discovered_endpoints.json",
    run_dir + "/api_flows.json",
    run_dir + "/candidates.json",
    errors_log=run_dir + "/errors.log",
)
```

### Replay

```text
python -m src.testing.replayer "captures/http_example.test/<run-id>"
```

### Classification and report

```text
python -m src.testing.report "captures/http_example.test/<run-id>"
```

## Outputs

| File | Description |
|---|---|
| `discovered_endpoints.json` | URLs and endpoints discovered during crawling. |
| `network.json` | Browser network events used for discovery and fallback candidates. |
| `api_flows.json` | Complete captured request/response flows where available. |
| `candidates.json` | Safe Stage A candidates selected for replay. |
| `replay_results.json` | Stage B victim/attacker responses and deltas. |
| `phase2_results.json` | Stage C classifications and evidence. |
| `phase2_report.md` | Human-readable Markdown report. |
| `errors.log` | Non-secret crawl, capture, or selection errors. |

## Interpreting results

### `POSSIBLE_IDOR`

The attacker received a successful, non-identical response for a credential
swap. This is a lead requiring review, not automatic proof of a vulnerability.

### `NOT_VULNERABLE`

The attacker was denied, normally with HTTP `401` or `403`.

### `INCONCLUSIVE`

The evidence was insufficient or unsafe to classify, for example baseline
drift, unsupported content, login redirects, identical bodies, or very small
responses.

Confidence is intentionally conservative. High and medium confidence require
stronger response evidence than a small response-size difference.

## Safety and privacy

- Test only explicitly authorized targets.
- The replayer allows only `GET` and `HEAD`.
- Scope checks fail closed when `SCOPE_DOMAIN` is missing.
- Destructive paths are blocked.
- Authentication headers and cookies are not copied between identities.
- Do not enable body capture unless it is necessary and authorized.
- Do not commit `.env`, browser state, tokens, or generated sensitive output.

## Troubleshooting

### `SCOPE_DOMAIN environment variable is required`

Create `.env` from `.env.example`, set `SCOPE_DOMAIN`, and run from the
repository root:

```text
cp .env.example .env
```

### `MissingAuthStateError`

Regenerate both identity states:

```text
python -m src.discovery.auth_setup --identity victim --origin "http://example.test"
python -m src.discovery.auth_setup --identity attacker --origin "http://example.test"
```

### `PreflightAuthenticationError`

The replayer could not prove that the two states represent different
accounts. Check the credentials and configure `IDENTITY_URL` or
`IDENTITY_URLS` with an endpoint that returns the current authenticated user.

### Browser launch or Playwright errors

Install the browser binaries:

```text
python -m playwright install chromium
```

### No candidates selected

Check `discovered_endpoints.json`, `network.json`, and `errors.log`. Candidate
selection intentionally excludes out-of-scope URLs, destructive paths,
unsupported methods, and URLs without supported object identifiers.
