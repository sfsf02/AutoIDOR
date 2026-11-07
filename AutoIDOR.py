"""Run the AutoIDOR candidate, replay, classification, and report pipeline."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


def origin_directory(origin: str) -> Path:
    parsed = urlparse(origin)
    hostname = (parsed.hostname or "").replace(":", "-")
    name = f"{parsed.scheme.lower()}_{hostname}"
    if parsed.port:
        name += f"_{parsed.port}"
    return ROOT / "captures" / name


def configure_origin_auth_paths(origin: str) -> tuple[Path, Path]:
    directory = origin_directory(origin)
    directory.mkdir(parents=True, exist_ok=True)
    victim = directory / "auth_state_victim.json"
    attacker = directory / "auth_state_attacker.json"
    # Child processes inherit these values, including crawler and replayer.
    import os

    os.environ["VICTIM_AUTH_STATE_PATH"] = str(victim)
    os.environ["ATTACKER_AUTH_STATE_PATH"] = str(attacker)
    return victim, attacker


def configure_auth_paths_for_capture(run_dir: Path) -> tuple[Path, Path]:
    """Use the per-origin auth states belonging to an existing capture."""
    origin_dir = run_dir.parent
    victim = origin_dir / "auth_state_victim.json"
    attacker = origin_dir / "auth_state_attacker.json"
    import os

    os.environ["VICTIM_AUTH_STATE_PATH"] = str(victim)
    os.environ["ATTACKER_AUTH_STATE_PATH"] = str(attacker)
    return victim, attacker


def latest_capture() -> Path:
    captures = ROOT / "captures"
    candidates = [
        path
        for path in captures.rglob("*")
        if path.is_dir()
        and (path / "discovered_endpoints.json").is_file()
        and (path / "api_flows.json").is_file()
    ]
    if not candidates:
        raise FileNotFoundError(
            "No capture directory containing discovered_endpoints.json "
            "and api_flows.json was found."
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)


def run_command(args: list[str]) -> None:
    result = subprocess.run(args, cwd=ROOT, check=False)
    if result.returncode:
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}: "
            f"{' '.join(args)}"
        )


def run_discovery(url: str, no_login: bool, headful: bool) -> Path:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--url must be a complete HTTP or HTTPS URL")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    victim_state, attacker_state = configure_origin_auth_paths(origin)
    started_at = max(
        (path.stat().st_mtime for path in (ROOT / "captures").rglob("*")),
        default=0,
    )

    if not no_login:
        print("\n[1/6] Creating victim authentication state...")
        run_command([
            sys.executable, "-m", "src.discovery.auth_setup",
            "--identity", "victim", "--origin", origin,
            "--output", str(victim_state),
        ])
        print("\n[2/6] Creating attacker authentication state...")
        run_command([
            sys.executable, "-m", "src.discovery.auth_setup",
            "--identity", "attacker", "--origin", origin,
            "--output", str(attacker_state),
        ])
    else:
        print("\n[1/6] Login disabled; using a clean public crawl.")

    print("\n[3/6] Crawling target URL...")
    command = [
        sys.executable, "-m", "src.discovery.crawler",
        "--url", url,
        "--scope", origin,
    ]
    if no_login:
        command.append("--no-login")
    if headful:
        command.append("--headful")
    run_command(command)

    capture_dirs = [
        path for path in (ROOT / "captures").rglob("*")
        if path.is_dir()
        and path.stat().st_mtime >= started_at
        and (path / "discovered_endpoints.json").is_file()
        and (path / "api_flows.json").is_file()
    ]
    if not capture_dirs:
        raise FileNotFoundError("Crawler completed but no capture directory was found.")
    return max(capture_dirs, key=lambda path: path.stat().st_mtime)


def select_candidates(run_dir: Path) -> None:
    script = """
from src.testing.candidate_selector import run

run_dir = r"{run_dir}"
candidates = run(
    discovered_path=run_dir + r"\\discovered_endpoints.json",
    flows_path=run_dir + r"\\api_flows.json",
    output_path=run_dir + r"\\candidates.json",
    errors_log=run_dir + r"\\errors.log",
)
print(f"Selected candidates: {{len(candidates)}}")
""".format(run_dir=str(run_dir))
    run_command([sys.executable, "-c", script])


def summarize(run_dir: Path) -> None:
    replay = json.loads((run_dir / "replay_results.json").read_text(encoding="utf-8"))
    results = json.loads((run_dir / "phase2_results.json").read_text(encoding="utf-8"))

    counts = {
        classification: sum(
            result.get("classification") == classification
            for result in results
        )
        for classification in ("POSSIBLE_IDOR", "NOT_VULNERABLE", "INCONCLUSIVE")
    }
    replay_errors = sum(bool(result.get("replay_error")) for result in replay["results"])

    print("\nAutoIDOR summary")
    print(f"Run directory: {run_dir}")
    print(f"Preflight sessions distinct: {replay['preflight'].get('sessions_distinct')}")
    print(f"Replay records: {len(replay['results'])}")
    print(f"Replay errors: {replay_errors}")
    for classification, count in counts.items():
        print(f"{classification}: {count}")
    print(f"Report: {run_dir / 'phase2_report.md'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--url",
        help="Target URL. Runs authentication setup and crawling before testing.",
    )
    source.add_argument(
        "--run-directory",
        type=Path,
        help="Existing capture directory. Defaults to the newest valid capture.",
    )
    parser.add_argument(
        "--no-login",
        action="store_true",
        help="Run a public crawl without authentication.",
    )
    parser.add_argument(
        "--headful",
        action="store_true",
        help="Show the browser during URL discovery.",
    )
    parser.add_argument(
        "--skip-candidate-selection",
        action="store_true",
        help="Reuse the existing candidates.json.",
    )
    parser.add_argument(
        "--run-tests",
        action="store_true",
        help="Run the complete pytest suite after the pipeline.",
    )
    args = parser.parse_args()

    if args.url:
        if args.no_login:
            raise RuntimeError(
                "--no-login can crawl public pages, but full replay requires "
                "distinct victim and attacker authentication states. Use a "
                "normal authenticated run for the complete pipeline."
            )
        run_dir = run_discovery(args.url, args.no_login, args.headful).resolve()
    else:
        if args.no_login:
            parser.error("--no-login requires --url")
        run_dir = (args.run_directory or latest_capture()).resolve()
        configure_auth_paths_for_capture(run_dir)
    required = (
        run_dir / "discovered_endpoints.json",
        run_dir / "api_flows.json",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("Required capture files not found: " + ", ".join(missing))

    print(f"Running AutoIDOR for: {run_dir}")
    if not args.skip_candidate_selection:
        print("\n[1/4] Selecting candidates...")
        select_candidates(run_dir)
    else:
        print("\n[1/4] Candidate selection skipped.")

    if not (run_dir / "candidates.json").is_file():
        raise FileNotFoundError(f"Candidates file not found: {run_dir / 'candidates.json'}")

    print("\n[2/4] Running authenticated replay...")
    run_command([sys.executable, "-m", "src.testing.replayer", str(run_dir)])

    print("\n[3/4] Classifying results and generating report...")
    run_command([sys.executable, "-m", "src.testing.report", str(run_dir)])

    print("\n[4/4] Summary")
    summarize(run_dir)

    if args.run_tests:
        print("\nRunning full test suite...")
        run_command([sys.executable, "-m", "pytest", "-q"])

    print("\nAutoIDOR pipeline completed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, RuntimeError) as error:
        print(f"AutoIDOR failed: {error}", file=sys.stderr)
        raise SystemExit(1)
