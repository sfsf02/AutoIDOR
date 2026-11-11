"""
Phase 2 / Stage C - report.py

Turns classifier.py's output into:
  - captures/run-*/phase2_results.json  (machine-readable, written by classifier.py)
  - captures/run-*/phase2_report.md     (human-readable, written here)

Deterministic: same input -> same report, modulo PHASE2_FIXED_TIMESTAMP.

Owned by: Olivier (Person C / Stage C). Lives under src/testing/ only.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_LONG_DIGITS_RE = re.compile(r"\d{7,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_COOKIE_RE = re.compile(r"(?i)(session|sessionid|auth_token|authorization|token|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token)=[^;\s\"']+")
_NAME_RE = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")
_URL_QUERY_SECRET_RE = re.compile(
    r"(?i)((?:session|sessionid|auth|auth_token|authorization|token|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|password|pass|email)=)([^&\s]+)"
)


def redact_url(url: str) -> str:
    if not url:
        return url
    redacted = _URL_QUERY_SECRET_RE.sub(r"\1***", url)
    return redacted


def redact_pii(text: str, cross_reference: str | None = None) -> str:
    """
    Final PII redaction pass applied before anything is written into the
    human-readable report. Separate from, and in addition to, Daniel's
    token/cookie redaction in Stage B - the attacker's body_snippet can
    still carry the owner's PII even after Stage B's pass.
    """
    if not text:
        return text

    redacted = text
    redacted = _JWT_RE.sub("***", redacted)
    redacted = _COOKIE_RE.sub(lambda m: m.group(0).split("=")[0] + "=***", redacted)
    # Redact full email (local part + domain)
    redacted = _EMAIL_RE.sub("***", redacted)
    redacted = _LONG_DIGITS_RE.sub("***", redacted)

    if cross_reference:
        for match in _NAME_RE.findall(redacted):
            if match in cross_reference:
                redacted = redacted.replace(match, "***")

    return redacted


def contains_secret(text: str) -> bool:
    """Used by the grep-style 'no secrets in output' test."""
    if not text:
        return False
    if _JWT_RE.search(text) or _COOKIE_RE.search(text):
        return True
    if _EMAIL_RE.search(text):
        return True
    if re.search(r"(?i)csrf", text):
        return True
    # Check for query params with secrets
    if _URL_QUERY_SECRET_RE.search(text):
        return True
    return False


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    fixed = os.environ.get("PHASE2_FIXED_TIMESTAMP")
    if fixed:
        return fixed
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sorted_findings(results: list[dict]) -> list[dict]:
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    findings = [r for r in results if r["classification"] == "POSSIBLE_IDOR"]

    for finding in findings:
        confidence = finding.get("confidence")
        if confidence not in confidence_order:
            raise ValueError(
                f"Invalid confidence {confidence!r} for "
                f"candidate_id={finding.get('candidate_id')}"
            )

    return sorted(
        findings,
        key=lambda r: (
            confidence_order[r["confidence"]],
            r["candidate_id"],
        ),
    )


def _sorted_by_id(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: r["candidate_id"])


def _escape_md(text: str) -> str:
    if text is None:
        return ""
    # Escape backticks and pipes to avoid breaking markdown tables
    text = str(text)
    text = text.replace("`", "\\`")
    text = text.replace("|", "\\|")
    return text


def generate_report(results: list[dict], preflight: dict) -> str:
    """Build the full phase2_report.md text from classified results."""
    primary_results = [r for r in results if r.get("test_kind") == "credential_swap"]
    possible_idor = [r for r in primary_results if r["classification"] == "POSSIBLE_IDOR"]
    not_vulnerable = _sorted_by_id([r for r in primary_results if r["classification"] == "NOT_VULNERABLE"])
    inconclusive = _sorted_by_id([r for r in primary_results if r["classification"] == "INCONCLUSIVE"])

    high = [r for r in possible_idor if r.get("confidence") == "high"]
    med = [r for r in possible_idor if r.get("confidence") == "medium"]
    low = [r for r in possible_idor if r.get("confidence") == "low"]

    findings_sorted = _sorted_findings(primary_results)

    manual_review = _sorted_by_id(
        [r for r in primary_results if r.get("rule_fired") == "body_identical_across_users"]
    )

    identifier_mutation_rows = _sorted_by_id(
        [r for r in results if r.get("test_kind") == "identifier_mutation"]
    )

    pii_redacted_any = False
    lines: list[str] = []

    lines.append(f"# Phase 2 IDOR Report — {_timestamp()}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Candidates tested: {len(primary_results)}")
    lines.append(
        f"- POSSIBLE_IDOR: {len(possible_idor)} "
        f"(high: {len(high)} / med: {len(med)} / low: {len(low)})"
    )
    lines.append(f"- NOT_VULNERABLE: {len(not_vulnerable)}")
    lines.append(f"- INCONCLUSIVE: {len(inconclusive)}")
    sessions_distinct = preflight.get("sessions_distinct", False) if isinstance(preflight, dict) else False
    lines.append(f"- Preflight sessions distinct: {'yes' if sessions_distinct else 'no'}")
    lines.append("")

    lines.append("## Findings (POSSIBLE_IDOR)")
    lines.append("")
    lines.append(
        "| candidate_id | method | URL | owner status | attacker status | "
        "size delta | classification | confidence | notes |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in findings_sorted:
        ev = r["evidence"]
        req = ev.get("request") or {}
        url_raw = req.get("url", "") or ""
        url_redacted = redact_url(url_raw)
        url = _escape_md(url_redacted)
        method = _escape_md(req.get("method", ""))
        a_status = ev.get("session_a_status")
        b_status = ev.get("session_b_status")
        size_delta = (ev.get("delta") or {}).get("size_delta_bytes")
        candidate_id = _escape_md(r['candidate_id'])
        classification = _escape_md(r['classification'])
        confidence = _escape_md(r.get('confidence', ''))
        rule_fired = _escape_md(r['rule_fired'])
        lines.append(
            f"| {candidate_id} | {method} | {url} | {a_status} | {b_status} | "
            f"{size_delta} | {classification} | {confidence} | "
            f"{rule_fired} |"
        )
    lines.append("")

    if identifier_mutation_rows:
        lines.append("## Corroborating evidence (identifier_mutation records)")
        lines.append("")
        lines.append("| candidate_id | rule_fired | classification | mutated URL | owner status | mutated status | response size (mutated) | content type | redirect | body comparison |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for r in identifier_mutation_rows:
            ev = r["evidence"]
            req = ev.get("request") or {}
            url_raw = req.get("url", "") or ""
            url_redacted = redact_url(url_raw)
            url = _escape_md(url_redacted)
            a_status = ev.get("session_a_status")
            b_status = ev.get("session_b_status")
            delta = ev.get("delta") or {}
            size_delta = delta.get("size_delta_bytes")
            b_ct = ev.get("session_b_content_type") or ev.get("session_a_content_type")
            redirected = delta.get("redirected_to_login", False)
            body_identical = delta.get("body_identical", False)
            body_comp = "identical" if body_identical else "different"
            lines.append(
                f"| {_escape_md(r['candidate_id'])} | {_escape_md(r['rule_fired'])} | {_escape_md(r['classification'])} | "
                f"{url} | {a_status} | {b_status} | {size_delta} | {_escape_md(b_ct or '')} | {redirected} | {body_comp} |"
            )
        lines.append("")

    lines.append("## Inconclusive")
    lines.append("")
    lines.append("| candidate_id | reason | replay_error |")
    lines.append("|---|---|---|")
    for r in inconclusive:
        err = r["evidence"].get("replay_error")
        err_str = "" if err is None else _escape_md(str(err))
        lines.append(f"| {_escape_md(r['candidate_id'])} | {_escape_md(r['rule_fired'])} | {err_str} |")
    lines.append("")

    lines.append("## Not vulnerable")
    lines.append("")
    lines.append("| candidate_id | rule_fired |")
    lines.append("|---|---|")
    for r in not_vulnerable:
        lines.append(f"| {_escape_md(r['candidate_id'])} | {_escape_md(r['rule_fired'])} |")
    lines.append("")

    if manual_review:
        lines.append("## Manual review (identical body across users)")
        lines.append("")
        lines.append(
            "These returned the same bytes to both sessions. That can mean public "
            "content, a constant error page, or a real shared-object leak - a human "
            "needs to look at the snippets before ruling this out."
        )
        lines.append("")
        lines.append("| candidate_id | URL |")
        lines.append("|---|---|")
        for r in manual_review:
            url_raw = (r["evidence"].get("request") or {}).get("url", "") or ""
            url = _escape_md(redact_url(url_raw))
            lines.append(f"| {_escape_md(r['candidate_id'])} | {url} |")
        lines.append("")

    lines.append("## Evidence appendix (per POSSIBLE_IDOR finding)")
    lines.append("")
    for r in findings_sorted:
        ev = r["evidence"]
        a_snip_raw = ev.get("session_a_body_snippet") or ""
        b_snip_raw = ev.get("session_b_body_snippet") or ""

        a_snip = redact_pii(a_snip_raw)
        b_snip = redact_pii(b_snip_raw, cross_reference=a_snip_raw)

        if a_snip != a_snip_raw or b_snip != b_snip_raw:
            pii_redacted_any = True
        if contains_secret(a_snip_raw) or contains_secret(b_snip_raw):
            pii_redacted_any = True

        lines.append(f"<details><summary>{_escape_md(r['candidate_id'])} ({_escape_md(str(r.get('confidence')) if r.get('confidence') is not None else '')})</summary>")
        lines.append("")
        lines.append(f"- Rule fired: `{_escape_md(r['rule_fired'])}`")
        lines.append(f"- Owner (session_a) snippet: `{_escape_md(a_snip)}`")
        lines.append(f"- Attacker (session_b) snippet: `{_escape_md(b_snip)}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    report_text = "\n".join(lines) + "\n"
    # Final enforcement: redact again if anything slipped through
    report_text = redact_pii(report_text)
    # Also redact URLs in the final text
    report_text = _URL_QUERY_SECRET_RE.sub(r"\1***", report_text)

    if pii_redacted_any:
        # Insert warning near top if not present
        if "PII" not in report_text[:200]:
            report_text = report_text.replace(
                "# Phase 2 IDOR Report",
                "# Phase 2 IDOR Report\n\nWARNING: Some evidence was redacted to remove PII. Review replay_results.json locally before sharing this report.",
                1,
            )

    return report_text


def write_report_atomic(report_text: str, out_path: str) -> None:
    import tempfile

    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(report_text)
        os.replace(tmp_path, out_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


# ---------------------------------------------------------------------------
# Entry points
#
# run_stage_c() is the integration point: it takes ONE run directory (the
# same captures/run-<timestamp>/ folder Mustafa's candidates.json and
# Daniel's replay_results.json already live in) and writes this stage's two
# output files into that same folder. This is what a future orchestration
# harness (run_phase2.py) should import and call directly - no path
# guessing needed, since Stage C's input and output share Stage A/B's
# existing run-folder convention.
# ---------------------------------------------------------------------------

def run_stage_c(run_dir: str) -> tuple[str, str]:
    """
    Read <run_dir>/replay_results.json, write <run_dir>/phase2_results.json
    and <run_dir>/phase2_report.md. Returns (results_path, report_path).

    Raises FileNotFoundError with a clear message if replay_results.json
    isn't in run_dir yet (e.g. Stage B hasn't run or hasn't merged).
    """
    from src.testing.classifier import (
        classify_all,
        load_replay_results,
        write_results_atomic,
    )

    replay_results_path = os.path.join(run_dir, "replay_results.json")
    if not os.path.isfile(replay_results_path):
        raise FileNotFoundError(
            f"{replay_results_path} not found. Stage C needs Daniel's "
            "replay_results.json in this run directory before it can classify "
            "anything - run Stage B first, or point at a run directory that "
            "already has it."
        )

    replay_results = load_replay_results(replay_results_path)
    results = classify_all(replay_results)

    results_path = os.path.join(run_dir, "phase2_results.json")
    write_results_atomic(results, results_path)

    report_text = generate_report(results, replay_results.get("preflight", {}))
    report_path = os.path.join(run_dir, "phase2_report.md")
    write_report_atomic(report_text, report_path)

    return results_path, report_path


def main(replay_results_path: str, out_dir: str) -> None:
    """Lower-level entry point: explicit input file + explicit output dir.
    Useful for ad-hoc runs (e.g. against a fixture) that don't follow the
    captures/run-*/ convention. Prefer run_stage_c() for real pipeline runs."""
    from src.testing.classifier import (
        classify_all,
        load_replay_results,
        write_results_atomic,
    )

    replay_results = load_replay_results(replay_results_path)
    results = classify_all(replay_results)

    results_path = os.path.join(out_dir, "phase2_results.json")
    write_results_atomic(results, results_path)

    report_text = generate_report(results, replay_results.get("preflight", {}))
    report_path = os.path.join(out_dir, "phase2_report.md")
    write_report_atomic(report_text, report_path)

    print(f"Wrote {results_path}")
    print(f"Wrote {report_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        # Single arg -> treat it as a captures/run-*/ directory.
        results_path, report_path = run_stage_c(sys.argv[1])
        print(f"Wrote {results_path}")
        print(f"Wrote {report_path}")
    elif len(sys.argv) == 3:
        # Two args -> explicit input file + explicit output dir (fixtures, ad-hoc runs).
        main(sys.argv[1], sys.argv[2])
    else:
        print(
            "usage:\n"
            "  python -m src.testing.report <captures/run-*/ dir>\n"
            "  python -m src.testing.report <replay_results.json> <out_dir>"
        )
        sys.exit(1)
