import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.testing import classifier
from src.testing import report

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def test_attacker_got_owner_object_is_possible_idor():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "session_b": {"status": 200, "content_type": "application/json", "response_size": 1100},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": True, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 100,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "POSSIBLE_IDOR"
    assert result["rule_fired"] == "attacker_got_owner_object"


def test_attacker_denied_is_not_vulnerable():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "session_b": {"status": 403, "content_type": "application/json", "response_size": 100},
        "delta": {
            "status_changed": True, "body_identical": False,
            "session_b_got_owner_object": False, "session_b_denied": True,
            "redirected_to_login": False, "size_delta_bytes": -900,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "NOT_VULNERABLE"
    assert result["rule_fired"] == "attacker_denied"


def test_body_identical_is_not_vulnerable_but_flagged_for_review():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "text/html", "response_size": 800},
        "session_b": {"status": 200, "content_type": "text/html", "response_size": 800},
        "delta": {
            "status_changed": False, "body_identical": True,
            "session_b_got_owner_object": False, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 0,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "NOT_VULNERABLE"
    assert result["rule_fired"] == "body_identical_across_users"


def test_redirect_to_login_is_inconclusive():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 302, "content_type": "text/html", "response_size": 100},
        "session_b": {"status": 302, "content_type": "text/html", "response_size": 100},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": False, "session_b_denied": False,
            "redirected_to_login": True, "size_delta_bytes": 0,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "INCONCLUSIVE"
    assert result["rule_fired"] == "redirect_to_login"


def test_baseline_drift_is_not_vulnerable():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "session_b": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": False, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 0,
        },
        "flags": [], "replay_error": "baseline_drift", "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "NOT_VULNERABLE"
    assert result["rule_fired"] == "baseline_drift"


def test_replay_error_is_inconclusive():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "session_b": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": False, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 0,
        },
        "flags": [], "replay_error": "unexpected_exception", "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "INCONCLUSIVE"


def test_small_response_is_inconclusive():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/json", "response_size": 10},
        "session_b": {"status": 200, "content_type": "application/json", "response_size": 10},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": False, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 0,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "INCONCLUSIVE"
    assert result["rule_fired"] == "small_response"


def test_owner_403_is_inconclusive():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 403, "content_type": "application/json", "response_size": 100},
        "session_b": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "delta": {
            "status_changed": True, "body_identical": False,
            "session_b_got_owner_object": True, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 900,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "INCONCLUSIVE"
    assert result["rule_fired"] == "owner_unreachable"


def test_binary_content_is_inconclusive():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/pdf", "response_size": 1000},
        "session_b": {"status": 200, "content_type": "application/pdf", "response_size": 1000},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": True, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 0,
        },
        "flags": [], "replay_error": None, "test_kind": "credential_swap",
    }
    result = classifier.classify_record(record)
    assert result["classification"] == "INCONCLUSIVE"
    assert result["rule_fired"] == "unexpected_content_type"


def test_identifier_mutation_alone_cannot_produce_possible_idor():
    record = {
        "candidate_id": "x",
        "session_a": {"status": 200, "content_type": "application/json", "response_size": 1000},
        "session_b": {"status": 200, "content_type": "application/json", "response_size": 1200},
        "delta": {
            "status_changed": False, "body_identical": False,
            "session_b_got_owner_object": True, "session_b_denied": False,
            "redirected_to_login": False, "size_delta_bytes": 200,
        },
        "flags": [], "replay_error": None, "test_kind": "identifier_mutation",
    }
    result = classifier.classify_record(record)
    assert result["classification"] != "POSSIBLE_IDOR"


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

def test_confidence_high_for_json_size_delta():
    a = {"status": 200, "content_type": "application/json", "body_snippet": "a"}
    b = {"status": 200, "content_type": "application/json", "body_snippet": "b"}
    delta = {"size_delta_bytes": 200}
    assert classifier.assign_confidence(a, b, delta) == "high"


def test_confidence_medium_for_html_size_delta():
    a = {"status": 200, "content_type": "text/html", "body_snippet": "a"}
    b = {"status": 200, "content_type": "text/html", "body_snippet": "b"}
    delta = {"size_delta_bytes": 20}
    assert classifier.assign_confidence(a, b, delta) == "medium"


def test_confidence_low_for_tiny_delta():
    a = {"status": 200, "content_type": "text/html", "body_snippet": "a"}
    b = {"status": 200, "content_type": "text/html", "body_snippet": "b"}
    delta = {"size_delta_bytes": 1}
    assert classifier.assign_confidence(a, b, delta) == "low"


def test_confidence_low_when_snippets_equal():
    a = {"status": 200, "content_type": "application/json", "body_snippet": "same"}
    b = {"status": 200, "content_type": "application/json", "body_snippet": "same"}
    delta = {"size_delta_bytes": 500}
    assert classifier.assign_confidence(a, b, delta) == "low"


# ---------------------------------------------------------------------------
# Preflight / abort
# ---------------------------------------------------------------------------

def test_aborts_if_sessions_not_distinct():
    data = load_fixture("replay_results_same_account.json")
    with pytest.raises(classifier.AbortPhase2):
        classifier.classify_all(data)


def test_aborts_if_preflight_block_missing():
    with pytest.raises(classifier.AbortPhase2):
        classifier.classify_all({"results": []})


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def test_redacts_jwt():
    text = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert "eyJ" not in report.redact_pii(text)


def test_redacts_cookie():
    text = "Set-Cookie: session=abc123xyz; Path=/"
    redacted = report.redact_pii(text)
    assert "abc123xyz" not in redacted


def test_redacts_email_in_snippet():
    text = '{"email": "alice@example.com"}'
    redacted = report.redact_pii(text)
    assert "alice@example.com" not in redacted


def test_redacts_long_digit_strings():
    text = '{"phone": "5551234567"}'
    redacted = report.redact_pii(text)
    assert "5551234567" not in redacted


def test_report_contains_no_secret_strings():
    data = load_fixture("replay_results_pii.json")
    results = classifier.classify_all(data)
    text = report.generate_report(results, data["preflight"])
    assert "alice@example.com" not in text
    assert "5551234567" not in text


# ---------------------------------------------------------------------------
# Determinism / structure
# ---------------------------------------------------------------------------

def test_report_is_deterministic_with_fixed_timestamp(monkeypatch):
    monkeypatch.setenv("PHASE2_FIXED_TIMESTAMP", "2026-01-01T00:00:00Z")
    data = load_fixture("replay_results_clean.json")
    results = classifier.classify_all(data)
    text1 = report.generate_report(results, data["preflight"])
    text2 = report.generate_report(results, data["preflight"])
    assert text1 == text2
    assert "2026-01-01T00:00:00Z" in text1


def test_summary_counts_match_results():
    data = load_fixture("replay_results_clean.json")
    results = classifier.classify_all(data)
    possible = sum(1 for r in results if r["classification"] == "POSSIBLE_IDOR")
    not_vuln = sum(1 for r in results if r["classification"] == "NOT_VULNERABLE")
    inconclusive = sum(1 for r in results if r["classification"] == "INCONCLUSIVE")
    assert possible == 2
    assert not_vuln == 2
    assert inconclusive == 1


def test_findings_sorted_by_confidence_then_id():
    data = load_fixture("replay_results_clean.json")
    results = classifier.classify_all(data)
    findings = report._sorted_findings(results)
    confidences = [f["confidence"] for f in findings]
    order = {"high": 0, "medium": 1, "low": 2}
    assert confidences == sorted(confidences, key=lambda c: order[c])


def test_results_json_is_valid_against_jsonschema():
    import jsonschema

    data = load_fixture("replay_results_clean.json")
    results = classifier.classify_all(data)
    with open(os.path.join(FIXTURES, "phase2_results_schema.json"), encoding="utf-8") as f:
        schema = json.load(f)
    jsonschema.validate(instance=results, schema=schema)


# ---------------------------------------------------------------------------
# End-to-end via clean fixture
# ---------------------------------------------------------------------------

def test_end_to_end_clean_fixture_matches_acceptance_criteria():
    data = load_fixture("replay_results_clean.json")
    results = classifier.classify_all(data)
    assert len(results) == 5
    classifications = [r["classification"] for r in results]
    assert classifications.count("POSSIBLE_IDOR") == 2
    assert classifications.count("NOT_VULNERABLE") == 2
    assert classifications.count("INCONCLUSIVE") == 1


# ---------------------------------------------------------------------------
# Integration: matches Daniel's captures/run-*/ convention, and fails loudly
# on schema drift rather than crashing obscurely.
# ---------------------------------------------------------------------------

def test_run_stage_c_reads_and_writes_same_run_directory(tmp_path):
    import shutil

    run_dir = tmp_path / "run-20261022"
    run_dir.mkdir()
    shutil.copy(
        os.path.join(FIXTURES, "replay_results_clean.json"),
        run_dir / "replay_results.json",
    )

    results_path, report_path = report.run_stage_c(str(run_dir))

    assert os.path.basename(results_path) == "phase2_results.json"
    assert os.path.basename(report_path) == "phase2_report.md"
    assert os.path.isfile(results_path)
    assert os.path.isfile(report_path)
    with open(results_path, encoding="utf-8") as f:
        results = json.load(f)
    assert len(results) == 5


def test_run_stage_c_missing_replay_results_raises_clear_error(tmp_path):
    run_dir = tmp_path / "run-empty"
    run_dir.mkdir()
    with pytest.raises(FileNotFoundError, match="replay_results.json"):
        report.run_stage_c(str(run_dir))


def test_classify_record_missing_candidate_id_raises_named_error():
    record = {
        "session_a": {"status": 200}, "session_b": {"status": 200}, "delta": {},
    }
    with pytest.raises(classifier.StageCInputError, match="candidate_id"):
        classifier.classify_record(record)


def test_classify_record_missing_session_raises_named_error():
    record = {"candidate_id": "abc-123", "session_b": {}, "delta": {}}
    with pytest.raises(classifier.StageCInputError, match="abc-123"):
        classifier.classify_record(record)
