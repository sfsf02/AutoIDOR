"""
Phase 2 / Stage C - classifier.py

Pure analysis. No network calls. Given Daniel's replay_results.json (Stage B
output), produces a classification for every candidate:

    POSSIBLE_IDOR | NOT_VULNERABLE | INCONCLUSIVE

Same input -> byte-identical output (see report.py for the timestamp knob).

Owned by: Olivier (Person C / Stage C). Lives under src/testing/ only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_CONTENT_TYPES = {"application/json", "text/html", "text/plain"}

# replay_error values that, per spec, count as NOT_VULNERABLE as long as
# the attacker did NOT get the owner's object.
NOT_VULNERABLE_REPLAY_ERRORS = {
    "baseline_drift",
    "auth_lost",
    "suspiciously_small",
    "budget_exceeded",
    "rate_limited",
}

OWNER_DENIED_STATUSES = (401, 403)

RULE_ATTACKER_GOT_OWNER_OBJECT = "attacker_got_owner_object"
RULE_ATTACKER_DENIED = "attacker_denied"
RULE_BODY_IDENTICAL = "body_identical_across_users"
RULE_IDENTIFIER_IGNORED = "identifier_ignored"
RULE_REDIRECT_TO_LOGIN = "redirect_to_login"
RULE_BASELINE_DRIFT = "baseline_drift"
RULE_NO_CONTROL = "no_control"
RULE_OWNER_UNREACHABLE = "owner_unreachable"
RULE_UNEXPECTED_CONTENT_TYPE = "unexpected_content_type"
RULE_SMALL_RESPONSE = "small_response"
RULE_REPLAY_ERROR = "replay_error"
RULE_UNKNOWN = "unknown"


class AbortPhase2(RuntimeError):
    """Raised when Stage C must not proceed (sessions not distinct, or
    the preflight block is missing entirely)."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class StageCInputError(ValueError):
    """Raised when a replay_results.json record doesn't match the documented
    Stage B schema. Carries the offending candidate_id so a mismatch between
    Daniel's real output and the documented contract is loud and actionable
    instead of a bare KeyError/TypeError during integration."""


def classify_all(replay_results: dict) -> list[dict]:
    """
    Classify every record in a Stage B replay_results.json payload.

    replay_results must have the shape:
        {"preflight": {"sessions_distinct": bool, ...}, "results": [...]}

    Raises AbortPhase2 if the preflight block is missing, or if
    preflight.sessions_distinct is False.

    Raises StageCInputError if an individual record doesn't match the
    documented Stage B schema (missing candidate_id, session_a, session_b,
    or delta) - this is the most likely failure mode on first integration
    with the real replayer.py output, so it gets a specific, named error
    rather than a generic crash.
    """
    if not isinstance(replay_results, dict) or "preflight" not in replay_results:
        raise AbortPhase2(
            "replay_results.json is missing the top-level 'preflight' block; "
            "refusing to classify without proof the two sessions are distinct."
        )

    preflight = replay_results["preflight"]
    if not preflight.get("sessions_distinct", False):
        raise AbortPhase2(
            "preflight.sessions_distinct is false: the owner and attacker "
            "sessions are the same account. Every finding would be meaningless."
        )

    results = replay_results.get("results", [])
    return [classify_record(record) for record in results]


def classify_record(record: dict) -> dict:
    """Classify a single Stage B record. Returns a phase2_results.json row."""
    candidate_id = record.get("candidate_id")
    if not candidate_id:
        raise StageCInputError(
            "A record in replay_results.json has no candidate_id - cannot "
            "trace this finding back to Stage A/B. Record keys present: "
            f"{sorted(record.keys())}"
        )
    for required in ("session_a", "session_b", "delta"):
        if required not in record:
            raise StageCInputError(
                f"candidate_id={candidate_id}: record is missing '{required}'. "
                "This usually means replayer.py's real output has drifted "
                "from the documented Stage B schema - check with Daniel."
            )

    session_a = record.get("session_a") or {}
    session_b = record.get("session_b") or {}
    delta = record.get("delta") or {}
    flags = record.get("flags") or []
    replay_error = record.get("replay_error")
    test_kind = record.get("test_kind", "credential_swap")

    classification, rule_fired = _classify(
        session_a, session_b, delta, flags, replay_error, test_kind
    )

    confidence = None
    if classification == "POSSIBLE_IDOR":
        confidence = assign_confidence(session_a, session_b, delta)

    evidence = {
        "request": record.get("request"),
        "session_a_status": session_a.get("status"),
        "session_b_status": session_b.get("status"),
        "session_a_content_type": session_a.get("content_type"),
        "session_b_content_type": session_b.get("content_type"),
        "session_a_body_snippet": session_a.get("body_snippet"),
        "session_b_body_snippet": session_b.get("body_snippet"),
        "delta": delta,
        "flags": flags,
        "replay_error": replay_error,
    }

    return {
        "candidate_id": candidate_id,
        "classification": classification,
        "confidence": confidence,
        "rule_fired": rule_fired,
        "test_kind": test_kind,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Core rules
# ---------------------------------------------------------------------------

def _classify(
    session_a: dict,
    session_b: dict,
    delta: dict,
    flags: list,
    replay_error: Optional[str],
    test_kind: str,
) -> tuple[str, str]:
    """
    Returns (classification, rule_fired).

    Priority (highest first):
      1. Owner (session_a) itself couldn't be reached -> INCONCLUSIVE.
         (Classification note 3: wrong auth / missing state, don't classify.)
      2. Content type outside the allowed set -> INCONCLUSIVE (binary/unknown).
      3. NOT_VULNERABLE conditions.
      4. POSSIBLE_IDOR conditions (credential_swap only).
      5. Remaining INCONCLUSIVE conditions.
      6. Fallback -> INCONCLUSIVE / unknown (never silently mislabel).
    """
    a_status = session_a.get("status")
    b_status = session_b.get("status")
    a_size = session_a.get("response_size", 0) or 0
    b_size = session_b.get("response_size", 0) or 0
    a_ct = session_a.get("content_type")
    b_ct = session_b.get("content_type")

    status_changed = delta.get("status_changed", False)
    body_identical = delta.get("body_identical", False)
    got_owner_object = delta.get("session_b_got_owner_object", False)
    denied = delta.get("session_b_denied", False)
    redirected = delta.get("redirected_to_login", False)

    # 1. Owner unreachable -> can't trust anything else in this record.
    if a_status in OWNER_DENIED_STATUSES:
        return "INCONCLUSIVE", RULE_OWNER_UNREACHABLE

    # 2. Binary / unexpected content -> don't classify.
    for ct in (a_ct, b_ct):
        if ct is not None and ct not in ALLOWED_CONTENT_TYPES:
            return "INCONCLUSIVE", RULE_UNEXPECTED_CONTENT_TYPE

    # 3. NOT_VULNERABLE
    if denied:
        return "NOT_VULNERABLE", RULE_ATTACKER_DENIED

    if test_kind == "credential_swap" and body_identical and not status_changed:
        # Suspicious but not conclusive by itself - surfaced separately in
        # the report's "Manual review" section by report.py.
        return "NOT_VULNERABLE", RULE_BODY_IDENTICAL

    if status_changed and not got_owner_object:
        return "NOT_VULNERABLE", RULE_IDENTIFIER_IGNORED

    if replay_error in NOT_VULNERABLE_REPLAY_ERRORS and not got_owner_object:
        rule = RULE_BASELINE_DRIFT if replay_error == "baseline_drift" else RULE_REPLAY_ERROR
        return "NOT_VULNERABLE", rule

    # 4. POSSIBLE_IDOR - all conditions must hold.
    if (
        test_kind == "credential_swap"
        and got_owner_object
        and not denied
        and not redirected
        and replay_error is None
    ):
        return "POSSIBLE_IDOR", RULE_ATTACKER_GOT_OWNER_OBJECT

    # 5. Remaining INCONCLUSIVE conditions.
    if "no_control_found" in flags:
        return "INCONCLUSIVE", RULE_NO_CONTROL

    if redirected:
        return "INCONCLUSIVE", RULE_REDIRECT_TO_LOGIN

    if replay_error is not None and replay_error not in NOT_VULNERABLE_REPLAY_ERRORS:
        return "INCONCLUSIVE", RULE_REPLAY_ERROR

    if a_size < 50 or b_size < 50:
        return "INCONCLUSIVE", RULE_SMALL_RESPONSE

    # 6. Fallback - never guess POSSIBLE_IDOR / NOT_VULNERABLE by default.
    return "INCONCLUSIVE", RULE_UNKNOWN


def assign_confidence(session_a: dict, session_b: dict, delta: dict) -> str:
    """Confidence is only assigned for POSSIBLE_IDOR records."""
    a_snippet = session_a.get("body_snippet")
    b_snippet = session_b.get("body_snippet")
    a_ct = session_a.get("content_type")
    b_ct = session_b.get("content_type")
    b_status = session_b.get("status")
    size_delta = abs(delta.get("size_delta_bytes", 0) or 0)

    # If the snippets are literally equal, we don't have clean positive
    # evidence of distinct owner data within the captured 512B window -
    # always flag these for manual review regardless of other signals.
    if a_snippet is not None and a_snippet == b_snippet:
        return "low"

    if (
        b_status == 200
        and a_ct == "application/json"
        and b_ct == "application/json"
        and size_delta > 50
    ):
        return "high"

    if b_status in (200, 206) and a_ct == b_ct and size_delta > 5:
        return "medium"

    return "low"


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_replay_results(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_results_atomic(results: list[dict], out_path: str) -> None:
    """Write temp file then rename, so a crash mid-write never leaves a
    truncated phase2_results.json."""
    import os
    import tempfile

    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=out_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp_path, out_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
