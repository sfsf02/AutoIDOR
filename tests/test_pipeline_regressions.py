import json

from src.capture.logger import finalize_spool
from src.testing.classifier import classify_record
from src.testing.replayer import response_contains_identifier


def test_capture_checkpoints_keep_all_records(tmp_path):
    output = tmp_path / "api_flows.json"
    spool = tmp_path / "api_flows.json.records.jsonl"
    spool.write_text('{"flow_id":"one"}\n', encoding="utf-8")
    finalize_spool(output)
    with spool.open("a", encoding="utf-8") as file:
        file.write('{"flow_id":"two"}\n')
    finalize_spool(output)
    assert [row["flow_id"] for row in json.loads(output.read_text())] == ["one", "two"]


def test_finalization_does_not_erase_existing_capture(tmp_path):
    output = tmp_path / "api_flows.json"
    output.write_text('[{"flow_id":"one"}]', encoding="utf-8")
    finalize_spool(output)
    assert json.loads(output.read_text()) == [{"flow_id": "one"}]


def test_json_object_identifier_is_required_for_positive_signal():
    body = b'{"id":101,"owner":"alice","title":"Private document"}'
    identifier = {"name": None, "original_value": "101"}
    assert response_contains_identifier(body, "application/json", identifier)
    assert not response_contains_identifier(body, "text/html", identifier)
    assert not response_contains_identifier(body, "application/json", {"name": None, "original_value": "202"})

def test_mutation_denial_is_not_reported_as_not_vulnerable():
    result = classify_record({
        "candidate_id": "candidate-1",
        "session_a": {"status": 200, "response_size": 100, "content_type": "application/json"},
        "session_b": {"status": 403, "response_size": 30, "content_type": "application/json"},
        "delta": {"session_b_denied": True},
        "flags": ["secondary_signal"],
        "replay_error": None,
        "test_kind": "identifier_mutation",
    })
    assert result["classification"] == "INCONCLUSIVE"
