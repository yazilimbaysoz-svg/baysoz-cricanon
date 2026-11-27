"""Core oracle tests with adversarial log streams.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json

from baysoz_cricanon.core import audit, diff
from baysoz_cricanon.input import parse_timestamp
from baysoz_cricanon.policy import PolicyError, policy_from_dict
from baysoz_cricanon.sarif import render, render_sarif

from helpers import cri, policy_dict, write_log


def _rules(result: object) -> set[str]:
    return {item.rule_id for item in result.findings}


def test_parse_timestamp_supports_nanoseconds_and_offsets() -> None:
    assert parse_timestamp("1970-01-01T00:00:00.000000001Z") == 1
    assert parse_timestamp("1970-01-01T00:00:00+00:00") == 0
    assert parse_timestamp("1970-01-01T02:00:00+02:00") == 0
    assert parse_timestamp("2026-11-27T01:02:03.123456789Z") > 0
    assert parse_timestamp("not-a-timestamp") is None


def test_clean_cri_audit(tmp_path) -> None:
    path = write_log(
        tmp_path / "clean.log",
        cri(1, "* boot ok", second=1)
        + cri(2, "* ready", second=2, stream="stderr"),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert result.lines_seen == 2
    assert result.streams == ("stderr", "stdout")
    assert len(result.records) == 2
    assert result.findings == ()
    assert result.clean


def test_partial_reassembly_groups_fragments(tmp_path) -> None:
    path = write_log(
        tmp_path / "partial.log",
        cri(1, "Traceback (most recent call last):", second=1, flag="P")
        + cri(2, '  File "app.py", line 7', second=1, flag="P")
        + cri(3, "ValueError: broken", second=1),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert "PARTIAL002" not in _rules(result)
    assert len(result.records) == 1
    assert "Traceback" in result.records[0].text
    assert "ValueError: broken" in result.records[0].text


def test_dangling_partial_is_reported(tmp_path) -> None:
    path = write_log(
        tmp_path / "dangling.log",
        cri(1, "* unfinished", second=1, flag="P"),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert "PARTIAL002" in _rules(result)
    assert not result.clean


def test_streams_are_never_merged(tmp_path) -> None:
    path = write_log(
        tmp_path / "streams.log",
        cri(1, "* out start", second=1, flag="P")
        + cri(2, "* err start", second=1, stream="stderr", flag="P")
        + cri(3, "  at out", second=2)
        + cri(4, "  at err", second=2, stream="stderr"),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert "STREAM001" not in _rules(result)
    assert "PARTIAL002" not in _rules(result)
    assert len(result.records) == 2
    assert {item.stream for item in result.records} == {"stdout", "stderr"}


def test_multiline_stacktrace_is_one_record(tmp_path) -> None:
    path = write_log(
        tmp_path / "multiline.log",
        cri(1, "seq=1 start", second=1)
        + cri(2, "  at worker.run(worker.py:10)", second=1)
        + cri(3, "  at main(main.py:4)", second=1)
        + cri(4, "seq=2 done", second=2),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert len(result.records) == 2
    assert "worker.run" in result.records[0].text
    assert "main(" in result.records[0].text
    assert result.records[1].text == "seq=2 done"


def test_multiline_orphan_is_reported(tmp_path) -> None:
    path = write_log(tmp_path / "orphan.log", cri(1, "unclassified", second=1))
    result = audit([path], policy_from_dict(policy_dict()))
    assert "MULTI002" in _rules(result)
    assert len(result.records) == 1


def test_duplicate_final_line_is_reported(tmp_path) -> None:
    data = policy_dict()
    data["rules"]["sequence_gaps"] = False
    path = write_log(
        tmp_path / "duplicate.log",
        cri(1, "* same record", second=1, fraction=0)
        + cri(2, "* same record", second=1, fraction=100_000_000),
    )
    result = audit([path], policy_from_dict(data))
    assert "DUP001" in _rules(result)


def test_sequence_gap_is_reported(tmp_path) -> None:
    path = write_log(
        tmp_path / "sequence.log",
        cri(1, "seq=1 ok", second=1) + cri(2, "seq=3 ok", second=2),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert "SEQ001" in _rules(result)
    assert not result.clean


def test_timestamp_regression_is_reported(tmp_path) -> None:
    path = write_log(
        tmp_path / "regression.log",
        cri(1, "* later", second=5) + cri(2, "* earlier", second=2),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    assert "TIME001" in _rules(result)


def test_docker_json_adapter(tmp_path) -> None:
    data = policy_dict()
    data["source_format"] = "docker-json"
    path = write_log(
        tmp_path / "docker.jsonl",
        json.dumps(
            {
                "log": "* docker record\n",
                "stream": "stdout",
                "time": "1970-01-01T00:00:00.000000001Z",
            },
        )
        + "\n",
    )
    result = audit([path], policy_from_dict(data))
    assert result.findings == ()
    assert result.records[0].text == "* docker record"
    assert result.records[0].start_ns == 1


def test_plain_adapter(tmp_path) -> None:
    data = policy_dict()
    data["source_format"] = "plain"
    path = write_log(tmp_path / "plain.txt", "* first\n* second\n")
    result = audit([path], policy_from_dict(data))
    assert len(result.records) == 2
    assert result.findings == ()


def test_policy_rejects_unsafe_regex() -> None:
    data = policy_dict()
    data["multiline"]["start_regex"] = r"^(a+)+$"
    try:
        policy_from_dict(data)
    except PolicyError as exc:
        assert "unbounded repetition" in str(exc)
    else:
        raise AssertionError("unsafe regex was accepted")


def test_policy_requires_bays_labs_attribution() -> None:
    data = policy_dict()
    data["attribution"] = "Somebody Else"
    try:
        policy_from_dict(data)
    except PolicyError as exc:
        assert "attribution" in str(exc)
    else:
        raise AssertionError("policy without Baysöz Labs attribution was accepted")


def test_line_size_limit_truncates(tmp_path) -> None:
    data = policy_dict()
    data["limits"]["max_line_bytes"] = 64
    path = write_log(tmp_path / "long.log", cri(1, "* " + "x" * 500, second=1))
    result = audit([path], policy_from_dict(data))
    assert "LIMIT002" in _rules(result)


def test_input_size_limit_skips_file(tmp_path) -> None:
    data = policy_dict()
    data["limits"]["max_input_bytes"] = 64
    path = write_log(tmp_path / "huge.log", cri(1, "* " + "x" * 500, second=1))
    result = audit([path], policy_from_dict(data))
    assert "LIMIT001" in _rules(result)
    assert result.records == ()


def test_sarif_contains_attribution_and_rules(tmp_path) -> None:
    path = write_log(
        tmp_path / "sarif.log",
        cri(1, "seq=1 ok", second=1) + cri(2, "seq=3 ok", second=2),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    document = json.loads(render_sarif(result))
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["properties"]["attribution"].startswith("Baysöz Labs")
    assert any(
        rule["id"] == "SEQ001"
        for rule in document["runs"][0]["tool"]["driver"]["rules"]
    )
    assert document["runs"][0]["results"][0]["properties"]["attribution"].startswith(
        "Baysöz Labs",
    )


def test_diff_reports_record_boundary_divergence(tmp_path) -> None:
    path = write_log(
        tmp_path / "diff.log",
        cri(1, "2026-11-27 INFO outer", second=1)
        + cri(2, "  at inner.run(x.py:1)", second=1),
    )
    baseline_data = policy_dict()
    baseline_data["multiline"]["start_regex"] = r"^\d{4}-"
    baseline_data["multiline"]["continue_regex"] = r"^\s+at "
    candidate_data = policy_dict()
    candidate_data["multiline"]["start_regex"] = r"^\s+at "
    candidate_data["multiline"]["continue_regex"] = None
    result = diff(
        [path],
        policy_from_dict(baseline_data),
        policy_from_dict(candidate_data),
    )
    assert "DIFF001" in _rules(result)
    assert result.baseline_count == 1
    assert result.candidate_count == 2
    assert not result.clean


def test_adversarial_corpus_has_no_stream_contamination(tmp_path) -> None:
    path = write_log(
        tmp_path / "adversarial.log",
        cri(1, "seq=1 out start", second=1, flag="P")
        + cri(2, "seq=2 err start", second=1, stream="stderr", flag="P")
        + cri(3, "  at out", second=2)
        + cri(4, "  at err", second=2, stream="stderr")
        + cri(5, "* bad line", second=3)
        + "garbage without CRI framing\n"
        + cri(7, "* never completed", second=4, flag="P"),
    )
    result = audit([path], policy_from_dict(policy_dict()))
    rules = _rules(result)
    assert "CRI001" in rules
    assert "PARTIAL002" in rules
    assert "STREAM001" not in rules
    assert "BUFFER001" not in rules
    assert len(result.records) == 4
    assert any("* bad line" in item.text for item in result.records)


def test_render_is_deterministic(tmp_path) -> None:
    path = write_log(
        tmp_path / "stable.log",
        cri(1, "* one", second=1) + cri(2, "* two", second=2),
    )
    policy = policy_from_dict(policy_dict())
    first = render(audit([path], policy), "json")
    second = render(audit([path], policy), "json")
    assert first == second
    assert "Baysöz Labs" in first
