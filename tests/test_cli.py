"""CLI contract tests for Baysöz Labs cricanon.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json

from baysoz_cricanon.cli import build_parser, main

from helpers import cri, policy_dict, write_log, write_policy


def test_root_help_mentions_attribution(capsys) -> None:
    help_text = build_parser().format_help()
    assert "Baysöz Labs" in help_text
    assert "baysozlabs@proton.me" in help_text
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "Baysöz Labs" in capsys.readouterr().out


def test_subcommand_help_mentions_attribution(capsys) -> None:
    try:
        main(["audit", "--help"])
    except SystemExit as exc:
        assert exc.code == 0
    output = capsys.readouterr().out
    assert "Baysöz Labs" in output
    assert "audit" in output


def test_version_output_mentions_attribution(capsys) -> None:
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    output = capsys.readouterr().out
    assert "Baysöz Labs" in output
    assert "baysozlabs@proton.me" in output


def test_cli_audit_json_output(tmp_path, capsys) -> None:
    path = write_log(tmp_path / "clean.log", cri(1, "* ok", second=1))
    code = main(["audit", "--input", str(path), "--format", "json"])
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert code == 0
    assert payload["attribution"].startswith("Baysöz Labs")
    assert payload["lines_seen"] == 1


def test_cli_audit_sarif_output(tmp_path, capsys) -> None:
    path = write_log(
        tmp_path / "gap.log",
        cri(1, "seq=1 ok", second=1) + cri(2, "seq=3 ok", second=2),
    )
    code = main(["audit", "--input", str(path), "--format", "sarif"])
    document = json.loads(capsys.readouterr().out)
    assert code == 1
    assert document["runs"][0]["results"][0]["ruleId"] == "SEQ001"


def test_cli_fail_on_none_suppresses_error_exit(tmp_path, capsys) -> None:
    path = write_log(tmp_path / "bad.log", "not-a-cri-line\n")
    code = main(["audit", "--input", str(path), "--fail-on", "none"])
    assert code == 0
    assert "CRI001" in capsys.readouterr().out


def test_cli_output_file(tmp_path) -> None:
    path = write_log(tmp_path / "clean.log", cri(1, "* ok", second=1))
    report = tmp_path / "report.sarif"
    code = main(
        ["audit", "--input", str(path), "--format", "sarif", "--output", str(report)],
    )
    assert code == 0
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["runs"][0]["results"] == []


def test_cli_diff_contract(tmp_path, capsys) -> None:
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
    baseline = write_policy(tmp_path / "baseline.json", baseline_data)
    candidate = write_policy(tmp_path / "candidate.json", candidate_data)
    code = main(
        [
            "diff",
            "--input",
            str(path),
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--format",
            "json",
        ],
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["findings"][0]["rule_id"] == "DIFF001"


def test_cli_missing_input_returns_configuration_error(capsys) -> None:
    code = main(["audit", "--input", "/definitely/not/here.log"])
    assert code == 2
    assert "Baysöz Labs" in capsys.readouterr().err
