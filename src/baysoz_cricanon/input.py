"""Bounded adapters for Kubernetes CRI, Docker JSON, and plain logs.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import calendar
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .findings import Finding
from .policy import Policy

_CRI_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))"
    r" (?P<stream>stdout|stderr) (?P<flag>[PF]) (?P<payload>.*)$",
)
_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d{2}:\d{2})$",
)


@dataclass(frozen=True)
class LogLine:
    """One normalized input line with provenance and replay metadata."""

    source: str
    line_no: int
    stream: str
    partial: bool | None
    timestamp_ns: int | None
    payload: str
    raw: str
    source_format: str


def parse_timestamp(text: str) -> int | None:
    """Parse an RFC 3339 timestamp into integer nanoseconds since epoch."""
    match = _TIMESTAMP_PATTERN.fullmatch(text)
    if match is None:
        return None
    zone = match.group("zone")
    normalized = match.group("base") + ("+00:00" if zone == "Z" else zone)
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    seconds = calendar.timegm(parsed.utctimetuple())
    fraction = match.group("fraction") or ""
    return seconds * 1_000_000_000 + int(fraction.ljust(9, "0"))


def _finding(
    rule_id: str,
    level: str,
    message: str,
    source: str,
    line_no: int,
    **evidence: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        level=level,
        message=message,
        source=source,
        line=line_no,
        evidence=evidence,
    )


def _truncate(raw: str, limit: int) -> str:
    encoded = raw.encode("utf-8", errors="replace")
    return encoded[:limit].decode("utf-8", errors="replace")


def _parse_docker_json(
    raw: str,
    source: str,
    line_no: int,
    policy: Policy,
) -> tuple[LogLine | None, list[Finding]]:
    findings: list[Finding] = []
    try:
        value: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [
            _finding(
                "JSON001",
                "error",
                "Docker JSON line is not valid JSON",
                source,
                line_no,
                detail=str(exc)[:120],
            ),
        ]
    if not isinstance(value, dict):
        return None, [
            _finding(
                "JSON001",
                "error",
                "Docker JSON line must be an object",
                source,
                line_no,
            ),
        ]
    log = value.get("log")
    stream = value.get("stream")
    time_value = value.get("time")
    if not isinstance(log, str):
        return None, [
            _finding(
                "JSON001",
                "error",
                "Docker JSON line has no string 'log' field",
                source,
                line_no,
            ),
        ]
    if stream not in {"stdout", "stderr"}:
        findings.append(
            _finding(
                "JSON001",
                "warning",
                "Docker JSON stream is invalid; default stream applied",
                source,
                line_no,
                stream=str(stream)[:80],
            ),
        )
        stream = policy.default_stream
    timestamp_ns = None
    if isinstance(time_value, str):
        timestamp_ns = parse_timestamp(time_value)
        if timestamp_ns is None:
            findings.append(
                _finding(
                    "JSON001",
                    "warning",
                    "Docker JSON timestamp is invalid",
                    source,
                    line_no,
                    timestamp=str(time_value)[:80],
                ),
            )
    else:
        findings.append(
            _finding(
                "JSON001",
                "warning",
                "Docker JSON timestamp is missing",
                source,
                line_no,
            ),
        )
    line = LogLine(
        source=source,
        line_no=line_no,
        stream=str(stream),
        partial=None,
        timestamp_ns=timestamp_ns,
        payload=log.rstrip("\r\n"),
        raw=raw,
        source_format="docker-json",
    )
    return line, findings


def _parse_cri(
    raw: str,
    source: str,
    line_no: int,
) -> tuple[LogLine | None, list[Finding]]:
    match = _CRI_PATTERN.fullmatch(raw)
    if match is None:
        return None, [
            _finding(
                "CRI001",
                "error",
                "CRI line does not match kubelet CRI format",
                source,
                line_no,
                raw=raw[:120],
            ),
        ]
    timestamp_ns = parse_timestamp(match.group("timestamp"))
    if timestamp_ns is None:
        return None, [
            _finding(
                "CRI001",
                "error",
                "CRI timestamp is not valid RFC 3339",
                source,
                line_no,
            ),
        ]
    line = LogLine(
        source=source,
        line_no=line_no,
        stream=match.group("stream"),
        partial=match.group("flag") == "P",
        timestamp_ns=timestamp_ns,
        payload=match.group("payload"),
        raw=raw,
        source_format="cri",
    )
    return line, []


def parse_line(
    raw: str,
    source: str,
    line_no: int,
    policy: Policy,
) -> tuple[LogLine | None, list[Finding]]:
    """Normalize one raw line using the policy source format."""
    raw = raw.rstrip("\r\n")
    byte_length = len(raw.encode("utf-8", errors="replace"))
    findings: list[Finding] = []
    if byte_length > policy.max_line_bytes:
        findings.append(
            _finding(
                "LIMIT002",
                "warning",
                "Line exceeds configured byte limit and was truncated",
                source,
                line_no,
                bytes=str(byte_length),
                limit=str(policy.max_line_bytes),
            ),
        )
        raw = _truncate(raw, policy.max_line_bytes)
    if not raw.strip():
        return None, []

    source_format = policy.source_format
    if source_format == "auto":
        source_format = "docker-json" if raw.lstrip().startswith("{") else "cri"

    if source_format == "docker-json":
        parsed, adapter_findings = _parse_docker_json(raw, source, line_no, policy)
        findings.extend(adapter_findings)
        return parsed, findings
    if source_format == "cri":
        parsed, adapter_findings = _parse_cri(raw, source, line_no)
        findings.extend(adapter_findings)
        return parsed, findings
    return (
        LogLine(
            source=source,
            line_no=line_no,
            stream=policy.default_stream,
            partial=None,
            timestamp_ns=None,
            payload=raw,
            raw=raw,
            source_format="plain",
        ),
        [],
    )


def read_lines(
    path: Path,
    policy: Policy,
) -> tuple[list[tuple[int, str]], list[Finding]]:
    """Read bounded input lines from one file."""
    source = str(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        return [], [
            _finding(
                "LIMIT001",
                "error",
                "Input file could not be inspected",
                source,
                1,
                detail=str(exc)[:120],
            ),
        ]
    if size > policy.max_input_bytes:
        return [], [
            _finding(
                "LIMIT001",
                "error",
                "Input file exceeds configured byte limit and was skipped",
                source,
                1,
                bytes=str(size),
                limit=str(policy.max_input_bytes),
            ),
        ]
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = list(enumerate(handle, start=1))
    except OSError as exc:
        return [], [
            _finding(
                "LIMIT001",
                "error",
                "Input file could not be read",
                source,
                1,
                detail=str(exc)[:120],
            ),
        ]
    return lines, []
