"""Stream-aware reassembly and multiline boundary analysis.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding
from .input import LogLine, parse_line, read_lines
from .policy import Policy


@dataclass(frozen=True)
class Sequence:
    """A CRI-complete sequence of one or more fragments."""

    stream: str
    lines: tuple[LogLine, ...]
    source: str
    first_line: int
    text: str
    start_ns: int | None
    end_ns: int | None


@dataclass(frozen=True)
class Record:
    """A canonical record after multiline boundary resolution."""

    stream: str
    sequences: tuple[Sequence, ...]
    source: str
    first_line: int
    last_line: int
    text: str
    start_ns: int | None
    end_ns: int | None


@dataclass(frozen=True)
class AuditResult:
    """Deterministic audit output for CI and library consumers."""

    records: tuple[Record, ...]
    findings: tuple[Finding, ...]
    lines_seen: int
    streams: tuple[str, ...]

    @property
    def clean(self) -> bool:
        """Return True when no error-level findings were produced."""
        return not any(item.level == "error" for item in self.findings)


@dataclass(frozen=True)
class DiffResult:
    """Result of a canonical record-set differential between two policies."""

    findings: tuple[Finding, ...]
    baseline_count: int
    candidate_count: int

    @property
    def clean(self) -> bool:
        """Return True when both policies produced identical record sets."""
        return not self.findings


def _byte_length(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def _first_text_line(text: str) -> str:
    return text.split("\n", 1)[0]


def _ns_gap_ms(start_ns: int | None, end_ns: int | None) -> int:
    if start_ns is None or end_ns is None:
        return 0
    return max(0, (start_ns - end_ns) // 1_000_000)


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


def reassemble(
    lines: list[LogLine],
    policy: Policy,
    findings: list[Finding],
) -> list[Sequence]:
    """Group CRI P/F fragments into stream-isolated complete sequences."""
    sequences: list[Sequence] = []
    pending: dict[str, list[LogLine]] = {}
    last_end_ns: dict[str, int] = {}

    def emit(group: list[LogLine]) -> None:
        if not group:
            return
        stream = group[0].stream
        if policy.stream_separation and any(item.stream != stream for item in group):
            findings.append(
                _finding(
                    "STREAM001",
                    "error",
                    "Reassembled record mixes stdout and stderr",
                    stream,
                    group[0].line_no,
                    streams=",".join(sorted({item.stream for item in group})),
                ),
            )
        if policy.timestamp_monotonic:
            for earlier, later in zip(group, group[1:], strict=False):
                if (
                    earlier.timestamp_ns is not None
                    and later.timestamp_ns is not None
                    and later.timestamp_ns < earlier.timestamp_ns
                ):
                    findings.append(
                        _finding(
                            "TIME001",
                            "warning",
                            "Timestamps regress inside a reassembled sequence",
                            later.source,
                            later.line_no,
                        ),
                    )
            previous_end = last_end_ns.get(stream)
            first_start = group[0].timestamp_ns
            if previous_end is not None and first_start is not None:
                if first_start < previous_end:
                    findings.append(
                        _finding(
                            "TIME001",
                            "warning",
                            "Timestamps regress across records in one stream",
                            group[0].source,
                            group[0].line_no,
                        ),
                    )
        timestamps = [
            item.timestamp_ns for item in group if item.timestamp_ns is not None
        ]
        end_ns = timestamps[-1] if timestamps else None
        if end_ns is not None:
            last_end_ns[stream] = max(end_ns, last_end_ns.get(stream, end_ns))
        sequences.append(
            Sequence(
                stream=stream,
                lines=tuple(group),
                source=group[0].source,
                first_line=group[0].line_no,
                text="\n".join(item.payload for item in group),
                start_ns=timestamps[0] if timestamps else None,
                end_ns=end_ns,
            ),
        )

    for line in lines:
        if line.partial is None:
            emit([line])
            continue
        buffer = pending.setdefault(line.stream, [])
        if line.partial:
            if buffer:
                previous = buffer[-1]
                gap = _ns_gap_ms(previous.timestamp_ns, line.timestamp_ns)
                if gap > policy.max_partial_gap_ms:
                    findings.append(
                        _finding(
                            "PARTIAL001",
                            "warning",
                            "Partial fragments exceed the event-time gap limit",
                            line.source,
                            line.line_no,
                            gap_ms=str(gap),
                        ),
                    )
            buffer.append(line)
            total_bytes = sum(_byte_length(item.payload) + 1 for item in buffer)
            if (
                len(buffer) > policy.max_record_lines
                or total_bytes > policy.max_record_bytes
            ):
                findings.append(
                    _finding(
                        "BUFFER001",
                        "error",
                        "Partial buffer exceeded configured limits and was dropped",
                        line.source,
                        line.line_no,
                        fragments=str(len(buffer)),
                        bytes=str(total_bytes),
                    ),
                )
                pending[line.stream] = []
            continue
        buffer.append(line)
        emit(buffer)
        pending[line.stream] = []

    if policy.complete_partials:
        for stream in sorted(pending):
            buffer = pending[stream]
            if buffer:
                findings.append(
                    _finding(
                        "PARTIAL002",
                        "error",
                        "Partial message was never completed by a final fragment",
                        buffer[-1].source,
                        buffer[-1].line_no,
                        stream=stream,
                        fragments=str(len(buffer)),
                    ),
                )
            emit(list(buffer))
    return sequences


def _make_record(group: list[Sequence]) -> Record:
    first = group[0]
    last = group[-1]
    return Record(
        stream=first.stream,
        sequences=tuple(group),
        source=first.source,
        first_line=first.first_line,
        last_line=last.lines[-1].line_no,
        text="\n".join(item.text for item in group),
        start_ns=first.start_ns,
        end_ns=last.end_ns,
    )


def _record_exceeds(group: list[Sequence], policy: Policy) -> bool:
    total_bytes = sum(_byte_length(item.text) + 1 for item in group)
    return len(group) > policy.max_record_lines or total_bytes > policy.max_record_bytes


def apply_multiline(
    sequences: list[Sequence],
    policy: Policy,
    findings: list[Finding],
) -> list[Record]:
    """Resolve multiline record boundaries with bounded event-time flushing."""
    if policy.start_pattern is None and policy.continue_pattern is None:
        return [_make_record([item]) for item in sequences]

    records: list[Record] = []
    pending: list[Sequence] = []

    def flush() -> None:
        if pending:
            records.append(_make_record(list(pending)))
            pending.clear()

    for sequence in sequences:
        first_line = _first_text_line(sequence.text)
        if (
            policy.ignore_pattern is not None
            and policy.ignore_pattern.match(first_line)
        ):
            continue
        if policy.start_pattern is not None and policy.start_pattern.match(first_line):
            if pending:
                gap = _ns_gap_ms(pending[-1].end_ns, sequence.start_ns)
                if policy.flush_timeout_ms and gap > policy.flush_timeout_ms:
                    findings.append(
                        _finding(
                            "MULTI003",
                            "warning",
                            "Incomplete multiline group exceeded flush timeout",
                            sequence.source,
                            sequence.first_line,
                            gap_ms=str(gap),
                        ),
                    )
                    flush()
            flush()
            pending.append(sequence)
            if _record_exceeds(pending, policy):
                findings.append(
                    _finding(
                        "MULTI001",
                        "warning",
                        "Single-sequence record exceeded configured limits",
                        sequence.source,
                        sequence.first_line,
                    ),
                )
                flush()
            continue
        if (
            pending
            and policy.continue_pattern is not None
            and policy.continue_pattern.match(first_line)
        ):
            pending.append(sequence)
            if _record_exceeds(pending, policy):
                findings.append(
                    _finding(
                        "MULTI001",
                        "warning",
                        "Multiline group exceeded configured limits and was flushed",
                        sequence.source,
                        sequence.first_line,
                    ),
                )
                flush()
            continue
        flush()
        findings.append(
            _finding(
                "MULTI002",
                "warning",
                "Line matched neither start nor continuation policy",
                sequence.source,
                sequence.first_line,
                payload=first_line[:120],
            ),
        )
        pending.append(sequence)
    flush()

    if policy.duplicates:
        previous: dict[tuple[str, str], tuple[int, int | None]] = {}
        for record in records:
            key = (record.stream, record.text)
            prior = previous.get(key)
            gap = _ns_gap_ms(prior[1], record.start_ns) if prior else 0
            if prior is not None and gap <= policy.duplicate_window_ms:
                findings.append(
                    _finding(
                        "DUP001",
                        "warning",
                        "Identical record emitted twice within duplicate window",
                        record.source,
                        record.first_line,
                        stream=record.stream,
                        previous_line=str(prior[0]),
                    ),
                )
            previous[key] = (record.first_line, record.start_ns)

    if policy.sequence_gaps and policy.sequence_pattern is not None:
        last_sequence: dict[str, int] = {}
        for record in records:
            match = policy.sequence_pattern.search(_first_text_line(record.text))
            if match is None:
                continue
            value = int(match.group(1))
            prior = last_sequence.get(record.stream)
            if prior is not None and value != prior + 1:
                findings.append(
                    _finding(
                        "SEQ001",
                        "error",
                        "Sequence number skipped or repeated",
                        record.source,
                        record.first_line,
                        stream=record.stream,
                        previous=str(prior),
                        current=str(value),
                    ),
                )
            last_sequence[record.stream] = value

    return records


def _sort_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    ordered = sorted(
        findings,
        key=lambda item: (item.source, item.line, item.rule_id, item.message),
    )
    return tuple(ordered)


def audit(paths: list[Path], policy: Policy) -> AuditResult:
    """Audit input files and return canonical records plus stable findings."""
    findings: list[Finding] = []
    lines: list[LogLine] = []
    lines_seen = 0
    for path in paths:
        raw_lines, read_findings = read_lines(path, policy)
        findings.extend(read_findings)
        for line_no, raw in raw_lines:
            lines_seen += 1
            parsed, parse_findings = parse_line(raw, str(path), line_no, policy)
            findings.extend(parse_findings)
            if parsed is not None:
                lines.append(parsed)
    sequences = reassemble(lines, policy, findings)
    records = apply_multiline(sequences, policy, findings)
    streams = tuple(sorted({record.stream for record in records}))
    return AuditResult(
        records=tuple(records),
        findings=_sort_findings(findings),
        lines_seen=lines_seen,
        streams=streams,
    )


def diff(
    paths: list[Path],
    baseline: Policy,
    candidate: Policy,
) -> DiffResult:
    """Compare canonical record sets produced by two policies."""
    left = audit(paths, baseline)
    right = audit(paths, candidate)
    left_counts = Counter((item.stream, item.text) for item in left.records)
    right_counts = Counter((item.stream, item.text) for item in right.records)
    findings: list[Finding] = []
    keys = sorted(set(left_counts) | set(right_counts))
    locations = {
        (item.stream, item.text): item for item in (*left.records, *right.records)
    }
    for key in keys:
        left_count = left_counts.get(key, 0)
        right_count = right_counts.get(key, 0)
        if left_count == right_count:
            continue
        location = locations[key]
        findings.append(
            _finding(
                "DIFF001",
                "error",
                "Policies emit different canonical record sets",
                location.source,
                location.first_line,
                stream=key[0],
                baseline=str(left_count),
                candidate=str(right_count),
                payload=_first_text_line(key[1])[:120],
            ),
        )
    return DiffResult(
        findings=_sort_findings(findings),
        baseline_count=len(left.records),
        candidate_count=len(right.records),
    )
