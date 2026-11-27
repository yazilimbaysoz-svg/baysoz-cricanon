"""Stable finding taxonomy for baysoz-cricanon.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .version import ATTRIBUTION

RULE_METADATA: dict[str, dict[str, str]] = {
    "CRI001": {
        "name": "MalformedCriLine",
        "short": "A CRI log line does not match the kubelet CRI format",
        "full": (
            "Expected '<rfc3339> <stdout|stderr> <P|F> <payload>'. "
            "Unparseable lines are skipped by the oracle and reported."
        ),
    },
    "JSON001": {
        "name": "MalformedDockerJsonLine",
        "short": "A Docker JSON log line is invalid or incomplete",
        "full": (
            "Each line must be a JSON object with string fields 'log', "
            "'stream' and 'time'."
        ),
    },
    "LIMIT001": {
        "name": "InputSizeLimit",
        "short": "An input file exceeds the configured byte limit",
        "full": "The file is skipped before parsing to keep analysis bounded.",
    },
    "LIMIT002": {
        "name": "LineSizeLimit",
        "short": "A log line exceeds the configured byte limit",
        "full": "The line is truncated before parsing to keep analysis bounded.",
    },
    "BUFFER001": {
        "name": "PartialBufferOverflow",
        "short": "A pending partial-message buffer exceeded a configured limit",
        "full": "The pending buffer is dropped to avoid unbounded memory use.",
    },
    "PARTIAL001": {
        "name": "PartialGap",
        "short": "Consecutive partial fragments are too far apart in event time",
        "full": "A large event-time gap can indicate a lost continuation fragment.",
    },
    "PARTIAL002": {
        "name": "DanglingPartial",
        "short": "A partial message was never completed by a final fragment",
        "full": "The end of input arrived while a stream still held P-flagged lines.",
    },
    "STREAM001": {
        "name": "StreamSeparationViolation",
        "short": "A reassembled record mixes more than one stream",
        "full": "stdout and stderr fragments must never be merged into one record.",
    },
    "TIME001": {
        "name": "TimestampRegression",
        "short": "Timestamps are not monotonic inside or across records",
        "full": "Non-monotonic timestamps usually indicate corruption or reordering.",
    },
    "MULTI001": {
        "name": "MultilineLimit",
        "short": "A multiline group exceeded its byte or line limit",
        "full": "The group is flushed immediately and reported.",
    },
    "MULTI002": {
        "name": "MultilineOrphan",
        "short": "A line matches neither start nor continuation policy",
        "full": "The line is forced to a new record boundary instead of being merged.",
    },
    "MULTI003": {
        "name": "MultilineFlushTimeout",
        "short": "An incomplete multiline group exceeded its event-time timeout",
        "full": "The group is flushed before the next start line is attached.",
    },
    "DUP001": {
        "name": "DuplicateRecord",
        "short": "An identical record was emitted twice within the duplicate window",
        "full": "Duplicate emission is a common multiline parser transition defect.",
    },
    "SEQ001": {
        "name": "SequenceGap",
        "short": "An application sequence number skipped or repeated a value",
        "full": "Sequence numbers expose silently dropped or replayed records.",
    },
    "DIFF001": {
        "name": "RecordBoundaryDivergence",
        "short": "Two policies produce different canonical record sets",
        "full": "The differential command reports record count differences by content.",
    },
}

LEVELS = frozenset({"error", "warning", "note"})


@dataclass(frozen=True)
class Finding:
    """A deterministic, CI-consumable observability defect report."""

    rule_id: str
    level: str
    message: str
    source: str
    line: int
    evidence: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.rule_id not in RULE_METADATA:
            msg = f"unknown rule id: {self.rule_id}"
            raise ValueError(msg)
        if self.level not in LEVELS:
            msg = f"unknown finding level: {self.level}"
            raise ValueError(msg)
        if self.line < 1:
            msg = "line numbers must be positive"
            raise ValueError(msg)
        object.__setattr__(
            self,
            "evidence",
            dict(sorted(self.evidence.items())),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation with explicit attribution."""
        return {
            "attribution": ATTRIBUTION,
            "rule_id": self.rule_id,
            "rule_name": RULE_METADATA[self.rule_id]["name"],
            "level": self.level,
            "message": self.message,
            "source": self.source,
            "line": self.line,
            "evidence": dict(self.evidence),
        }
