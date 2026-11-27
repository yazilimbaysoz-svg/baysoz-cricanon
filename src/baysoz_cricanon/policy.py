"""Bounded policy loading for baysoz-cricanon.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .version import ATTRIBUTION

_MAX_PATTERN_LENGTH = 256
_UNBOUNDED_REPETITION = re.compile(r"(?:\*|\+|\{\d+,\}|\{,\d+\})[?+]?")
_ALLOWED_FORMATS = frozenset({"auto", "cri", "docker-json", "plain"})

DEFAULT_POLICY_DICT: dict[str, Any] = {
    "attribution": ATTRIBUTION,
    "name": "kubernetes-cri-balanced",
    "source_format": "auto",
    "default_stream": "stdout",
    "multiline": {
        "start_regex": (
            r"^(?:\d{4}-\d{2}-\d{2}|[A-Z][a-z]{2} \d{2}|Exception|Traceback|\*|seq=)"
        ),
        "continue_regex": r"^\s+(?:at |Caused by:|File )",
        "ignore_regex": r"^\s*$",
        "sequence_regex": r"^seq=(\d+)\b",
        "max_record_bytes": 65536,
        "max_record_lines": 200,
        "flush_timeout_ms": 5000,
        "max_partial_gap_ms": 1000,
    },
    "limits": {
        "max_line_bytes": 1048576,
        "max_input_bytes": 268435456,
    },
    "rules": {
        "timestamp_monotonic": True,
        "stream_separation": True,
        "complete_partials": True,
        "sequence_gaps": True,
        "duplicates": True,
        "duplicate_window_ms": 250,
    },
}


class PolicyError(ValueError):
    """Raised when a policy document is structurally invalid."""


@dataclass(frozen=True)
class Policy:
    """Validated, compiled analysis policy."""

    name: str
    source_format: str
    default_stream: str
    start_pattern: re.Pattern[str] | None
    continue_pattern: re.Pattern[str] | None
    ignore_pattern: re.Pattern[str] | None
    sequence_pattern: re.Pattern[str] | None
    max_line_bytes: int
    max_input_bytes: int
    max_record_bytes: int
    max_record_lines: int
    flush_timeout_ms: int
    max_partial_gap_ms: int
    timestamp_monotonic: bool
    stream_separation: bool
    complete_partials: bool
    sequence_gaps: bool
    duplicates: bool
    duplicate_window_ms: int


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        msg = f"{label} must be a JSON object"
        raise PolicyError(msg)
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        msg = f"{label} must be a non-empty string"
        raise PolicyError(msg)
    return value


def _require_int(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        msg = f"{label} must be an integer >= {minimum}"
        raise PolicyError(msg)
    return value


def _require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        msg = f"{label} must be a boolean"
        raise PolicyError(msg)
    return value


def _compile_pattern(value: Any, label: str) -> re.Pattern[str] | None:
    if value is None:
        return None
    pattern = _require_string(value, label)
    if len(pattern) > _MAX_PATTERN_LENGTH:
        msg = f"{label} exceeds {_MAX_PATTERN_LENGTH} characters"
        raise PolicyError(msg)
    repetitions = _UNBOUNDED_REPETITION.findall(pattern)
    if len(repetitions) > 1:
        msg = f"{label} may contain at most one unbounded repetition"
        raise PolicyError(msg)
    if "\\1" in pattern or "\\2" in pattern:
        msg = f"{label} may not use backreferences"
        raise PolicyError(msg)
    try:
        return re.compile(pattern)
    except re.error as exc:
        msg = f"{label} is not a valid regular expression: {exc}"
        raise PolicyError(msg) from exc


def policy_from_dict(data: Any) -> Policy:
    """Validate a policy document and compile its bounded regexes."""
    root = _require_mapping(data, "policy")
    if root.get("attribution") != ATTRIBUTION:
        msg = f"policy attribution must be {ATTRIBUTION!r}"
        raise PolicyError(msg)

    source_format = _require_string(root.get("source_format"), "source_format")
    if source_format not in _ALLOWED_FORMATS:
        msg = f"source_format must be one of {sorted(_ALLOWED_FORMATS)}"
        raise PolicyError(msg)

    multiline = _require_mapping(root.get("multiline"), "multiline")
    limits = _require_mapping(root.get("limits"), "limits")
    rules = _require_mapping(root.get("rules"), "rules")

    return Policy(
        name=_require_string(root.get("name"), "name"),
        source_format=source_format,
        default_stream=_require_string(
            root.get("default_stream"),
            "default_stream",
        ),
        start_pattern=_compile_pattern(multiline.get("start_regex"), "start_regex"),
        continue_pattern=_compile_pattern(
            multiline.get("continue_regex"),
            "continue_regex",
        ),
        ignore_pattern=_compile_pattern(multiline.get("ignore_regex"), "ignore_regex"),
        sequence_pattern=_compile_pattern(
            multiline.get("sequence_regex"),
            "sequence_regex",
        ),
        max_line_bytes=_require_int(
            limits.get("max_line_bytes"),
            "limits.max_line_bytes",
            64,
        ),
        max_input_bytes=_require_int(
            limits.get("max_input_bytes"),
            "limits.max_input_bytes",
            64,
        ),
        max_record_bytes=_require_int(
            multiline.get("max_record_bytes"),
            "multiline.max_record_bytes",
            64,
        ),
        max_record_lines=_require_int(
            multiline.get("max_record_lines"),
            "multiline.max_record_lines",
            1,
        ),
        flush_timeout_ms=_require_int(
            multiline.get("flush_timeout_ms"),
            "multiline.flush_timeout_ms",
        ),
        max_partial_gap_ms=_require_int(
            multiline.get("max_partial_gap_ms"),
            "multiline.max_partial_gap_ms",
        ),
        timestamp_monotonic=_require_bool(
            rules.get("timestamp_monotonic"),
            "rules.timestamp_monotonic",
        ),
        stream_separation=_require_bool(
            rules.get("stream_separation"),
            "rules.stream_separation",
        ),
        complete_partials=_require_bool(
            rules.get("complete_partials"),
            "rules.complete_partials",
        ),
        sequence_gaps=_require_bool(
            rules.get("sequence_gaps"),
            "rules.sequence_gaps",
        ),
        duplicates=_require_bool(rules.get("duplicates"), "rules.duplicates"),
        duplicate_window_ms=_require_int(
            rules.get("duplicate_window_ms"),
            "rules.duplicate_window_ms",
        ),
    )


def builtin_policy() -> Policy:
    """Return the built-in balanced Kubernetes CRI policy."""
    return policy_from_dict(DEFAULT_POLICY_DICT)


def load_policy(path: Path) -> Policy:
    """Load a JSON policy document from disk."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"invalid policy JSON in {path}: {exc}"
        raise PolicyError(msg) from exc
    return policy_from_dict(data)
