"""Deterministic SARIF 2.1.0 and human-readable renderers.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .findings import RULE_METADATA
from .version import ATTRIBUTION, __version__

if TYPE_CHECKING:
    from .core import AuditResult, DiffResult


def _sarif_rule(rule_id: str) -> dict[str, object]:
    metadata = RULE_METADATA[rule_id]
    return {
        "id": rule_id,
        "name": metadata["name"],
        "shortDescription": {"text": metadata["short"]},
        "fullDescription": {"text": metadata["full"]},
    }


def _sarif_result(item: object) -> dict[str, object]:
    return {
        "ruleId": item.rule_id,
        "level": item.level,
        "message": {"text": item.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": item.source},
                    "region": {"startLine": item.line},
                },
            },
        ],
        "properties": {"attribution": ATTRIBUTION, "evidence": item.evidence},
    }


def render_sarif(result: AuditResult | DiffResult) -> str:
    """Render findings as a deterministic SARIF 2.1.0 document."""
    findings = result.findings
    rule_ids = sorted({item.rule_id for item in findings})
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baysoz-cricanon",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/yazilimbaysoz-svg/baysoz-cricanon"
                        ),
                        "fullDescription": {
                            "text": (
                                "Offline CRI log-stream record-boundary and "
                                "continuity oracle — Baysöz Labs "
                                "<baysozlabs@proton.me>"
                            ),
                        },
                        "rules": [_sarif_rule(rule_id) for rule_id in rule_ids],
                    },
                },
                "results": [_sarif_result(item) for item in findings],
                "properties": {
                    "attribution": ATTRIBUTION,
                    "finding_count": len(findings),
                },
            },
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_json(result: AuditResult | DiffResult) -> str:
    """Render a stable JSON representation for library and CI consumers."""
    if hasattr(result, "records"):
        audit_result = result
        payload: dict[str, object] = {
            "attribution": ATTRIBUTION,
            "tool": "baysoz-cricanon",
            "version": __version__,
            "lines_seen": audit_result.lines_seen,
            "streams": list(audit_result.streams),
            "records": [
                {
                    "source": item.source,
                    "stream": item.stream,
                    "first_line": item.first_line,
                    "last_line": item.last_line,
                    "text": item.text,
                }
                for item in audit_result.records
            ],
            "findings": [item.to_dict() for item in audit_result.findings],
        }
    else:
        diff_result = result
        payload = {
            "attribution": ATTRIBUTION,
            "tool": "baysoz-cricanon",
            "version": __version__,
            "baseline_records": diff_result.baseline_count,
            "candidate_records": diff_result.candidate_count,
            "findings": [item.to_dict() for item in diff_result.findings],
        }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_text(result: AuditResult | DiffResult) -> str:
    """Render a compact, deterministic text report."""
    lines = [
        f"baysoz-cricanon {__version__} — {ATTRIBUTION}",
    ]
    if hasattr(result, "records"):
        lines.append(f"lines seen: {result.lines_seen}")
        lines.append(f"records emitted: {len(result.records)}")
        lines.append(f"streams: {', '.join(result.streams) or '-'}")
    else:
        lines.append(f"baseline records: {result.baseline_count}")
        lines.append(f"candidate records: {result.candidate_count}")
    lines.append(f"findings: {len(result.findings)}")
    if not result.findings:
        lines.append("PASS: zero findings")
    for item in result.findings:
        lines.append(
            f"{item.level.upper():7} {item.rule_id} "
            f"{item.source}:{item.line}: {item.message}",
        )
    return "\n".join(lines) + "\n"


def render(result: AuditResult | DiffResult, output_format: str) -> str:
    """Dispatch rendering by requested output format."""
    if output_format == "sarif":
        return render_sarif(result)
    if output_format == "json":
        return render_json(result)
    if output_format == "text":
        return render_text(result)
    msg = f"unknown output format: {output_format}"
    raise ValueError(msg)
