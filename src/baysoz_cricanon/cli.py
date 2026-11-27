"""Command-line interface for baysoz-cricanon.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .core import audit, diff
from .policy import Policy, PolicyError, builtin_policy, load_policy
from .sarif import render
from .version import ATTRIBUTION, __version__

_OUTPUT_FORMATS = ("text", "json", "sarif")
_INPUT_SUFFIXES = frozenset({".log", ".jsonl", ".json", ".txt"})


def _description(text: str) -> str:
    return f"{text} — {ATTRIBUTION}"


def _expand_inputs(values: Sequence[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        path = Path(value)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if (
                    child.is_file()
                    and not child.is_symlink()
                    and child.suffix.lower() in _INPUT_SUFFIXES
                ):
                    paths.append(child)
        elif path.is_file():
            paths.append(path)
        else:
            msg = f"input path does not exist: {path}"
            raise ValueError(msg)
    if not paths:
        msg = "no input files found"
        raise ValueError(msg)
    return paths


def _select_policy(path: str | None) -> Policy:
    if path is None:
        return builtin_policy()
    return load_policy(Path(path))


def _write(rendered: str, output: str | None) -> None:
    if output is None:
        sys.stdout.write(rendered)
        return
    Path(output).write_text(rendered, encoding="utf-8")


def _blocking(result: object, fail_on: str) -> bool:
    levels = {
        "none": set(),
        "error": {"error"},
        "warning": {"error", "warning"},
        "all": {"error", "warning", "note"},
    }
    active = levels[fail_on]
    return any(item.level in active for item in result.findings)


def _add_report_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=_OUTPUT_FORMATS,
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--output",
        help="write the report to this file instead of stdout",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "error", "warning", "all"),
        default="error",
        help="finding level that produces exit code 1 (default: error)",
    )


def _audit_command(args: argparse.Namespace) -> int:
    policy = _select_policy(args.policy)
    result = audit(_expand_inputs(args.input), policy)
    _write(render(result, args.format), args.output)
    return 1 if _blocking(result, args.fail_on) else 0


def _diff_command(args: argparse.Namespace) -> int:
    baseline = load_policy(Path(args.baseline))
    candidate = load_policy(Path(args.candidate))
    result = diff(_expand_inputs(args.input), baseline, candidate)
    _write(render(result, args.format), args.output)
    return 1 if _blocking(result, args.fail_on) else 0


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser with explicit authors in every help surface."""
    parser = argparse.ArgumentParser(
        prog="cricanon",
        description=_description(
            "Offline CRI log-stream record-boundary and continuity oracle",
        ),
        epilog=ATTRIBUTION,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cricanon {__version__} — {ATTRIBUTION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser(
        "audit",
        description=_description("Audit CRI or Docker log streams"),
        epilog=ATTRIBUTION,
        help="audit log streams and emit deterministic findings",
    )
    audit_parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="input files or directories",
    )
    audit_parser.add_argument(
        "--policy",
        help="optional JSON policy; the built-in policy is used otherwise",
    )
    _add_report_options(audit_parser)
    audit_parser.set_defaults(handler=_audit_command)

    diff_parser = subparsers.add_parser(
        "diff",
        description=_description("Compare two multiline policies on one corpus"),
        epilog=ATTRIBUTION,
        help="diff canonical record sets produced by two policies",
    )
    diff_parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="input files or directories",
    )
    diff_parser.add_argument("--baseline", required=True, help="baseline policy JSON")
    diff_parser.add_argument("--candidate", required=True, help="candidate policy JSON")
    _add_report_options(diff_parser)
    diff_parser.set_defaults(handler=_diff_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a POSIX-style exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handler: Any = args.handler
        return int(handler(args))
    except (OSError, PolicyError, ValueError) as exc:
        sys.stderr.write(f"cricanon: {exc} — {ATTRIBUTION}\n")
        return 2
