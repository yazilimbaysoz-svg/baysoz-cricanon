"""Shared adversarial fixture helpers.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from baysoz_cricanon.policy import DEFAULT_POLICY_DICT


def write_log(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def write_policy(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path


def policy_dict() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_POLICY_DICT)


def cri(
    line_no: int,
    payload: str,
    stream: str = "stdout",
    flag: str = "F",
    second: int = 0,
    fraction: int = 0,
) -> str:
    stamp = f"2026-11-27T01:02:{second:02d}.{fraction:09d}Z"
    return f"{stamp} {stream} {flag} {payload}\n"
