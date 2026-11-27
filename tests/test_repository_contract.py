"""Repository-wide attribution contract.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

_PUBLIC_FILES = (
    ".github/workflows/ci.yml",
    ".gitignore",
    "CHANGELOG.md",
    "LICENSE",
    "PLAN.md",
    "README.md",
    "SECURITY.md",
    "docs/ARCHITECTURE.md",
    "docs/MARKET_RESEARCH.md",
    "pyproject.toml",
    "uv.lock",
    "src/baysoz_cricanon/__init__.py",
    "src/baysoz_cricanon/__main__.py",
    "src/baysoz_cricanon/cli.py",
    "src/baysoz_cricanon/core.py",
    "src/baysoz_cricanon/findings.py",
    "src/baysoz_cricanon/input.py",
    "src/baysoz_cricanon/policy.py",
    "src/baysoz_cricanon/sarif.py",
    "src/baysoz_cricanon/version.py",
)


def test_every_public_file_attributes_bays_labs() -> None:
    missing = []
    for relative in _PUBLIC_FILES:
        text = (_ROOT / relative).read_text(encoding="utf-8")
        if "Baysöz Labs" not in text or "baysozlabs@proton.me" not in text:
            missing.append(relative)
    assert missing == []
