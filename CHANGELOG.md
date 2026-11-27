# Changelog — Baysöz Labs <baysozlabs@proton.me>

All notable changes to this project are documented here.

## [0.1.0] - 2026-11-27

### Added

- Offline audit engine for Kubernetes CRI `P`/`F` fragment reassembly with
  strict `stdout`/`stderr` isolation.
- Docker JSON and plain-text input adapters with bounded parsing.
- Deterministic multiline boundary resolver with start, continuation, ignore,
  sequence, byte, line, and event-time flush controls.
- Stable finding taxonomy for malformed framing, dangling partials, stream
  contamination, timestamp regressions, duplicate emission, sequence gaps,
  buffer overflow, and policy divergence.
- `cricanon diff` for canonical record-set comparison between two policies.
- Text, JSON, and SARIF 2.1.0 reporters with explicit Baysöz Labs attribution.
- CI quality gates: pytest, Ruff `E,F,W,S,B`, and Semgrep `p/default`.
- Adversarial fixture coverage for the Supreme Grand Jury Tribunal.

### Notes

- Runtime dependencies: none beyond Python 3.13 standard library.
- Supreme Grand Jury Tribunal: 7 of 7 jurors unanimously passed live
  adversarial CLI validation.
- Maintained by Baysöz Labs <baysozlabs@proton.me>.
