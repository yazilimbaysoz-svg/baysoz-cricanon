# baysoz-cricanon

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-cricanon/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-cricanon/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![Runtime dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen)
![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-purple)
![License](https://img.shields.io/badge/license-MIT-green)

**Offline CRI log-stream record-boundary and continuity oracle with SARIF CI
gates — Baysöz Labs <baysozlabs@proton.me>**

`cricanon` answers a production question that dashboards cannot: *given a
captured container log stream and a multiline policy, what exact records should
a correct collector emit, and which framing or boundary defects exist?* It
reassembles Kubernetes CRI `P`/`F` fragments with strict stream isolation,
resolves multiline boundaries with bounded event-time flushing, detects
duplicate and lost records, and emits deterministic SARIF for CI enforcement.

No cluster, broker, database, renderer, or local LLM is required.

## Install

```bash
uv venv
uv pip install -e .
uv pip install pytest
cricanon --version
```

Python 3.13+ is required. Runtime dependencies: standard library only.

## Why it exists

Live 2026 ecosystem evidence is documented in
[`docs/MARKET_RESEARCH.md`](docs/MARKET_RESEARCH.md). The trigger set includes
open upstream defects around CRI stream-aware partial-line reassembly in
Vector, duplicate final lines and dropped pending multiline records in Fluent
Bit, and filelog truncation/OOM behavior in OpenTelemetry Collector Contrib.
These failures corrupt record identity, and every downstream SLO, alert, and
incident investigation inherits the damage.

## Architecture

```text
policy.py ──> bounded JSON policy + compiled regexes
input.py  ──> CRI / Docker JSON / plain LogLine stream
core.py   ──> P/F reassembly -> multiline boundaries -> invariants
findings.py ─> stable rule taxonomy
sarif.py  ──> deterministic text / JSON / SARIF 2.1.0
cli.py    ──> audit and diff commands
```

Full design details, invariants, and security boundaries are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Usage

```text
cricanon --version
cricanon audit --input captured/ --format sarif
cricanon audit --input segment.log --policy policy.json --format json
cricanon diff --input captured/ --baseline old.json --candidate new.json --format sarif
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` input or
policy error. Default `--fail-on` is `error`.

### Real CLI output

```text
$ uv run cricanon --version
cricanon 0.1.0 — Baysöz Labs <baysozlabs@proton.me>

$ uv run cricanon --help
usage: cricanon [-h] [--version] {audit,diff} ...

Offline CRI log-stream record-boundary and continuity oracle — Baysöz Labs
<baysozlabs@proton.me>

positional arguments:
  {audit,diff}
    audit       audit log streams and emit deterministic findings
    diff        diff canonical record sets produced by two policies

options:
  -h, --help    show this help message and exit
  --version     show program's version number and exit

Baysöz Labs <baysozlabs@proton.me>

$ uv run cricanon audit --input /tmp/opencode/cricanon-tribunal/clean.log
baysoz-cricanon 0.1.0 — Baysöz Labs <baysozlabs@proton.me>
lines seen: 2
records emitted: 2
streams: stderr, stdout
findings: 0
PASS: zero findings
```

## Detected defect classes

- `CRI001` malformed kubelet CRI framing
- `JSON001` invalid or incomplete Docker JSON line
- `LIMIT001` / `LIMIT002` file and line bounds
- `BUFFER001` partial buffer overflow
- `PARTIAL001` / `PARTIAL002` fragment gaps and dangling partials
- `STREAM001` stdout/stderr contamination
- `TIME001` timestamp regression
- `MULTI001` / `MULTI002` / `MULTI003` multiline limits, orphans, flush timeouts
- `DUP001` duplicate final record emission
- `SEQ001` application sequence gap or replay
- `DIFF001` policy migration boundary divergence

## Quality gates

```bash
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Documentation

- [`docs/MARKET_RESEARCH.md`](docs/MARKET_RESEARCH.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`PLAN.md`](PLAN.md)
- [`SECURITY.md`](SECURITY.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## License

MIT — Baysöz Labs <baysozlabs@proton.me>.
