# Architecture — Baysöz Labs <baysozlabs@proton.me>

## System intent

`baysoz-cricanon` is a deterministic offline oracle for the question:

> Given a captured log stream and a multiline policy, what exact records would
> a correct, bounded, stream-aware collector emit — and where does the input
> violate that contract?

It does not start a collector, contact a cluster, or execute arbitrary
configuration. It consumes immutable files, applies a validated policy, and
produces stable reports suitable for CI enforcement.

## Component map

```text
CLI (cli.py)
  ├── policy loader (policy.py) ──> validated, compiled bounded regexes
  ├── input adapters (input.py) ──> CRI / Docker JSON / plain LogLine
  ├── reassembler (core.py) ─────> stream-isolated CRI sequences
  ├── multiline resolver (core.py) -> canonical Record objects
  ├── finding taxonomy (findings.py) -> stable rule ids and levels
  └── renderers (sarif.py) ──────> text / JSON / SARIF 2.1.0
```

## Data flow

1. **Input expansion.** Files are accepted directly; directories are expanded
   deterministically over `.log`, `.jsonl`, `.json`, and `.txt` suffixes.
   Symlinked children are skipped to avoid escaping a captured corpus tree.
2. **Bounded read.** Each file's byte size is checked before parsing. Input
   that exceeds `limits.max_input_bytes` is skipped with `LIMIT001`.
3. **Line normalization.** Each raw line is checked against
   `limits.max_line_bytes`, truncated with `LIMIT002` when needed, and parsed
   according to `source_format` (`auto`, `cri`, `docker-json`, or `plain`).
   `auto` selects Docker JSON for lines beginning with `{`, else CRI.
4. **CRI reassembly.** A `P` fragment is buffered per stream. An `F` line
   closes that stream's buffer into one sequence. Buffers are isolated by
   `stdout`/`stderr`, so an interleaved container cannot contaminate records.
5. **Multiline resolution.** Each sequence is classified against
   `start_regex`, `continue_regex`, and `ignore_regex`. Unmatched lines are
   forced to a new boundary and reported as `MULTI002`. Event-time gaps beyond
   `flush_timeout_ms` flush an incomplete group with `MULTI003`.
6. **Cross-record invariants.** Duplicate emission, application sequence
   gaps, and timestamp regressions are checked on canonical records.
7. **Rendering.** Findings are sorted by source, line, rule id, and message.
   JSON and SARIF are emitted with sorted keys and UTF-8 preserved, so byte
   output is reproducible across machines.

## Core invariants

| Invariant | Enforcement | Rule id |
| --- | --- | --- |
| No cross-stream merge | per-stream partial buffers + post-check | `STREAM001` |
| No dangling partial | EOF buffer scan | `PARTIAL002` |
| Bounded partial growth | line/byte limit on buffer | `BUFFER001` |
| Event-time continuity | gap checks on partial and multiline groups | `PARTIAL001`, `MULTI003` |
| No duplicate final emission | content + stream fingerprint within window | `DUP001` |
| No lost/replayed application record | configurable sequence regex | `SEQ001` |
| Monotonic ingestion order | timestamp check within and across sequences | `TIME001` |
| Bounded regex evaluation | one unbounded repetition, no backrefs, 256 chars | policy validation |
| Bounded memory | file, line, record, and buffer limits | `LIMIT001`, `LIMIT002`, `BUFFER001`, `MULTI001` |

## Why offline event-time semantics are sufficient

A collector's wall-clock flush timer is not reproducible from a static corpus.
The oracle therefore uses *event-time deltas between adjacent records* as the
flush signal. This is intentional and documented: it detects the dangerous
shape (an incomplete group followed by a distant new start) without depending
on scheduler timing. CI results are identical for the same bytes.

## Differential mode

`cricanon diff` runs the full audit twice over the same paths with two
policies, reduces canonical records to `(stream, text)` counters, and reports
symmetric differences as `DIFF001`. This directly tests policy migrations such
as tightening a start regex or changing a continuation pattern, which is the
highest-risk change in multiline collector configuration.

## Security posture

- No `eval`, `exec`, `subprocess`, shell invocation, or dynamic import of
  policy code.
- Policies are JSON data only; regexes are validated and bounded before
  compilation.
- Input size and record size limits are mandatory and non-optional.
- All file I/O uses explicit UTF-8 encoding; undecodable bytes are replaced
  rather than executed or silently trusted.
- SARIF output contains only captured evidence strings, truncated to bounded
  lengths at the finding boundary.

## Public API

The package exports `audit`, `diff`, `Policy`, `policy_from_dict`,
`builtin_policy`, `load_policy`, `AuditResult`, `DiffResult`, `ATTRIBUTION`,
and `__version__` from `baysoz_cricanon`. The CLI is a thin adapter over the
same library functions, so library consumers and CI use identical logic.

## Attribution

Architecture and implementation by Baysöz Labs <baysozlabs@proton.me>.
