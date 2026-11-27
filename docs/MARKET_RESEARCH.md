# Market Research — Baysöz Labs <baysozlabs@proton.me>

## Research window and method

This report records a live ecosystem survey performed on **2026-11-27** with
`gh search repos` and `gh search issues`, followed by a de-duplication pass
against all 45 entries in `/home/runner/work/_temp/existing-repos.json`.
No service was started, no model was invoked, and no network-dependent runtime
component was selected. The selected implementation target is **Python 3.13+**
with `uv`, standard-library-only runtime dependencies, and deterministic SARIF
2.1.0 output.

The governing question was not "what is a small useful script?" but "which
production observability failure mode is currently expensive, recurring, and
not already covered by the adjacent Baysöz Labs portfolio?" Trivial helpers,
wrappers around a single command, and toy format converters were excluded.

## Live repository signal (stars observed via `gh search repos`)

| Repository | Stars | Last push | Ecosystem role |
| --- | ---: | --- | --- |
| `netdata/netdata` | 81,656 | 2026-11-27 | Full-stack observability, 2000+ integrations |
| `grafana/grafana` | 78,213 | 2026-11-27 | Composable telemetry visualization |
| `juspay/hyperswitch` | 45,925 | 2026-11-27 | High-throughput systems with deep telemetry needs |
| `langfuse/langfuse` | 37,899 | 2026-11-26 | OpenTelemetry-based engineering platform |
| `openobserve/openobserve` | 23,195 | 2026-11-27 | Unified logs, metrics, traces, SLO |
| `vectordotdev/vector` | 22,979 | 2026-11-26 | High-performance observability pipeline |
| `kubeshark/kubeshark` | 12,151 | 2026-11-24 | eBPF Kubernetes L4/L7 observability |
| `quickwit-oss/quickwit` | 11,816 | 2026-11-26 | Search engine for observability data |
| `microsoft/retina` | 3,191 | 2026-11-26 | eBPF networking observability |
| `cilium/tetragon` | 5,234 | 2026-11-26 | Security observability and runtime enforcement |

The signal is unambiguous: large, actively maintained observability systems
are growing around collection pipelines and Kubernetes telemetry. The "
collector layer" is where correctness pressure concentrates, because every
downstream dashboard, SLO, alert, and forensic investigation inherits its
record boundaries.

## Live issue signal (open issues observed via `gh search issues`)

The following open issues were retrieved live and directly motivate the
selected scope:

1. **Vector** — `kubernetes_logs: partial-line reassembly merges stdout and
   stderr because the merge key ignores the CRI stream` (1 comment, opened
   2026-10-06):
   https://github.com/vectordotdev/vector/issues/26562
2. **Fluent Bit** — `multiline: duplicate final line emitted for regex parsers
   transitioning back to start_state` (opened 2026-11-03):
   https://github.com/fluent/fluent-bit/issues/12713
3. **Fluent Bit** — `in_tail: pending multiline record silently dropped when
   flush_timeout fires while the input is paused` (opened 2026-11-03):
   https://github.com/fluent/fluent-bit/issues/12710
4. **Fluent Bit** — `filter_multiline: per-tag streams never freed, unbounded
   memory growth on high pod churn` (opened 2026-10-28):
   https://github.com/fluent/fluent-bit/issues/12670
5. **Fluent Bit** — `Records flushed by in_tail's multiline at shutdown skip
   all filters (or are lost with memory storage)` (opened 2026-10-21):
   https://github.com/fluent/fluent-bit/issues/12628
6. **OpenTelemetry Collector Contrib** — `[receiver/filelog]
   max_log_size_behavior: truncate emits the remainder as a new record when
   the line spans polls` (opened 2026-11-11):
   https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/53018
7. **OpenTelemetry Collector Contrib** — `Add configuration to limit per-poll
   log loading in filelog receiver to prevent OOM` (opened 2026-02-11):
   https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/46002
8. **OpenTelemetry Collector Contrib** — `Promote file_log receiver to stable -
   Testing` (opened 2026-10-14):
   https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/52034
9. **Vector** — `Let vector validate report use of deprecated
   features/transforms/sinks/sources etc.` (opened 2022-06-21, still open):
   https://github.com/vectordotdev/vector/issues/13249
10. **Vector** — `prometheus_remote_write source: skip_nan_values does not
    cover histogram/summary counts, stale-marker NaN still 400s the whole
    request` (opened 2026-08-26):
    https://github.com/vectordotdev/vector/issues/26228

A cross-cutting pattern emerges: **record boundaries, stream isolation,
truncation, flush timeouts, and bounded buffering** are recurring production
defects in the world's most deployed collectors. These are not presentation
bugs. A merged stdout/stderr fragment corrupts severity and attribution; a
duplicated final line double-counts errors; a dropped pending multiline record
erases the stack trace that explains an incident; an unbounded buffer turns a
noisy pod into a collector OOM.

## Gap analysis against the existing Baysöz Labs portfolio

The 45 existing repositories already cover a broad, mature surface:

- telemetry semantics: `baysoz-metriccanon`, `baysoz-tailcanon`,
  `baysoz-tracecontinuity`, `baysoz-cardinalis`, `baysoz-queryoracle`;
- SLO and alerting: `baysoz-burnlattice`, `baysoz-alertpath-oracle`;
- Kubernetes policy: `baysoz-netpol-oracle`, `baysoz-routegate`,
  `baysoz-admissioncel`, `baysoz-disruption-oracle`, `baysoz-profilediff`;
- collector configuration: `baysoz-otelgate`;
- profiling and tracing: `baysoz-profilediff`, `baysoz-tracecontinuity`;
- log-related but different: `baysoz-logmask` (streaming PII/secret masking).

None of them treats **kubelet CRI line framing plus multiline record-boundary
reassembly** as a first-class oracle. `baysoz-otelgate` validates collector
configuration syntax and policy, not emitted record identity. `baysoz-logmask`
redacts content, not boundaries. `baysoz-tracecontinuity` concerns distributed
trace propagation, not container stdout/stderr multiplexing. The chosen
project therefore fills a real adjacent hole instead of cloning an existing
tool.

## Selected project

**`baysoz-cricanon`** — an offline, deterministic CRI log-stream
record-boundary and continuity oracle with SARIF CI gates.

It is deliberately positioned as a *pre-deployment and CI conformance
instrument*: teams feed captured CRI/Docker-JSON/plain log segments and two
candidate multiline policies into the CLI. The oracle reassembles `P`/`F`
fragments with stream isolation, resolves multiline boundaries with bounded
event-time flush semantics, detects duplicate emission, sequence gaps, stream
contamination, timestamp regressions, dangling partials, and buffer overflow,
then emits a stable SARIF report. A `diff` mode compares two policies against
the same corpus and reports canonical record-set divergence.

### Why this is genuinely needed in 2026-2027

1. **Collector stability work is active.** The live issues above are dated
   October and November 2026, not historical backlog.
2. **Boundaries are the shared dependency of every downstream signal.**
   Metrics derived from logs, error budgets, alert routing, and incident
   forensics all fail when a stack trace is split or duplicated.
3. **Kubernetes CRI is a protocol with subtle state.** The `P`/`F` flag and
   `stdout`/`stderr` tag create a two-dimensional state machine. Treating it
   as text lines is exactly the bug reported in Vector issue 26562.
4. **Offline verification is operationally cheap.** A fixed corpus plus a
   policy diff can run in CI without a cluster, a broker, a database, or an
   LLM. This satisfies the zero-heavy-services constraint while still testing
   production logic.
5. **The portfolio avoids duplication.** The new tool is orthogonal to
   semantic conformance, redaction, cardinality, and configuration linting.

### Rejected alternatives

- Another log masking or redaction CLI: redundant with `baysoz-logmask` and
  semantically shallow.
- Another collector config linter: redundant with `baysoz-otelgate`.
- An LLM-based incident summarizer: violates zero local LLM requirement and
  introduces nondeterminism.
- A dashboard or storage engine: violates zero heavy services.
- A generic JSON formatter: trivial and forbidden.

## Success criteria

- Zero runtime dependencies beyond Python 3.13 standard library.
- Deterministic JSON and SARIF output with explicit Baysöz Labs attribution.
- Strict bounds on file size, line size, record size, regex complexity, and
  partial buffer growth.
- Adversarial corpus coverage for stream interleaving, duplicate final lines,
  dangling partials, malformed framing, sequence gaps, and timestamp
  regressions.
- Zero findings from `pytest`, `ruff check --select E,F,W,S,B .`, and
  `semgrep --config p/default --error .`.

Research authored by Baysöz Labs <baysozlabs@proton.me>.
