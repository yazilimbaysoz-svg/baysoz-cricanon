# Security Policy — Baysöz Labs <baysozlabs@proton.me>

## Supported versions

Security fixes are applied to the current `0.1.x` line and to `main`.

## Reporting

Report security issues privately to **baysozlabs@proton.me**. Include the
affected version, a minimal reproduction, and the expected versus observed
behavior. Do not open a public issue for an unpatched vulnerability.

## Threat model

`baysoz-cricanon` parses untrusted log captures and untrusted JSON policies in
CI. The following are in scope:

- policy files that attempt to smuggle executable behavior through regexes;
- adversarial log lines designed to cause unbounded buffering or catastrophic
  backtracking;
- oversized files that exhaust CI runner memory;
- path traversal in directory expansion;
- report injection through control characters in captured payloads.

## Mitigations

- Policies are parsed with `json.loads` only. No Python expressions, imports,
  shell commands, or plugins are accepted from policy files.
- Regex patterns are limited to 256 characters, one unbounded repetition, no
  backreferences, and must compile under Python 3.13.
- Every file is size-checked before reading. Lines, partial buffers, and
  multiline groups have explicit byte and line limits.
- Directory expansion skips symlinks and restricts suffixes.
- Findings truncate evidence payloads to 120 characters.
- Output is UTF-8 JSON or text with stable key ordering. No HTML is generated.

## Quality gates

Every change must pass:

```text
uv run pytest -q
uv run ruff check --select E,F,W,S,B .
uv run semgrep --config p/default --error .
```

## Scope exclusions

The tool does not redact secrets from captured logs by default. Do not publish
raw SARIF or JSON reports if the input corpus contains credentials; use the
existing `baysoz-logmask` tool upstream if masking is required.

Security contact: Baysöz Labs <baysozlabs@proton.me>.
