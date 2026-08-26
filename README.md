# mcp-sinks — Semgrep ruleset for MCP server vulnerability research

A two-tier Semgrep ruleset for auditing Model Context Protocol (MCP)
servers for security vulnerabilities. Used to discover CVE-2026-2035922
(mac-shell-mcp) and a newline-separator allow-list bypass in cmd-line-mcp.

## What it finds

**Inventory rules (WARNING)** — flags every dangerous sink so you can
trace whether a tool argument reaches it. High recall, expect false
positives.

**Taint rules (ERROR)** — MCP-aware taint analysis tracing tool handler
arguments directly to dangerous sinks. Higher precision.

**Audit rules** — narrow, high-confidence patterns for specific known
bypass shapes (a validator regex that omits `\n`, an `execFile`/`spawn`
call whose `shell` option isn't a hard `false`), rather than a generic
sink flag.

Covers six vulnerability classes across Python and JavaScript/TypeScript:
- OS command injection (CWE-78)
- Path traversal / sandbox escape (CWE-22)
- Server-side request forgery (CWE-918)
- SQL injection (CWE-89)
- Insecure deserialisation (CWE-502)
- Transport hygiene — 0.0.0.0 binding, TLS verification disabled

## Install

```bash
# Install Semgrep
pipx install semgrep

# Clone this repo
git clone https://github.com/ShroudLabs-io/mcp-sinks
```

## Usage

```bash
# Full scan (inventory + taint + audit)
semgrep --config mcp-sinks.yml ./target-repo

# Taint-confirmed findings only
semgrep --config mcp-sinks.yml --severity ERROR ./target-repo

# SARIF output for GHSA attachment
semgrep --config mcp-sinks.yml --sarif -o findings.sarif ./target-repo
```

## Self-test

Confirm the ruleset is working against the included fixtures:

```bash
semgrep --config mcp-sinks.yml fixtures/
# or, to also assert the exact count and fail CI on drift:
python scripts/check_fixtures.py
```

Expected: 18 findings, including 3 TAINT hits.

## Two cases worth knowing about

### The mac-shell-mcp case: `execFile` isn't automatically safe

`child_process.execFile`/`spawn` take an argv array, which is normally the
*safe* alternative to `exec` — no shell re-parses the arguments, so shell
metacharacters in them are inert. That safety is conditional on the
`shell` option staying falsy. mac-shell-mcp called
`execFileAsync(command, args, { shell: this.shell })`, where `this.shell`
defaults to `'/bin/zsh'` — always a truthy string — so the "safe" call ran
through a shell on every invocation anyway (CVE-2026-2035922, CVSS 9.3).

The original ruleset's `mcp-js-inventory-shell-exec` only matched a
*literal* `shell: true` on `spawn`/`spawnSync`, so it missed both this
call shape and `execFile` entirely — zero findings on the real vulnerable
file. `mcp-js-inventory-exec-with-shell-option` now flags
`execFile`/`execFileSync`/`spawn`/`spawnSync` whenever `shell` is present
and isn't a literal `false` — true, a path string, or a variable/property
access all count, since any of them can be truthy at runtime.

### The cmd-line-mcp case: a separator check that forgot `\n`

cmd-line-mcp's `validate_command()` blocks command-chaining by checking
`re.search(r"[|;&]", command)` before running the command via
`asyncio.create_subprocess_shell`. A POSIX shell treats a bare newline as
a statement terminator identical to `;` — so `"ls /tmp\ntouch /pwned"`
satisfies the allow-list check (the first line is a permitted command) and
the second line still executes. The general shell-exec inventory rule
already flagged the sink itself, but nothing pointed at the actual root
cause in the validator.

`mcp-py-audit-separator-missing-newline` (and a JS/TS equivalent) fires
directly on a separator/dangerous-pattern regex that enumerates shell
metacharacters without including `\n` — the exact shape of this bug,
independent of which sink the validated string eventually reaches.

## CVEs found with this tool

- CVE-2026-2035922 (CVSS 9.3 Critical) — mac-shell-mcp
- cmd-line-mcp (CVE pending) — newline separator bypass

## Background

Built as part of MCP security research at
[Shroud Labs](https://shroudlabs.io).
The MCP ecosystem is 18 months old and largely unaudited —
the hit-rate on community servers is real.

## Author

Taran, Shroud Labs Limited
taran@shroudlabs.io
