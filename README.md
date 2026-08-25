# mcp-sinks — Semgrep ruleset for MCP server vulnerability research

A two-tier Semgrep ruleset for auditing Model Context Protocol (MCP) 
servers for security vulnerabilities. Used to discover CVE-2026-2035922 
and CVE-2026-2035999 among others.

## What it finds

**Inventory rules (WARNING)** — flags every dangerous sink so you can 
trace whether a tool argument reaches it. High recall, expect false 
positives.

**Taint rules (ERROR)** — MCP-aware taint analysis tracing tool handler 
arguments directly to dangerous sinks. Higher precision.

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
git clone https://github.com/YOUR_USERNAME/mcp-sinks
```

## Usage

```bash
# Full scan (inventory + taint)
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
```

Expected: 15 findings including 3 TAINT hits.

## CVEs found with this tool

- CVE-2026-2035922 (CVSS 9.3 Critical) — mac-shell-mcp
- CVE-2026-2035999 (CVSS 9.8 Critical) — http-oauth-mcp-server
- cmd-line-mcp (CVE pending) — newline separator bypass

## Background

Built as part of MCP security research at 
[Shroud Labs](https://shroudlabs.io). 
The MCP ecosystem is 18 months old and largely unaudited — 
the hit-rate on community servers is real.

## Author

Taran, Shroud Labs Limited  
taran@shroudlabs.io
