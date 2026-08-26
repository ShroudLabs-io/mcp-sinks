#!/usr/bin/env python3
"""
Self-test: confirm mcp-sinks.yml fires the expected finding count against
fixtures/. Guards the README's "Expected: 18 findings, including 3 TAINT
hits" claim against silent drift as rules are added or tightened.

Usage:
    python scripts/check_fixtures.py
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "mcp-sinks.yml"
FIXTURES = ROOT / "fixtures"

EXPECTED_TOTAL = 18
EXPECTED_TAINT = 3


def main():
    r = subprocess.run(
        ["semgrep", "--config", str(RULES), str(FIXTURES),
         "--json", "--quiet", "--metrics", "off"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(r.stdout)
    results = data["results"]
    taint = [res for res in results if res["extra"]["severity"] == "ERROR"]

    print(f"total findings: {len(results)} (expected {EXPECTED_TOTAL})")
    print(f"taint (ERROR) findings: {len(taint)} (expected {EXPECTED_TAINT})")
    for res in results:
        print(f"  {res['check_id'].split('.')[-1]:<42} "
              f"{res['extra']['severity']:<8} "
              f"{res['path']}:{res['start']['line']}")

    if len(results) != EXPECTED_TOTAL or len(taint) != EXPECTED_TAINT:
        print("\nFAIL: finding count drifted from the README's self-test claim.")
        print("Update EXPECTED_TOTAL/EXPECTED_TAINT here AND the README together.")
        sys.exit(1)
    print("\nOK")


if __name__ == "__main__":
    main()
