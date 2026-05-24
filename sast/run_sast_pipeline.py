"""
Full SAST Pipeline — runs Bandit scan and applies quality gate.
Mirrors SonarQube integration at Zebra Technologies.

Usage:
    python sast\run_sast_pipeline.py
    python sast\run_sast_pipeline.py --fail-on medium
"""

import subprocess
import sys
import json
import argparse
from pathlib import Path

ROOT    = Path(__file__).parent.parent
REPORTS = ROOT / "reports"

SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW"]

CWE_MAP = {
    "B602": "CWE-78  Command Injection",
    "B608": "CWE-89  SQL Injection",
    "B324": "CWE-327 Weak Cryptography",
    "B104": "CWE-605 All Interfaces",
    "B404": "CWE-78  Subprocess Import",
}

SONARQUBE_MAP = {
    "B602": "squid:S4721",
    "B608": "squid:S3649",
    "B324": "squid:S4790",
    "B104": "squid:S4823",
    "B404": "squid:S4721",
}


def banner(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def severity_gte(actual, threshold):
    try:
        return SEVERITY_ORDER.index(actual) <= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-on", default="high",
                        choices=["high", "medium", "low"])
    args = parser.parse_args()
    threshold = args.fail_on.upper()

    print("\n" + "=" * 60)
    print("  SAST CI/CD PIPELINE")
    print("  Mirrors SonarQube integration at Zebra Technologies")
    print(f"  Threshold: {threshold}+")
    print("=" * 60)

    REPORTS.mkdir(exist_ok=True)
    output_file = REPORTS / "sast-results.json"

    # Step 1: Run Bandit scan
    banner("STEP 1/2 — Run Bandit SAST Scan")
    print(f"  Scanning: {ROOT / 'app'}")
    print("  Rules: SQL injection, command injection,")
    print("         weak crypto, hardcoded secrets, 200+ more\n")

    result = subprocess.run([
        sys.executable, "-m", "bandit",
        "-r", str(ROOT / "app"),
        "-f", "json",
        "-o", str(output_file),
        "-q",
    ], capture_output=True, text=True)

    if not output_file.exists():
        print("  ERROR: Scan failed")
        print(result.stderr)
        sys.exit(2)

    with open(output_file, encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    totals  = data.get("metrics", {}).get("_totals", {})
    high    = totals.get("SEVERITY.HIGH", 0)
    medium  = totals.get("SEVERITY.MEDIUM", 0)
    low     = totals.get("SEVERITY.LOW", 0)

    print(f"  Scan complete:")
    print(f"    Total issues : {len(results)}")
    print(f"    HIGH         : {high}")
    print(f"    MEDIUM       : {medium}")
    print(f"    LOW          : {low}")

    # Step 2: Quality gate
    banner("STEP 2/2 — Quality Gate")
    print(f"  Threshold : {threshold}+")
    print()

    blocking = [
        r for r in results
        if severity_gte(r.get("issue_severity", "LOW"), threshold)
    ]

    if blocking:
        print(f"  BLOCKING ISSUES ({len(blocking)}):")
        print()
        for issue in blocking:
            tid   = issue.get("test_id", "")
            name  = issue.get("test_name", "")
            sev   = issue.get("issue_severity", "")
            line  = issue.get("line_number", "?")
            cwe   = CWE_MAP.get(tid, "")
            sonar = SONARQUBE_MAP.get(tid, "")
            text  = issue.get("issue_text", "")[:80]

            print(f"  [{sev}] {tid} — {name}")
            print(f"    Line      : {line}")
            print(f"    CWE       : {cwe}")
            print(f"    SonarQube : {sonar}")
            print(f"    Detail    : {text}")
            print()

    # Final decision
    banner("PIPELINE COMPLETE")
    if blocking:
        print(f"  RESULT : GATE FAILED")
        print(f"  {len(blocking)} blocking issue(s) at {threshold}+")
        print(f"  Build promotion BLOCKED")
        print()
        print("  Remediation steps:")
        for issue in blocking:
            tid  = issue.get("test_id", "")
            line = issue.get("line_number", "?")
            name = issue.get("test_name", "")
            print(f"    -> Fix [{tid}] {name} at line {line}")
        print("=" * 60)
        sys.exit(1)
    else:
        print(f"  RESULT : GATE PASSED")
        print(f"  No {threshold}+ issues found")
        print(f"  Build may be promoted")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()