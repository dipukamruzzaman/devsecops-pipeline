"""
Full SBOM Pipeline — runs all steps in sequence.
This is what the CI/CD job runs in GitHub Actions.

Usage:
    python sbom\run_sbom_pipeline.py
    python sbom\run_sbom_pipeline.py --fail-on high
"""

import subprocess
import sys
import argparse
import json
from pathlib import Path

ROOT    = Path(__file__).parent.parent
REPORTS = ROOT / "reports"


def banner(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def run(cmd, description):
    print(f"\n  Running: {description}")
    print(f"  Command: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=False)
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-on", default="critical",
                        choices=["critical", "high", "medium", "low"])
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  SBOM CI/CD PIPELINE")
    print("  Mirrors JFrog Xray integration at Zebra Technologies")
    print("=" * 60)

    REPORTS.mkdir(exist_ok=True)

    # Step 1: Generate SBOM
    banner("STEP 1/3 — Generate CycloneDX SBOM")
    code = run([
        sys.executable, "-c",
        "import sys; sys.path.insert(0, r'C:\\Users\\DD\\AppData\\Roaming"
        "\\Python\\Python311\\site-packages'); "
        "from cyclonedx_py._internal.cli import run as r; "
        "sys.argv=['cyclonedx-py','environment','--of','JSON',"
        f"'--output-file',r'{REPORTS}\\sbom.cdx.json']; r()"
    ], "cyclonedx-py environment")

    if Path(REPORTS / "sbom.cdx.json").exists():
        with open(REPORTS / "sbom.cdx.json", encoding="utf-8") as f:
            sbom = json.load(f)
        count = len(sbom.get("components", []))
        print(f"\n  ✓ SBOM generated — {count} components inventoried")
        print(f"    Format  : CycloneDX {sbom.get('specVersion')}")
        print(f"    Serial  : {sbom.get('serialNumber')}")
    else:
        print("  ✗ SBOM generation failed")
        sys.exit(2)

    # Step 2: CVE scan
    banner("STEP 2/3 — CVE Vulnerability Scan")
    code = run([
        sys.executable, "-m", "pip_audit",
        "--requirement", str(ROOT / "app" / "requirements.txt"),
        "--format", "json",
        "--output", str(REPORTS / "pip-audit.json"),
        "--skip-editable",
    ], "pip-audit CVE scan")

    with open(REPORTS / "pip-audit.json", encoding="utf-8") as f:
        audit = json.load(f)
    packages = audit.get("dependencies", [])
    total_vulns = sum(len(p.get("vulns", [])) for p in packages)
    affected = sum(1 for p in packages if p.get("vulns"))
    print(f"\n  Scan complete:")
    print(f"    Packages scanned    : {len(packages)}")
    print(f"    Packages with CVEs  : {affected}")
    print(f"    Total CVEs found    : {total_vulns}")

    # Step 3: Policy gate
    banner("STEP 3/3 — Policy Gate")
    code = run([
        sys.executable,
        str(ROOT / "sbom" / "policy_gate.py"),
        "--fail-on", args.fail_on,
    ], f"policy gate (fail-on: {args.fail_on})")

    # Final result
    banner("PIPELINE COMPLETE")
    if code == 0:
        print("  RESULT : ✓ PASSED — build may be promoted")
    else:
        print("  RESULT : ✗ FAILED — build promotion BLOCKED")
    print(f"  Reports : {REPORTS}")
    print("=" * 60)

    sys.exit(code)


if __name__ == "__main__":
    main()