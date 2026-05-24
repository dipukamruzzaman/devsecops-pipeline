"""
SBOM Policy Gate
Reads pip-audit CVE results and enforces a severity threshold.
Mirrors JFrog Xray policy engine behaviour.

Usage:
    python sbom\policy_gate.py                   # default: fail on CRITICAL
    python sbom\policy_gate.py --fail-on high    # fail on HIGH+
    python sbom\policy_gate.py --fail-on medium  # fail on MEDIUM+
"""

import json
import sys
import argparse

# CVEs we classify as CRITICAL based on known severity ratings
# In JFrog Xray this comes from the enriched vulnerability database
CRITICAL_CVES = {
    "CVE-2023-32681",   # requests: proxy auth header leak
    "CVE-2023-0286",    # cryptography/OpenSSL: RCE
    "CVE-2023-4863",    # Pillow/libwebp: heap buffer overflow
    "CVE-2023-50447",   # Pillow: arbitrary code execution
    "CVE-2024-26130",   # cryptography: NULL pointer dereference
    "PYSEC-2023-254",   # cryptography: NULL pointer dereference
}

HIGH_CVES = {
    "CVE-2024-35195",   # requests: TLS verification bypass
    "CVE-2024-0727",    # cryptography/OpenSSL: PKCS12 DoS
    "CVE-2024-28219",   # Pillow: buffer overflow strcpy
    "CVE-2026-27205",   # flask: Vary header missing
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def get_severity(vuln_id: str, aliases: list) -> str:
    all_ids = {vuln_id} | set(aliases)
    if all_ids & CRITICAL_CVES:
        return "CRITICAL"
    elif all_ids & HIGH_CVES:
        return "HIGH"
    else:
        return "MEDIUM"


def severity_gte(actual: str, threshold: str) -> bool:
    try:
        return SEVERITY_ORDER.index(actual) <= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(description="SBOM Policy Gate")
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["critical", "high", "medium", "low"],
        help="Block build if any CVE is at this severity or above"
    )
    args = parser.parse_args()
    threshold = args.fail_on.upper()

    print("=" * 60)
    print("  SBOM POLICY GATE")
    print(f"  Threshold: {threshold}+")
    print("=" * 60)
    print()
    print("  Policy rules (mirrors JFrog Xray):")
    print("  CRITICAL -> block build immediately")
    print("  HIGH     -> block build, flag for security review")
    print("  MEDIUM   -> warn, track in dashboard")
    print("  LOW      -> pass, log for awareness")
    print()

    with open(r'reports\pip-audit.json', encoding='utf-8') as f:
        audit = json.load(f)

    packages  = audit.get('dependencies', [])
    affected  = [p for p in packages if p.get('vulns')]
    blocking  = []
    warnings  = []

    for pkg in affected:
        for v in pkg.get('vulns', []):
            vid      = v.get('id', '')
            aliases  = v.get('aliases', [])
            fix      = ', '.join(v.get('fix_versions', [])) or 'no fix'
            severity = get_severity(vid, aliases)

            entry = {
                'package':  pkg['name'],
                'version':  pkg['version'],
                'id':       vid,
                'severity': severity,
                'fix':      fix,
            }

            if severity_gte(severity, threshold):
                blocking.append(entry)
            else:
                warnings.append(entry)

    # Print blocking issues
    if blocking:
        print(f"  BLOCKING ({len(blocking)} issues at {threshold}+):")
        print()
        seen = set()
        for e in blocking:
            key = (e['package'], e['id'])
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{e['severity']}] {e['package']} {e['version']}")
            print(f"    CVE : {e['id']}")
            print(f"    Fix : upgrade to {e['fix']}")
            print()

    # Print warnings
    if warnings:
        seen = set()
        unique_warns = []
        for e in warnings:
            key = (e['package'], e['id'])
            if key not in seen:
                seen.add(key)
                unique_warns.append(e)
        print(f"  WARNINGS ({len(unique_warns)} issues below threshold):")
        for e in unique_warns:
            print(f"    [{e['severity']}] {e['package']} {e['version']} "
                  f"-- {e['id']} -- fix: {e['fix']}")
        print()

    # Gate decision
    print("=" * 60)
    if blocking:
        unique_blocking = len({(e['package'], e['id']) for e in blocking})
        print(f"  RESULT: GATE FAILED")
        print(f"  {unique_blocking} blocking issue(s) found")
        print(f"  Build promotion BLOCKED")
        print()
        print("  Remediation steps:")
        fixed = {}
        for e in blocking:
            if e['package'] not in fixed:
                fixed[e['package']] = e['fix']
        for pkg, fix in fixed.items():
            print(f"    -> upgrade {pkg} to {fix}")
        print("=" * 60)
        sys.exit(1)
    else:
        print(f"  RESULT: GATE PASSED")
        print(f"  No {threshold}+ vulnerabilities found")
        print(f"  Build may be promoted")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()