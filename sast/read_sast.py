"""
Read and display Bandit SAST results.
Shows findings grouped by severity — same view as SonarQube dashboard.
"""

import json

CWE_MAP = {
    "B404": "CWE-78  OS Command Injection (subprocess import)",
    "B602": "CWE-78  OS Command Injection (shell=True)",
    "B608": "CWE-89  SQL Injection",
    "B324": "CWE-327 Broken Cryptography (MD5)",
    "B104": "CWE-605 Binding to all interfaces",
    "B105": "CWE-259 Hardcoded Password",
    "B106": "CWE-259 Hardcoded Password",
}

SONARQUBE_MAP = {
    "B602": "squid:S4721 — OS Command Injection",
    "B608": "squid:S3649 — SQL Injection",
    "B324": "squid:S4790 — Weak Hash Algorithm",
    "B104": "squid:S4823 — Binding all interfaces",
    "B404": "squid:S4721 — OS Command Injection",
}

with open(r'reports\sast-results.json', encoding='utf-8') as f:
    data = json.load(f)

results = data.get('results', [])
metrics = data.get('metrics', {})

print("=" * 60)
print("  SAST SCAN RESULTS — Bandit / SonarQube equivalent")
print("=" * 60)
print()

# Summary
total = metrics.get('_totals', {})
print("  SUMMARY:")
print(f"    Files scanned : "
      f"{len(metrics) - 1}")
print(f"    Lines of code : "
      f"{sum(m.get('loc',0) for k,m in metrics.items() if k != '_totals')}")
print(f"    HIGH issues   : {total.get('SEVERITY.HIGH', 0)}")
print(f"    MEDIUM issues : {total.get('SEVERITY.MEDIUM', 0)}")
print(f"    LOW issues    : {total.get('SEVERITY.LOW', 0)}")
print()

# Group by severity
for severity in ['HIGH', 'MEDIUM', 'LOW']:
    issues = [r for r in results
              if r.get('issue_severity') == severity]
    if not issues:
        continue

    icon = {'HIGH': '🚨', 'MEDIUM': '⚠️ ', 'LOW': 'ℹ️ '}[severity]
    print(f"  {icon} {severity} SEVERITY ({len(issues)} issues)")
    print(f"  {'-' * 50}")

    for issue in issues:
        test_id   = issue.get('test_id', '')
        test_name = issue.get('test_name', '')
        line      = issue.get('line_number', '?')
        confidence= issue.get('issue_confidence', '?')
        text      = issue.get('issue_text', '')
        code      = issue.get('code', '').strip()
        cwe       = CWE_MAP.get(test_id, '')
        sonar     = SONARQUBE_MAP.get(test_id, '')

        print(f"\n  [{test_id}] {test_name}")
        print(f"  Line       : {line} (confidence: {confidence})")
        if cwe:
            print(f"  CWE        : {cwe}")
        if sonar:
            print(f"  SonarQube  : {sonar}")
        print(f"  Finding    : {text}")
        if code:
            # show first 2 lines of code snippet
            lines = [l for l in code.splitlines() if l.strip()][:2]
            for l in lines:
                print(f"  Code       : {l.strip()}")

    print()

# Quality gate simulation
print("=" * 60)
print("  QUALITY GATE DECISION")
print("=" * 60)
high_count = total.get('SEVERITY.HIGH', 0)
med_count  = total.get('SEVERITY.MEDIUM', 0)

print(f"\n  HIGH issues  : {high_count}")
print(f"  MEDIUM issues: {med_count}")
print()

if high_count > 0:
    print("  RESULT: ✗ GATE FAILED")
    print("  HIGH severity issues found — build blocked")
    print()
    print("  Remediation required:")
    for issue in results:
        if issue.get('issue_severity') == 'HIGH':
            tid  = issue.get('test_id','')
            name = issue.get('test_name','')
            line = issue.get('line_number','?')
            print(f"    • Fix [{tid}] {name} at line {line}")
else:
    print("  RESULT: ✓ GATE PASSED")
    print("  No HIGH severity issues — build may proceed")