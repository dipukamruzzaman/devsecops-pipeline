"""
DAST Scanner — Dynamic Application Security Testing
Burp Suite Professional equivalent (open-source Python implementation)

Usage:
    python dast\run_dast.py
    python dast\run_dast.py --host localhost --port 9000
    python dast\run_dast.py --fail-on medium
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import sys
import argparse
from datetime import datetime, timezone

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]

findings = []


def add_finding(title, severity, endpoint, evidence, remediation, cwe=""):
    findings.append({
        "title":       title,
        "severity":    severity,
        "endpoint":    endpoint,
        "evidence":    evidence[:300],
        "remediation": remediation,
        "cwe":         cwe,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    })
    icons = {
        CRITICAL: "[CRITICAL]",
        HIGH:     "[HIGH]    ",
        MEDIUM:   "[MEDIUM]  ",
        LOW:      "[LOW]     ",
        INFO:     "[INFO]    ",
    }
    print(f"\n  {icons.get(severity, '[?]')} {title}")
    print(f"    Endpoint    : {endpoint}")
    print(f"    Evidence    : {evidence[:100]}")
    print(f"    Remediation : {remediation[:100]}")
    if cwe:
        print(f"    CWE         : {cwe}")


def banner(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def http_get(url, timeout=5):
    try:
        req  = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)
    except Exception as e:
        return None, str(e), {}


def http_post(url, payload, timeout=5):
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)
    except Exception as e:
        return None, str(e), {}


def test_health(base):
    banner("TEST 1 — Health Check & Reachability")
    status, body, headers = http_get(f"{base}/health")
    if status == 200:
        print(f"  Target is reachable (HTTP {status})")
        print(f"  Response: {body.strip()}")
        return True
    else:
        print(f"  ERROR: Target not reachable (status={status})")
        return False


def test_security_headers(base):
    banner("TEST 2 — Security Headers (Burp Suite: Passive Scan)")
    print("  Checking HTTP response headers for security protections\n")

    status, body, headers = http_get(f"{base}/health")
    headers_lower = {k.lower(): v for k, v in headers.items()}

    required = {
        "x-content-type-options":    "Prevents MIME-type sniffing attacks",
        "x-frame-options":           "Prevents clickjacking attacks",
        "content-security-policy":   "Prevents XSS and data injection",
        "strict-transport-security": "Enforces HTTPS connections",
        "x-xss-protection":          "Enables browser XSS filtering",
        "referrer-policy":           "Controls referrer information leakage",
    }

    for header, description in required.items():
        if header in headers_lower:
            print(f"  PRESENT : {header}")
        else:
            print(f"  MISSING : {header}")
            add_finding(
                title=f"Missing security header: {header}",
                severity=MEDIUM,
                endpoint="GET /health",
                evidence=f"Header '{header}' not present in response",
                remediation=f"Add '{header}' to all responses. {description}",
                cwe="CWE-693 Protection Mechanism Failure",
            )


def test_sql_injection(base):
    banner("TEST 3 — SQL Injection (Burp Suite: Active Scan)")
    print("  Sending SQL injection payloads to test input handling\n")
    print("  CWE-89: Improper Neutralisation of Special Elements in SQL\n")

    payloads = [
        ("' OR '1'='1",             "Classic OR bypass"),
        ("' OR '1'='1'--",          "Comment bypass"),
        ("'; SELECT * FROM users--", "UNION attack"),
        ("' AND SLEEP(2)--",         "Time-based blind"),
        ("admin'--",                 "Auth bypass"),
    ]

    endpoint = f"{base}/api/devices"
    for payload, description in payloads:
        encoded = urllib.parse.quote(payload)
        url     = f"{endpoint}?status={encoded}"
        status, body, _ = http_get(url)

        sql_errors = ["sqlite", "syntax error", "sql", "select", "from", "where"]
        error_leaked  = any(err in body.lower() for err in sql_errors)
        data_returned = status == 200 and len(body) > 20 and "devices" in body
        vulnerable    = error_leaked or data_returned

        status_label = "VULNERABLE" if vulnerable else "blocked  "
        print(f"  [{status_label}] {description:<30} payload: {payload[:30]}")

        if vulnerable:
            add_finding(
                title="SQL Injection — confirmed exploitable",
                severity=CRITICAL,
                endpoint="GET /api/devices?status=<payload>",
                evidence=(
                    f"Payload '{payload}' returned HTTP {status} "
                    f"with {len(body)} bytes."
                ),
                remediation=(
                    "Use parameterised queries: "
                    "conn.execute('SELECT * FROM devices "
                    "WHERE status=?', (status_filter,))"
                ),
                cwe="CWE-89 SQL Injection",
            )
            break


def test_command_injection(base):
    banner("TEST 4 — Command Injection (Burp Suite: Active Scan)")
    print("  Sending OS command injection payloads\n")
    print("  CWE-78: Improper Neutralisation of OS Commands\n")

    payloads = [
        ("localhost & whoami",   "Windows chaining (&)"),
        ("localhost && whoami",  "Windows chaining (&&)"),
        ("localhost | whoami",   "Pipe to command"),
        ("localhost; whoami",    "Unix semicolon"),
        ("localhost%0awhoami",   "Newline injection"),
    ]

    endpoint = f"{base}/api/ping"
    for payload, description in payloads:
        encoded = urllib.parse.quote(payload)
        url     = f"{endpoint}?host={encoded}"
        status, body, _ = http_get(url)

        cmd_indicators = [
            "nt authority", "system32", "windows",
            "administrator", "program files",
            "uid=", "root", "bin/sh", "/home/",
            "desktop", "access denied",
        ]
        vulnerable = (
            status == 200 and
            any(ind.lower() in body.lower() for ind in cmd_indicators)
        )

        status_label = "VULNERABLE" if vulnerable else "blocked  "
        print(f"  [{status_label}] {description:<30} payload: {payload[:30]}")

        if vulnerable:
            snippet = body[:150].replace('\n', ' ')
            add_finding(
                title="OS Command Injection — confirmed exploitable",
                severity=CRITICAL,
                endpoint="GET /api/ping?host=<payload>",
                evidence=f"Payload '{payload}' executed. Response: {snippet}",
                remediation=(
                    "1. Use shell=False with list args "
                    "2. Whitelist allowed hosts "
                    "3. Validate all input"
                ),
                cwe="CWE-78 OS Command Injection",
            )
            break


def test_authentication(base):
    banner("TEST 5 — Authentication Testing (Burp Suite: Auth Scan)")
    print("  Testing for default credentials and weak tokens\n")

    default_creds = [
        ("admin", "password"),
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", ""),
        ("root",  "root"),
        ("test",  "test"),
        ("guest", "guest"),
    ]

    print("  Testing default credentials:")
    for username, password in default_creds:
        status, body, _ = http_post(
            f"{base}/api/login",
            {"username": username, "password": password}
        )
        if status == 200 and "token" in body:
            print(f"  ACCEPTED : {username} / "
                  f"{'(empty)' if not password else password}")
            add_finding(
                title="Default credentials accepted",
                severity=HIGH,
                endpoint="POST /api/login",
                evidence=(
                    f"Credentials {username}/"
                    f"{password or '(empty)'} "
                    f"returned HTTP 200 with token"
                ),
                remediation=(
                    "Remove default accounts. "
                    "Enforce strong passwords. "
                    "Implement account lockout."
                ),
                cwe="CWE-521 Weak Password Requirements",
            )
        else:
            print(f"  rejected : {username} / "
                  f"{'(empty)' if not password else password}")

    print("\n  Testing token security:")
    status, body, _ = http_post(
        f"{base}/api/login",
        {"username": "admin", "password": "password"}
    )
    if status == 200:
        try:
            token = json.loads(body).get("token", "")
            if token and len(token) <= 32:
                print(f"  WEAK TOKEN: length={len(token)} (appears MD5-based)")
                add_finding(
                    title="Weak authentication token (MD5-based)",
                    severity=HIGH,
                    endpoint="POST /api/login",
                    evidence=(
                        f"Token length={len(token)}, "
                        f"appears to be MD5 hash: {token[:16]}..."
                    ),
                    remediation=(
                        "Use secrets.token_hex(32) or JWT with RS256. "
                        "Never use MD5 for tokens."
                    ),
                    cwe="CWE-330 Insufficient Random Values",
                )
            else:
                print(f"  Token length={len(token)} — acceptable")
        except Exception:
            pass


def test_info_disclosure(base):
    banner("TEST 6 — Information Disclosure (Burp Suite: Passive Scan)")
    print("  Checking for sensitive information in responses\n")

    status, body, _ = http_get(f"{base}/api/version")
    if status == 200:
        try:
            data = json.loads(body)
            if data.get("debug") is True:
                print("  FOUND: debug=true in API response")
                add_finding(
                    title="Debug mode enabled in API response",
                    severity=MEDIUM,
                    endpoint="GET /api/version",
                    evidence=f"Response contains debug=true: {body[:100]}",
                    remediation="Remove debug flag from production responses.",
                    cwe="CWE-489 Active Debug Code",
                )
            else:
                print("  OK: no debug flag in response")
        except Exception:
            pass

    status, body, _ = http_get(f"{base}/api/doesnotexist-xyz")
    if "traceback" in body.lower() or "exception" in body.lower():
        print("  FOUND: stack trace in error response")
        add_finding(
            title="Stack trace exposed in error response",
            severity=MEDIUM,
            endpoint="GET /api/doesnotexist-xyz",
            evidence=f"HTTP {status}: {body[:100]}",
            remediation="Return generic error messages only.",
            cwe="CWE-209 Information Exposure via Error Message",
        )
    else:
        print(f"  OK: 404 handled cleanly (HTTP {status})")


def policy_gate(fail_on):
    banner(f"POLICY GATE (fail-on: {fail_on.upper()}+)")

    counts = {}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n  Total findings : {len(findings)}")
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0):
            print(f"  {sev:<10} : {counts[sev]}")

    fail_on_upper   = fail_on.upper()
    threshold_index = SEVERITY_ORDER.index(fail_on_upper)

    blocking = []
    for f in findings:
        try:
            finding_index = SEVERITY_ORDER.index(f["severity"].upper())
            if finding_index <= threshold_index:
                blocking.append(f)
        except ValueError:
            pass

    print()
    if not blocking:
        print(f"  RESULT: GATE PASSED")
        print(f"  No {fail_on_upper}+ findings")
        return True

    print(f"  RESULT: GATE FAILED")
    print(f"  {len(blocking)} blocking finding(s) at {fail_on_upper}+")
    print(f"  Build promotion BLOCKED")
    print()
    print("  Blocking findings:")
    seen = set()
    for f in blocking:
        key = f["title"]
        if key in seen:
            continue
        seen.add(key)
        print(f"    [{f['severity']}] {f['title']}")
        print(f"      Endpoint : {f['endpoint']}")
        print(f"      Fix      : {f['remediation'][:80]}")
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",    default="localhost")
    parser.add_argument("--port",    type=int, default=9000)
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low"])
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"

    print("\n" + "=" * 60)
    print("  DAST PIPELINE — Burp Suite equivalent")
    print(f"  Target  : {base}")
    print(f"  Fail on : {args.fail_on.upper()}+")
    print("=" * 60)
    print()
    print("  NOTE: DAST tests the RUNNING application.")
    print("  Make sure app.py is running in another terminal.")

    if not test_health(base):
        print("\n  ERROR: App not reachable. Start it first:")
        print("  python app\\app.py")
        sys.exit(2)

    test_security_headers(base)
    test_sql_injection(base)
    test_command_injection(base)
    test_authentication(base)
    test_info_disclosure(base)

    gate_passed = policy_gate(args.fail_on)

    banner("PIPELINE COMPLETE")
    print(f"  Findings    : {len(findings)}")
    print(f"  Policy gate : {'PASSED' if gate_passed else 'FAILED'}")
    print("=" * 60)

    sys.exit(0 if gate_passed else 1)


if __name__ == "__main__":
    main()