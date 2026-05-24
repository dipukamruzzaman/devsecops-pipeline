# DevSecOps Pipeline — SBOM + SAST + DAST

A production-grade software supply chain security pipeline demonstrating
three pillars of DevSecOps — built to reflect real enterprise implementations.

## What this demonstrates

| Pillar | Tool | Enterprise Equivalent | My Experience |
|--------|------|-----------------------|---------------|
| **SBOM** | `cyclonedx-bom` + `pip-audit` | JFrog Xray (CycloneDX) | EO14028 compliance |
| **SAST** | `bandit` | SonarQube | Zebra — CI/CD quality gates |
| **DAST** | Custom scanner | Burp Suite Professional |enterprise security platform |

## SBOM — Software Bill of Materials

Generates a CycloneDX 1.6 SBOM, scans every dependency for known CVEs,
and enforces a policy gate that mirrors JFrog Xray's behaviour.

### Why SBOM matters — EO14028
After the SolarWinds supply chain attack (2020), Executive Order 14028
mandated that all software sold to the US federal government must provide
an SBOM. At Zebra Technologies I led the technical integration of JFrog
Xray and the organisational rollout across 7,000 engineers.

### Run it

```bash
# Install tools
python -m pip install cyclonedx-bom pip-audit

# Install app dependencies
python -m pip install -r app/requirements.txt

# Run the full pipeline
python sbom/run_sbom_pipeline.py --fail-on high
```

### What it does
1. Generates a CycloneDX SBOM — inventories every component, version, license
2. Runs CVE scan — checks all dependencies against PyPA advisory database
3. Applies policy gate — blocks build promotion if CVEs exceed threshold

### Sample output
STEP 1/3 — Generate CycloneDX SBOM
✓ SBOM generated — 66 components inventoried
Format: CycloneDX 1.6
STEP 2/3 — CVE Vulnerability Scan
Packages scanned   : 17
Packages with CVEs : 5
Total CVEs found   : 33
STEP 3/3 — Policy Gate (HIGH+)
[CRITICAL] requests 2.28.2 — CVE: PYSEC-2023-74 — Fix: 2.31.0
[CRITICAL] cryptography 38.0.4 — CVE: CVE-2023-0286 — Fix: 39.0.1
[CRITICAL] pillow 9.4.0 — CVE: CVE-2023-4863 — Fix: 10.0.1
RESULT: GATE FAILED — build promotion BLOCKED

## SAST — Static Application Security Testing
*(Coming soon — Bandit / SonarQube equivalent)*

## DAST — Dynamic Application Security Testing
*(Coming soon — Burp Suite equivalent)*

## Author

**Md Kamruzzaman** — QA Lead
[dipukamruzzaman1@gmail.com](mailto:dipukamruzzaman1@gmail.com) ·
[LinkedIn](https://www.linkedin.com/in/md-kamruzzaman-sqa) ·
[Portfolio](https://mk-qa-engineer.netlify.app/) ·
[GitHub](https://github.com/dipukamruzzaman)
