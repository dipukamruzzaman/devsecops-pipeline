import json

with open(r'reports\pip-audit.json', encoding='utf-8') as f:
    audit = json.load(f)

packages = audit.get('dependencies', [])
total_vulns = sum(len(pkg.get('vulns', [])) for pkg in packages)
affected    = [p for p in packages if p.get('vulns')]

print(f'Total vulnerabilities : {total_vulns}')
print(f'Packages affected     : {len(affected)}')
print()

for pkg in affected:
    vulns = pkg.get('vulns', [])
    print(f'PACKAGE: {pkg["name"]} {pkg["version"]}')
    print('-' * 60)

    for v in vulns:
        vid     = v.get('id', '')
        fix     = ', '.join(v.get('fix_versions', [])) or 'no fix available'
        desc    = v.get('description', '')[:120]
        aliases = ', '.join(v.get('aliases', [])[:2])
        print(f'  ID      : {vid}')
        if aliases:
            print(f'  Aliases : {aliases}')
        print(f'  Fix in  : {fix}')
        print(f'  Detail  : {desc}')
        print()

    print()