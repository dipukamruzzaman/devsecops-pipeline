import json

with open(r'reports\sbom.cdx.json', encoding='utf-8') as f:
    sbom = json.load(f)

components = sbom.get('components', [])

print(f'Total components : {len(components)}')
print(f'Format           : CycloneDX {sbom.get("specVersion")}')
print(f'Serial number    : {sbom.get("serialNumber")}')
print()
print(f'{"Package":<30} {"Version":<15} {"License"}')
print('-' * 65)

for c in components[:15]:
    name = c.get('name', '')
    ver  = c.get('version', '?')
    lic  = ', '.join(
        l.get('license', {}).get('id', '?')
        for l in c.get('licenses', [])
    ) or 'unspecified'
    print(f'{name:<30} {ver:<15} {lic}')

print(f'... and {len(components) - 15} more components')