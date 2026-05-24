import json

with open(r'reports\pip-audit.json', encoding='utf-8') as f:
    audit = json.load(f)

print(f'Type: {type(audit)}')
print()

if isinstance(audit, dict):
    print('Keys:', list(audit.keys()))
    print()
    # show first entry
    for key, val in audit.items():
        print(f'{key}: {str(val)[:200]}')
        print()
elif isinstance(audit, list):
    print(f'List length: {len(audit)}')
    print('First item type:', type(audit[0]))
    print('First item:', str(audit[0])[:300])