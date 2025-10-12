import os
import json
import re
from typing import Any

EVENTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'events'))
PLACEHOLDERS = {
    'accountId': '111111111111',
    'recipientAccountId': '111111111111',
    'accessKeyId': 'AKIA****************',  # keep AKIA pattern for realism
    'principalId': 'AROA****************:User',
    'sourceIPAddress': '0.0.0.0',
    'ip': '0.0.0.0'
}

IP_REGEX = re.compile(r'(\b\d{1,3}(?:\.\d{1,3}){3}\b)')
ACCOUNT_REGEX = re.compile(r'arn:aws:[a-z0-9-]+::(\d{12}):')

def redact_value(key: str, value: Any):
    if value is None:
        return value
    if key in PLACEHOLDERS:
        return PLACEHOLDERS[key]
    if isinstance(value, str):
        # Replace IPs
        value = IP_REGEX.sub(PLACEHOLDERS['sourceIPAddress'], value)
        # Replace account ids embedded in arns
        def _acct_sub(m):
            return m.group(0).replace(m.group(1), PLACEHOLDERS['accountId'])
        value = ACCOUNT_REGEX.sub(_acct_sub, value)
    return value

SENSITIVE_KEYS = {"accountId", "accessKeyId", "principalId", "sourceIPAddress", "recipientAccountId"}

def walk(obj):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            v = obj[k]
            if isinstance(v, (dict, list)):
                walk(v)
            else:
                if k in SENSITIVE_KEYS:
                    obj[k] = redact_value(k, v)
                else:
                    obj[k] = redact_value(k, v)
    elif isinstance(obj, list):
        for i in range(len(obj)):
            v = obj[i]
            if isinstance(v, (dict, list)):
                walk(v)
            else:
                obj[i] = redact_value('value', v)

def is_new_event_cloudtrail(path: str) -> bool:
    # Heuristic: our newly added events include Crimson Collective incident in JSON (not in cloudtrail) but rely on list from missing file
    # Simpler: operate on any .cloudtrail file whose base name matches one of actions in action.json
    return path.endswith('.json.cloudtrail')

def main():
    modified = []
    for root, _dirs, files in os.walk(EVENTS_DIR):
        for f in files:
            if not f.endswith('.json.cloudtrail'):
                continue
            full = os.path.join(root, f)
            try:
                with open(full, 'r', encoding='utf-8') as fh:
                    text = fh.read().strip()
                data = json.loads(text)
            except Exception:
                continue
            original = json.dumps(data, sort_keys=True)
            walk(data)
            redacted = json.dumps(data, sort_keys=True)
            if redacted != original:
                with open(full, 'w', encoding='utf-8') as fh:
                    json.dump(data, fh, indent=4)
                modified.append(full)
    print(f'Redacted {len(modified)} CloudTrail files.')
    for m in modified:
        print(' -', m)

if __name__ == '__main__':
    main()
