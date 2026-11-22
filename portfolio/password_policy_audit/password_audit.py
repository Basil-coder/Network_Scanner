"""Offline password-policy audit for synthetic, non-secret policy test cases."""
import argparse
import json
import re
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 1000
ALLOWED = {'id', 'password', 'expected'}


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {'min_length', 'max_length', 'require_classes', 'blocklist'}:
        raise ValueError('policy must contain min_length, max_length, require_classes, blocklist')
    minimum, maximum = policy['min_length'], policy['max_length']
    if type(minimum) is not int or type(maximum) is not int or not 1 <= minimum <= maximum <= 1024:
        raise ValueError('invalid length limits')
    classes = policy['require_classes']
    if not isinstance(classes, list) or len(classes) != len(set(map(str, classes))) or any(c not in ('lower', 'upper', 'digit', 'symbol') for c in classes):
        raise ValueError('invalid required classes')
    blocklist = policy['blocklist']
    if not isinstance(blocklist, list) or any(not isinstance(v, str) or not v for v in blocklist) or len(blocklist) > 10000:
        raise ValueError('invalid blocklist')
    return policy


def audit_password(password, policy):
    if not isinstance(password, str):
        raise ValueError('password must be text')
    reasons = []
    if len(password) < policy['min_length']:
        reasons.append('too_short')
    if len(password) > policy['max_length']:
        reasons.append('too_long')
    checks = {
        'lower': any(c.isascii() and c.islower() for c in password),
        'upper': any(c.isascii() and c.isupper() for c in password),
        'digit': any(c.isascii() and c.isdigit() for c in password),
        'symbol': any(not c.isalnum() and not c.isspace() for c in password),
    }
    for required in policy['require_classes']:
        if not checks[required]:
            reasons.append('missing_' + required)
    if password.casefold() in {s.casefold() for s in policy['blocklist']}:
        reasons.append('blocklisted')
    return {'accepted': not reasons, 'reasons': reasons}


def audit_document(document, policy):
    if not isinstance(document, list) or len(document) > MAX_RECORDS:
        raise ValueError('expected an array of at most 1000 records')
    seen = set()
    results = []
    for record in document:
        if not isinstance(record, dict) or set(record) != {'id', 'password'}:
            raise ValueError('each record requires only id and password')
        identifier = record['id']
        if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', identifier) or identifier in seen:
            raise ValueError('invalid or duplicate synthetic id')
        seen.add(identifier)
        outcome = audit_password(record['password'], policy)
        results.append({'id': identifier, **outcome})
    return {'schema_version': 1, 'total': len(results), 'accepted': sum(r['accepted'] for r in results), 'results': results}


def read_json(path):
    p = Path(path)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError('input exceeds 1 MiB')
    return json.loads(p.read_text(encoding='utf-8'))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Audit ONLY synthetic password test fixtures offline; output never includes passwords.')
    parser.add_argument('--policy', required=True)
    parser.add_argument('--fixtures', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    policy = validate_policy(read_json(args.policy))
    result = audit_document(read_json(args.fixtures), policy)
    destination = Path(args.output)
    if destination.resolve() in {Path(args.policy).resolve(), Path(args.fixtures).resolve()}:
        parser.error('output must not overwrite inputs')
    destination.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f"Audited {result['total']} synthetic cases; {result['accepted']} accepted. Report: {destination}")


if __name__ == '__main__':
    main()
