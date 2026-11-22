import unittest
from password_audit import audit_document, audit_password, validate_policy

POLICY = {'min_length': 12, 'max_length': 64, 'require_classes': ['lower', 'upper', 'digit'], 'blocklist': ['KnownBadPassword123']}

class AuditTests(unittest.TestCase):
    def setUp(self):
        self.policy = validate_policy(POLICY)

    def test_valid(self):
        self.assertTrue(audit_password('ExamplePassphrase2026', self.policy)['accepted'])

    def test_short(self):
        self.assertIn('too_short', audit_password('Ab3', self.policy)['reasons'])

    def test_missing_class(self):
        self.assertIn('missing_digit', audit_password('OnlyLettersHere', self.policy)['reasons'])

    def test_blocklist_casefold(self):
        self.assertIn('blocklisted', audit_password('knownbadpassword123', self.policy)['reasons'])

    def test_never_output_password(self):
        report = audit_document([{'id': 'demo', 'password': 'ExamplePassphrase2026'}], self.policy)
        self.assertNotIn('ExamplePassphrase2026', str(report))

    def test_duplicate_id(self):
        with self.assertRaises(ValueError):
            audit_document([{'id': 'x', 'password': 'abc'}, {'id': 'x', 'password': 'def'}], self.policy)

    def test_bad_id(self):
        with self.assertRaises(ValueError):
            audit_document([{'id': 'someone@example.com', 'password': 'abc'}], self.policy)

    def test_bad_policy_bool(self):
        with self.assertRaises(ValueError):
            validate_policy({**POLICY, 'min_length': True})

    def test_bad_policy_class(self):
        with self.assertRaises(ValueError):
            validate_policy({**POLICY, 'require_classes': ['admin']})

    def test_max_length(self):
        self.assertIn('too_long', audit_password('X' * 65, self.policy)['reasons'])

    def test_empty_cases(self):
        self.assertEqual(audit_document([], self.policy)['total'], 0)

    def test_invalid_document(self):
        with self.assertRaises(ValueError):
            audit_document({'password': 'foo'}, self.policy)

if __name__ == '__main__':
    unittest.main()
