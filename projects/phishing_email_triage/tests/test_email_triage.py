import unittest
from email_triage import analyze


class TriageTests(unittest.TestCase):
    def test_failure_and_host_extraction(self):
        raw = b'Authentication-Results: mx.example; spf=fail; dkim=pass\nContent-Type: text/plain\n\nVisit https://login.example.test/path?token=SECRET'
        result = analyze(raw)
        self.assertEqual(result['authentication_claims_unverified'][0]['result'], 'fail')
        self.assertEqual(result['url_hosts'], [{'scheme': 'https', 'host': 'login.example.test'}])
        self.assertNotIn('SECRET', str(result))

    def test_no_auth(self):
        self.assertTrue(analyze(b'Subject: hello\n\nBody')['findings'])

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            analyze(b'x' * 2_000_001)

    def test_malformed_url(self):
        self.assertEqual(analyze(b'Subject: test\n\nhttps://[bad')['url_hosts'], [])

    def test_attachment_metadata_only(self):
        raw = (b'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="x"\n\n'
               b'--x\nContent-Type: application/x-msdownload\nContent-Disposition: attachment; filename="demo.exe"\n\n123\n--x--')
        result = analyze(raw)
        self.assertEqual(result['attachments_metadata_only'][0]['size_bytes'], 3)
        self.assertNotIn('demo.exe', str(result))


if __name__ == '__main__':
    unittest.main()
