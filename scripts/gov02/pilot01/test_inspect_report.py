"""Only invented, nonfunctional report data; no native scanner process."""
import json
import unittest
from inspect_report import inspect_bytes

def fixture(rule="sar-pilot-inert-rule",file="/input/positive.txt"):
    return json.dumps([{"RuleID":rule,"File":file,"StartLine":1,
                        "Secret":"SAR_INERT_DEMO_ABCD1234",
                        "Match":"SAR_INERT_DEMO_ABCD1234",
                        "Fingerprint":"FAKE-CORRELATION-ONLY"}]).encode()

class PilotReportTests(unittest.TestCase):
    def test_expected_inert_finding_is_redacted(self):
        receipt=inspect_bytes(fixture())
        self.assertEqual(receipt["findings"],1)
        self.assertTrue(receipt["synthetic_only"])
        self.assertFalse(receipt["operational_pass"])
        self.assertNotIn("INERT_DEMO",str(receipt))
    def test_wrong_rule_and_file_refuse(self):
        for data in [fixture(rule="malicious"),fixture(file="/input/negative.txt")]:
            with self.assertRaises(ValueError): inspect_bytes(data)
    def test_missing_empty_multiple_and_null_refuse(self):
        for data in [b"",b"[]",b"null",b"[{},{}]",b"{}"]:
            with self.assertRaises(ValueError): inspect_bytes(data)
    def test_duplicate_json_keys_refuse(self):
        with self.assertRaises(ValueError):
            inspect_bytes(b'[{"RuleID":"a","RuleID":"b"}]')
    def test_truncated_oversized_and_bad_utf8_refuse(self):
        for data in [b"[",b"\xff",b" "*65537]:
            with self.assertRaises(ValueError): inspect_bytes(data)
    def test_missing_sensitive_fields_refuse(self):
        with self.assertRaises(ValueError):
            inspect_bytes(b'[{"RuleID":"sar-pilot-inert-rule","File":"/input/positive.txt","StartLine":1}]')
if __name__=="__main__":unittest.main()
