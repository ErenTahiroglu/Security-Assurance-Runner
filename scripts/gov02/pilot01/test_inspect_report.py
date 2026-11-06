"""Only invented, nonfunctional report data; no native scanner process."""
import json
import unittest
from inspect_report import inspect_bytes

def fixture(rule="sar-pilot-inert-rule",file="/input/positive.txt"):
    return json.dumps([{"RuleID":rule,"File":file,"StartLine":1,"EndLine":1,
                        "StartColumn":1,"EndColumn":23,
                        "Secret":"REDACTED", "Match":"REDACTED",
                        "Fingerprint":f"{file}:sar-pilot-inert-rule:1"}]).encode()

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
    def test_sensitive_values_must_match_exact_redaction(self):
        for field in ("Secret", "Match"):
            for value in ("", "unrelated", "SAR_INERT_DEMO_ABCD1234", "REDACTED-suffix"):
                data=json.loads(fixture())
                data[0][field]=value
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError) as error: inspect_bytes(json.dumps(data).encode())
                    self.assertNotIn(value, str(error.exception)) if value else None
    def test_fixture_location_and_fingerprint_required(self):
        for field,value in (("StartLine",0),("EndLine",2),("StartColumn",0),("EndColumn",0),
                            ("StartColumn",30),("Fingerprint",""),("Fingerprint",42),
                            ("Fingerprint","unexpected"),("Commit","unexpected")):
            data=json.loads(fixture())
            data[0][field]=value
            with self.subTest(field=field,value=value):
                with self.assertRaises(ValueError): inspect_bytes(json.dumps(data).encode())
        for field in ("EndLine","StartColumn","EndColumn","Fingerprint","Secret","Match"):
            data=json.loads(fixture())
            del data[0][field]
            with self.subTest(missing=field):
                with self.assertRaises(ValueError): inspect_bytes(json.dumps(data).encode())
    def test_private_values_never_appear_in_receipt_or_error(self):
        marker="SAR_INERT_DEMO_ABCD1234"
        receipt=inspect_bytes(fixture())
        self.assertNotIn(marker,json.dumps(receipt))
        for field in ("RuleID","File","Fingerprint","Secret","Match"):
            data=json.loads(fixture())
            data[0][field]=marker
            try:
                result=inspect_bytes(json.dumps(data).encode())
                self.assertNotIn(marker,json.dumps(result))
            except ValueError as error:
                self.assertNotIn(marker,str(error))
if __name__=="__main__":unittest.main()
