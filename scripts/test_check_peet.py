import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("check_peet", Path(__file__).with_name("check-peet.py"))
peet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peet)


class PeetReporting(unittest.TestCase):
    def test_body_read_failure_retains_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            (out / "observations").mkdir()
            name = peet.PEET_CASES[0]
            (out / "observations" / (name + ".json")).write_text(json.dumps({
                "status": "fail", "error": "unexpected EOF", "error_stage": "body_read",
                "protocol": "HTTP/2.0", "body_bytes": 7, "content_length": 100,
                "automatically_decompressed": False}), encoding="utf-8")
            results = peet.peet_results(out, json.dumps({"Test": name, "Action": "fail"}), 1, 10)
            self.assertEqual(results[0]["status"], "fail")
            for part in ("unexpected EOF", "stage=body_read", "bytes_read=7", "content_length=100", "HTTP/2.0"):
                self.assertIn(part, results[0]["message"])

    def test_missing_skipped_or_malformed_evidence_never_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            for action in ("pass", "skip"):
                output = "\n".join(json.dumps({"Test": name, "Action": action}) for name in peet.PEET_CASES)
                results = peet.peet_results(out, output, 0, 5)
                self.assertFalse(any(x["status"] == "pass" for x in results))
            (out / "observations").mkdir()
            for name in peet.PEET_CASES:
                (out / "observations" / (name.replace("/", "-") + ".json")).write_text("invalid", encoding="utf-8")
            results = peet.peet_results(out, "not json", 2, 5)
            self.assertTrue(all(x["status"] == "error" for x in results))

    def test_process_failure_is_not_hidden_by_passed_cases(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            (out / "observations").mkdir()
            for name in peet.PEET_CASES:
                (out / "observations" / (name.replace("/", "-") + ".json")).write_text(json.dumps({"status": "pass", "endpoint": peet.ENDPOINT, "http_status": 200, "observed": {"tls": {"ja3": "771,4865,0,29,"}}}), encoding="utf-8")
            output = "\n".join(json.dumps({"Test": name, "Action": "pass"}) for name in peet.PEET_CASES)
            results = peet.peet_results(out, output, 1, 5)
            self.assertEqual(results[-1]["step"]["id"], "peet.package")
            self.assertEqual(results[-1]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
