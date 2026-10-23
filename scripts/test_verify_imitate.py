import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

spec=importlib.util.spec_from_file_location("verify_imitate",Path(__file__).with_name("verify-imitate.py"))
verification=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


class FailureReporting(unittest.TestCase):
    def test_preflight_failure_keeps_four_readable_formats(self):
        with tempfile.TemporaryDirectory() as parent:
            output=verification.write_failure(Path(parent),RuntimeError('failure <script> & "测试"'))
            data=json.loads((output / "results.json").read_text(encoding="utf-8"))
            self.assertEqual((data["status"],data["exit_code"]),("tool_error",2))
            page=(output / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>",page)
            self.assertIn("&lt;script&gt;",page)
            self.assertIn("No complete acceptance claimed",page)
            self.assertIn("Exit code: 2",(output / "summary.md").read_text(encoding="utf-8"))
            self.assertEqual(ET.parse(output / "junit.xml").getroot().attrib["errors"],"1")


if __name__=="__main__":
    unittest.main()
