import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from soc2_scanner.scanner import ScanConfig, run_scan


class ScannerOutputTests(unittest.TestCase):
    def test_run_scan_writes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config = ScanConfig(
                controls=["CC1"],
                regions=["us-east-1"],
                profile=None,
                output_dir=tmp_dir,
            )

            fake_session = Mock()
            fake_session.region_name = "us-east-1"

            with patch("soc2_scanner.scanner.boto3.Session", return_value=fake_session):
                with patch(
                    "soc2_scanner.scanner._get_account_identity",
                    return_value={"account_id": "123", "arn": "arn", "identity_error": None},
                ):
                    with patch("soc2_scanner.scanner.evaluate_control") as mock_eval:
                        mock_eval.return_value = {
                            "control_id": "CC1",
                            "title": "Control Environment",
                            "status": "pass",
                            "evidence_sources": [],
                            "collected_at": "now",
                            "gaps": [],
                            "errors": [],
                            "data": {},
                        }

                        result = run_scan(config)

            json_path = os.path.join(tmp_dir, "evidence.json")
            csv_path = os.path.join(tmp_dir, "evidence_summary.csv")
            hash_path = os.path.join(tmp_dir, "evidence.json.sha256")

            self.assertIn(json_path, result["artifacts"])
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(hash_path))

            with open(json_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["controls"], ["CC1"])
            self.assertEqual(payload["account_id"], "123")


if __name__ == "__main__":
    unittest.main()
