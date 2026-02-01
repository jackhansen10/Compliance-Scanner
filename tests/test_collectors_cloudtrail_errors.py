import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.cloudtrail import collect_cloudtrail


class CloudTrailCollectorErrorTests(unittest.TestCase):
    def test_collect_cloudtrail_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.cloudtrail.safe_call") as safe_call:
            safe_call.return_value = (None, "boom")
            result = collect_cloudtrail(session, ["us-east-1"])

        self.assertEqual(result["trail_count"], 0)
        self.assertIn("us-east-1: boom", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
