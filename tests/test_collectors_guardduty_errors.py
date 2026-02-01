import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.guardduty import collect_guardduty


class GuardDutyCollectorErrorTests(unittest.TestCase):
    def test_collect_guardduty_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.guardduty.safe_call") as safe_call:
            safe_call.return_value = (None, "denied")
            result = collect_guardduty(session, ["us-east-1"])

        self.assertEqual(result["detector_count"], 0)
        self.assertIn("us-east-1: denied", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
