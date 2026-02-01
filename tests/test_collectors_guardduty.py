import unittest
from unittest.mock import Mock

from soc2_scanner.collectors.guardduty import collect_guardduty


class GuardDutyCollectorTests(unittest.TestCase):
    def test_collect_guardduty_enabled_detector(self) -> None:
        client = Mock()
        client.list_detectors.return_value = {"DetectorIds": ["det-1"]}
        client.get_detector.return_value = {"Status": "ENABLED"}

        session = Mock()
        session.client.return_value = client

        result = collect_guardduty(session, ["us-east-1"])
        self.assertEqual(result["detector_count"], 1)
        self.assertEqual(result["enabled_detector_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
