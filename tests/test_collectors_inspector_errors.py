import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.inspector import collect_inspector


class InspectorCollectorErrorTests(unittest.TestCase):
    def test_collect_inspector_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.inspector.safe_call") as safe_call:
            safe_call.return_value = (None, "fail")
            result = collect_inspector(session, ["us-east-1"])

        self.assertEqual(result["coverage_region_count"], 0)
        self.assertIn("inspector2:us-east-1: fail", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
