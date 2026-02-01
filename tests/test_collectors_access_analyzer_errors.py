import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.access_analyzer import collect_access_analyzer


class AccessAnalyzerCollectorErrorTests(unittest.TestCase):
    def test_collect_access_analyzer_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.access_analyzer.safe_call") as safe_call:
            safe_call.return_value = (None, "access denied")
            result = collect_access_analyzer(session, ["us-east-1"])

        self.assertEqual(result["analyzer_count"], 0)
        self.assertIn("accessanalyzer:us-east-1: access denied", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
