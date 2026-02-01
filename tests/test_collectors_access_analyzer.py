import unittest
from unittest.mock import Mock

from soc2_scanner.collectors.access_analyzer import collect_access_analyzer


class AccessAnalyzerCollectorTests(unittest.TestCase):
    def test_collect_access_analyzer_active_count(self) -> None:
        client = Mock()
        client.list_analyzers.return_value = {
            "analyzers": [
                {"name": "default", "status": "ACTIVE", "type": "ACCOUNT"}
            ]
        }

        session = Mock()
        session.client.return_value = client

        result = collect_access_analyzer(session, ["us-east-1"])
        self.assertEqual(result["analyzer_count"], 1)
        self.assertEqual(result["active_analyzer_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
