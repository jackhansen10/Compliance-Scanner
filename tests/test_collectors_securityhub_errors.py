import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.securityhub import collect_securityhub


class SecurityHubCollectorErrorTests(unittest.TestCase):
    def test_collect_securityhub_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.securityhub.safe_call") as safe_call:
            safe_call.return_value = (None, "no access")
            result = collect_securityhub(session, ["us-east-1"])

        self.assertEqual(result["enabled_region_count"], 0)
        self.assertIn("securityhub:us-east-1: no access", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
