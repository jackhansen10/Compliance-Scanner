import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.waf import collect_waf


class WafCollectorErrorTests(unittest.TestCase):
    def test_collect_waf_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.waf.safe_call") as safe_call:
            safe_call.return_value = (None, "no perms")
            result = collect_waf(session, ["us-east-1"])

        self.assertEqual(result["web_acl_count"], 0)
        self.assertIn("wafv2:us-east-1: no perms", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
