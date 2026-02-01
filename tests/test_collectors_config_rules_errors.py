import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.config_rules import collect_config_rules


class ConfigRulesCollectorErrorTests(unittest.TestCase):
    def test_collect_config_rules_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.config_rules.paginate_call") as paginate_call:
            paginate_call.return_value = ([], "denied")
            result = collect_config_rules(session, ["us-east-1"])

        self.assertEqual(result["rule_count"], 0)
        self.assertIn("config:us-east-1: denied", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
