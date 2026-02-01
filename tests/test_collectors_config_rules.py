import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.config_rules import collect_config_rules


class ConfigRulesCollectorTests(unittest.TestCase):
    def test_collect_config_rules_empty(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.config_rules.paginate_call") as paginate_call:
            paginate_call.return_value = ([], None)
            result = collect_config_rules(session, ["us-east-1"])

        self.assertEqual(result["rule_count"], 0)
        self.assertEqual(result["noncompliant_count"], 0)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
