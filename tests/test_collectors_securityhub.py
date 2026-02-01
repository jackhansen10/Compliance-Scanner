import unittest
from unittest.mock import Mock

from soc2_scanner.collectors.securityhub import collect_securityhub


class SecurityHubCollectorTests(unittest.TestCase):
    def test_collect_securityhub_enabled(self) -> None:
        client = Mock()
        client.describe_hub.return_value = {"HubArn": "arn:hub"}
        client.list_enabled_products_for_import.return_value = {
            "ProductSubscriptions": ["prod-1"]
        }

        session = Mock()
        session.client.return_value = client

        result = collect_securityhub(session, ["us-east-1"])
        self.assertEqual(result["enabled_region_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
