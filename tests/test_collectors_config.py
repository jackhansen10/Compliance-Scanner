import unittest
from unittest.mock import Mock

from soc2_scanner.collectors.config import collect_config


class ConfigCollectorTests(unittest.TestCase):
    def test_collect_config_recording(self) -> None:
        client = Mock()
        client.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{"name": "default"}]
        }
        client.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [
                {"name": "default", "recording": True, "lastStatus": "SUCCESS"}
            ]
        }
        client.describe_delivery_channels.return_value = {
            "DeliveryChannels": [{"name": "default"}]
        }

        session = Mock()
        session.client.return_value = client

        result = collect_config(session, ["us-east-1"])
        self.assertEqual(result["recorder_count"], 1)
        self.assertEqual(result["recording_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
