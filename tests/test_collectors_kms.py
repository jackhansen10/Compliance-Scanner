import unittest
from unittest.mock import Mock

from soc2_scanner.collectors.kms import collect_kms


class KmsCollectorTests(unittest.TestCase):
    def test_collect_kms_rotation_counts(self) -> None:
        client = Mock()
        client.list_keys.return_value = {"Keys": [{"KeyId": "key-1"}]}
        client.describe_key.return_value = {"KeyMetadata": {"KeyState": "Enabled"}}
        client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}

        session = Mock()
        session.client.return_value = client

        result = collect_kms(session, ["us-east-1"])
        self.assertEqual(result["sampled_key_count"], 1)
        self.assertEqual(result["rotation_enabled_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
