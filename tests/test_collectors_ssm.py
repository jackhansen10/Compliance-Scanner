import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.ssm import collect_ssm


class SsmCollectorTests(unittest.TestCase):
    def test_collect_ssm_online_count(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.ssm.paginate_call") as paginate_call:
            paginate_call.return_value = (
                [
                    {
                        "InstanceId": "i-1",
                        "PingStatus": "Online",
                        "PlatformName": "Linux",
                    }
                ],
                None,
            )
            result = collect_ssm(session, ["us-east-1"])
        self.assertEqual(result["managed_instance_count"], 1)
        self.assertEqual(result["online_instance_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
