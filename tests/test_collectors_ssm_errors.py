import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.ssm import collect_ssm


class SsmCollectorErrorTests(unittest.TestCase):
    def test_collect_ssm_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.ssm.paginate_call") as paginate_call:
            paginate_call.return_value = ([], "boom")
            result = collect_ssm(session, ["us-east-1"])

        self.assertEqual(result["managed_instance_count"], 0)
        self.assertIn("ssm:us-east-1: boom", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
