import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.vpc import collect_vpc


class VpcCollectorErrorTests(unittest.TestCase):
    def test_collect_vpc_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.vpc.paginate_call") as paginate_call:
            paginate_call.return_value = ([], "bad")
            result = collect_vpc(session, ["us-east-1"])

        self.assertEqual(result["flow_log_count"], 0)
        self.assertIn("ec2:us-east-1: bad", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
