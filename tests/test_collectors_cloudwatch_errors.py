import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.cloudwatch import collect_cloudwatch


class CloudWatchCollectorErrorTests(unittest.TestCase):
    def test_collect_cloudwatch_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.cloudwatch.paginate_call") as paginate_call:
            paginate_call.return_value = ([], "oops")
            result = collect_cloudwatch(session, ["us-east-1"])

        self.assertEqual(result["alarm_count"], 0)
        self.assertIn("cloudwatch:us-east-1: oops", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
