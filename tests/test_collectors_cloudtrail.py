import unittest
from unittest.mock import Mock

from soc2_scanner.collectors.cloudtrail import collect_cloudtrail


class CloudTrailCollectorTests(unittest.TestCase):
    def test_collect_cloudtrail_counts_logging(self) -> None:
        cloudtrail_client = Mock()
        cloudtrail_client.describe_trails.return_value = {
            "trailList": [
                {"Name": "trail-1", "HomeRegion": "us-east-1", "IsMultiRegionTrail": True}
            ]
        }
        cloudtrail_client.get_trail_status.return_value = {"IsLogging": True}

        session = Mock()
        session.client.return_value = cloudtrail_client

        result = collect_cloudtrail(session, ["us-east-1"])
        self.assertEqual(result["trail_count"], 1)
        self.assertEqual(result["logging_trail_count"], 1)
        self.assertEqual(result["multi_region_trail_count"], 1)
        self.assertEqual(result["errors"], [])


if __name__ == "__main__":
    unittest.main()
