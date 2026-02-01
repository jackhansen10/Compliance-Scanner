import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.config import collect_config


class ConfigCollectorErrorTests(unittest.TestCase):
    def test_collect_config_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.config.safe_call") as safe_call:
            safe_call.return_value = (None, "no perms")
            result = collect_config(session, ["us-east-1"])

        self.assertEqual(result["recorder_count"], 0)
        self.assertTrue(any("no perms" in err for err in result["errors"]))


if __name__ == "__main__":
    unittest.main()
