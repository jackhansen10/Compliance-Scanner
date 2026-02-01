import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.backup import collect_backup


class BackupCollectorErrorTests(unittest.TestCase):
    def test_collect_backup_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.backup.safe_call") as safe_call:
            safe_call.return_value = (None, "no perms")
            result = collect_backup(session, ["us-east-1"])

        self.assertEqual(result["backup_plan_count"], 0)
        self.assertIn("backup:us-east-1: no perms", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
