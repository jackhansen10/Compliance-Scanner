import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.organizations import collect_organizations


class OrganizationsCollectorErrorTests(unittest.TestCase):
    def test_collect_organizations_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.organizations.safe_call") as safe_call:
            safe_call.return_value = (None, "denied")
            result = collect_organizations(session)

        self.assertEqual(result["account_count"], 0)
        self.assertTrue(any("organizations" in err for err in result["errors"]))


if __name__ == "__main__":
    unittest.main()
