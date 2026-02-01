import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.codebuild import collect_codebuild


class CodeBuildCollectorErrorTests(unittest.TestCase):
    def test_collect_codebuild_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.codebuild.safe_call") as safe_call:
            safe_call.return_value = (None, "denied")
            result = collect_codebuild(session, ["us-east-1"])

        self.assertEqual(result["project_count"], 0)
        self.assertIn("codebuild:us-east-1: denied", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
