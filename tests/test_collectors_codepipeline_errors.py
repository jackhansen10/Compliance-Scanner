import unittest
from unittest.mock import Mock, patch

from soc2_scanner.collectors.codepipeline import collect_codepipeline


class CodePipelineCollectorErrorTests(unittest.TestCase):
    def test_collect_codepipeline_errors_collected(self) -> None:
        session = Mock()
        session.client.return_value = Mock()

        with patch("soc2_scanner.collectors.codepipeline.safe_call") as safe_call:
            safe_call.return_value = (None, "denied")
            result = collect_codepipeline(session, ["us-east-1"])

        self.assertEqual(result["pipeline_count"], 0)
        self.assertIn("codepipeline:us-east-1: denied", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
