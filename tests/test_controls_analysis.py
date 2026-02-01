import unittest
from unittest.mock import Mock

from soc2_scanner.controls import CONTROL_REGISTRY, EvidenceContext, evaluate_control


class ControlAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = Mock()
        self.context = EvidenceContext(session=self.session, regions=["us-east-1"])
        self._original_evaluators = {
            control_id: data["evaluator"]
            for control_id, data in CONTROL_REGISTRY.items()
        }

    def tearDown(self) -> None:
        for control_id, evaluator in self._original_evaluators.items():
            CONTROL_REGISTRY[control_id]["evaluator"] = evaluator

    def test_unknown_control_returns_not_implemented(self) -> None:
        result = evaluate_control("CC999", self.context)
        self.assertEqual(result["status"], "not_implemented")
        self.assertIn("No evidence collector implemented", result["gaps"][0])

    def test_status_prioritizes_errors_over_gaps(self) -> None:
        control = CONTROL_REGISTRY["CC1"]
        control["evaluator"] = Mock(return_value=({}, ["gap"], ["error"]))
        result = evaluate_control("CC1", self.context)
        self.assertEqual(result["status"], "needs_review")

    def test_status_pass_when_no_gaps_or_errors(self) -> None:
        control = CONTROL_REGISTRY["CC2"]
        control["evaluator"] = Mock(return_value=({}, [], []))
        result = evaluate_control("CC2", self.context)
        self.assertEqual(result["status"], "pass")


if __name__ == "__main__":
    unittest.main()
