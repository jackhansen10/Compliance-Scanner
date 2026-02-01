from __future__ import annotations

"""Compatibility re-exports for analysis module consumers."""

from soc2_scanner.controls import CONTROL_REGISTRY, EvidenceContext, evaluate_control
from soc2_scanner.controls.context import status_from_findings

__all__ = ["CONTROL_REGISTRY", "EvidenceContext", "evaluate_control", "status_from_findings"]
