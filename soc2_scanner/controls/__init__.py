from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from soc2_scanner.controls import cc1, cc2, cc3, cc4, cc5, cc6, cc7, cc8
from soc2_scanner.controls.context import EvidenceContext, status_from_findings


CONTROL_REGISTRY: Dict[str, Dict[str, Any]] = {
    cc1.CONTROL_ID: {
        "title": cc1.TITLE,
        "sources": cc1.SOURCES,
        "evaluator": cc1.evaluate,
    },
    cc2.CONTROL_ID: {
        "title": cc2.TITLE,
        "sources": cc2.SOURCES,
        "evaluator": cc2.evaluate,
    },
    cc3.CONTROL_ID: {
        "title": cc3.TITLE,
        "sources": cc3.SOURCES,
        "evaluator": cc3.evaluate,
    },
    cc4.CONTROL_ID: {
        "title": cc4.TITLE,
        "sources": cc4.SOURCES,
        "evaluator": cc4.evaluate,
    },
    cc5.CONTROL_ID: {
        "title": cc5.TITLE,
        "sources": cc5.SOURCES,
        "evaluator": cc5.evaluate,
    },
    cc6.CONTROL_ID: {
        "title": cc6.TITLE,
        "sources": cc6.SOURCES,
        "evaluator": cc6.evaluate,
    },
    cc7.CONTROL_ID: {
        "title": cc7.TITLE,
        "sources": cc7.SOURCES,
        "evaluator": cc7.evaluate,
    },
    cc8.CONTROL_ID: {
        "title": cc8.TITLE,
        "sources": cc8.SOURCES,
        "evaluator": cc8.evaluate,
    },
}


def evaluate_control(control: str, context: EvidenceContext) -> Dict[str, Any]:
    definition = CONTROL_REGISTRY.get(control)
    if not definition:
        return {
            "control_id": control,
            "status": "not_implemented",
            "evidence_sources": [],
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "gaps": ["No evidence collector implemented for this control."],
            "errors": [],
            "data": {},
        }

    data, gaps, errors = definition["evaluator"](context)
    status = status_from_findings(gaps, errors)

    return {
        "control_id": control,
        "title": definition["title"],
        "status": status,
        "evidence_sources": definition["sources"],
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "gaps": gaps,
        "errors": errors,
        "data": data,
    }


__all__ = ["CONTROL_REGISTRY", "EvidenceContext", "evaluate_control"]
