from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

import boto3


@dataclass
class EvidenceContext:
    session: boto3.Session
    regions: List[str]
    cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def get_cached(
    context: EvidenceContext,
    key: str,
    collector: Callable[..., Dict[str, Any]],
    *args: Any,
) -> Dict[str, Any]:
    if key not in context.cache:
        context.cache[key] = collector(*args)
    return context.cache[key]


def status_from_findings(gaps: List[str], errors: List[str]) -> str:
    if errors:
        return "needs_review"
    if gaps:
        return "fail"
    return "pass"
