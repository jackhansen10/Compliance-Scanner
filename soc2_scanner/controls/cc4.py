from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.collectors import collect_cloudwatch, collect_config_rules
from soc2_scanner.controls.context import EvidenceContext, get_cached


CONTROL_ID = "CC4"
TITLE = "Monitoring Activities"
SOURCES = ["AWS Config", "CloudWatch"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    config_rules_data = get_cached(
        context, "config_rules", collect_config_rules, context.session, context.regions
    )
    cloudwatch_data = get_cached(
        context, "cloudwatch", collect_cloudwatch, context.session, context.regions
    )
    gaps: List[str] = []
    errors = config_rules_data["errors"] + cloudwatch_data["errors"]

    if config_rules_data["rule_count"] == 0:
        gaps.append("No AWS Config rules detected.")
    if config_rules_data["noncompliant_count"] > 0:
        gaps.append("Non-compliant AWS Config rules detected.")
    if cloudwatch_data["alarm_count"] == 0:
        gaps.append("No CloudWatch alarms detected.")

    return {
        "config_rules": config_rules_data,
        "cloudwatch": cloudwatch_data,
    }, gaps, errors
