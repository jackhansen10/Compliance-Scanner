from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.collectors import collect_cloudtrail, collect_config, collect_ssm
from soc2_scanner.controls.context import EvidenceContext, get_cached


CONTROL_ID = "CC7"
TITLE = "System Operations"
SOURCES = ["AWS Config", "SSM", "CloudTrail"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    config_data = get_cached(context, "config", collect_config, context.session, context.regions)
    ssm_data = get_cached(context, "ssm", collect_ssm, context.session, context.regions)
    cloudtrail_data = get_cached(
        context, "cloudtrail", collect_cloudtrail, context.session, context.regions
    )
    gaps: List[str] = []
    errors = config_data["errors"] + ssm_data["errors"] + cloudtrail_data["errors"]

    if config_data["recording_count"] == 0:
        gaps.append("AWS Config is not recording in any provided region.")
    if ssm_data["managed_instance_count"] == 0:
        gaps.append("No SSM managed instances detected.")
    if cloudtrail_data["logging_trail_count"] == 0:
        gaps.append("No CloudTrail trails are actively logging.")

    return {
        "config": config_data,
        "ssm": ssm_data,
        "cloudtrail": cloudtrail_data,
    }, gaps, errors
