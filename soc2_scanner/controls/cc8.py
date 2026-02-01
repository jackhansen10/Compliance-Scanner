from __future__ import annotations

from typing import Any, Dict, List, Tuple

from soc2_scanner.collectors import (
    collect_cloudtrail,
    collect_codebuild,
    collect_codepipeline,
)
from soc2_scanner.controls.context import EvidenceContext, get_cached


CONTROL_ID = "CC8"
TITLE = "Change Management"
SOURCES = ["CodePipeline", "CodeBuild", "CloudTrail"]


def evaluate(context: EvidenceContext) -> Tuple[Dict[str, Any], List[str], List[str]]:
    codepipeline_data = get_cached(
        context, "codepipeline", collect_codepipeline, context.session, context.regions
    )
    codebuild_data = get_cached(
        context, "codebuild", collect_codebuild, context.session, context.regions
    )
    cloudtrail_data = get_cached(
        context, "cloudtrail", collect_cloudtrail, context.session, context.regions
    )
    gaps: List[str] = []
    errors = codepipeline_data["errors"] + codebuild_data["errors"] + cloudtrail_data["errors"]

    if codepipeline_data["pipeline_count"] == 0 and codebuild_data["project_count"] == 0:
        gaps.append("No CodePipeline or CodeBuild projects detected.")
    if cloudtrail_data["logging_trail_count"] == 0:
        gaps.append("No CloudTrail trails are actively logging.")

    return {
        "codepipeline": codepipeline_data,
        "codebuild": codebuild_data,
        "cloudtrail": cloudtrail_data,
    }, gaps, errors
