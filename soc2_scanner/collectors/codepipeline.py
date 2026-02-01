"""CodePipeline evidence collector.

SOC 2 controls: CC8 (Change Management)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_codepipeline(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    pipelines: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("codepipeline", region_name=region)
        response, error = safe_call(client.list_pipelines)
        if error:
            errors.append(format_error("codepipeline", region, error))
            continue
        for pipeline in response.get("pipelines", []):
            state, state_error = safe_call(
                client.get_pipeline_state, name=pipeline.get("name")
            )
            if state_error:
                errors.append(format_error("codepipeline", region, state_error))
            pipelines.append(
                {
                    "name": pipeline.get("name"),
                    "region": region,
                    "latest_execution_status": (
                        state.get("stageStates", [{}])[0]
                        .get("latestExecution", {})
                        .get("status")
                        if state
                        else None
                    ),
                }
            )

    return {
        "pipeline_count": len(pipelines),
        "pipelines_sample": pipelines[:25],
        "errors": errors,
    }
