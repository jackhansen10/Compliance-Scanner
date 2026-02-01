"""CodeBuild evidence collector.

SOC 2 controls: CC8 (Change Management)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_codebuild(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    projects: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("codebuild", region_name=region)
        response, error = safe_call(client.list_projects)
        if error:
            errors.append(format_error("codebuild", region, error))
            continue
        for name in response.get("projects", []):
            projects.append(
                {
                    "name": name,
                    "region": region,
                }
            )

    return {
        "project_count": len(projects),
        "projects_sample": projects[:25],
        "errors": errors,
    }
