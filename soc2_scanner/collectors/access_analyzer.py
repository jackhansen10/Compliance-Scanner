"""IAM Access Analyzer evidence collector.

SOC 2 controls: CC6 (Logical and Physical Access)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_access_analyzer(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    analyzers: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("accessanalyzer", region_name=region)
        response, error = safe_call(client.list_analyzers, type="ACCOUNT")
        if error:
            errors.append(format_error("accessanalyzer", region, error))
            continue
        for analyzer in response.get("analyzers", []):
            analyzers.append(
                {
                    "name": analyzer.get("name"),
                    "region": region,
                    "status": analyzer.get("status"),
                    "type": analyzer.get("type"),
                }
            )

    return {
        "analyzer_count": len(analyzers),
        "active_analyzer_count": sum(
            1 for analyzer in analyzers if analyzer.get("status") == "ACTIVE"
        ),
        "analyzers": analyzers,
        "errors": errors,
    }
