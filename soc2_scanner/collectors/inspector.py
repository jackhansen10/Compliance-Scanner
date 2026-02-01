"""Inspector2 evidence collector.

SOC 2 controls: CC3 (Risk Assessment)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_inspector(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    regions_data: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("inspector2", region_name=region)
        coverage, coverage_error = safe_call(
            client.list_coverage, filterCriteria={}, maxResults=10
        )
        if coverage_error:
            errors.append(format_error("inspector2", region, coverage_error))
        regions_data.append(
            {
                "region": region,
                "coverage_count": len(coverage.get("coveredResources", []) if coverage else []),
            }
        )

    return {
        "coverage_region_count": sum(
            1 for region in regions_data if region.get("coverage_count", 0) > 0
        ),
        "regions": regions_data,
        "errors": errors,
    }
