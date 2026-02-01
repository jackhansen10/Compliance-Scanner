"""CloudTrail evidence collector.

SOC 2 controls: CC1, CC2, CC6, CC7, CC8 (logging and change evidence)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import safe_call


def collect_cloudtrail(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    trails: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("cloudtrail", region_name=region)
        response, error = safe_call(client.describe_trails, includeShadowTrails=True)
        if error:
            errors.append(f"{region}: {error}")
            continue
        for trail in response.get("trailList", []):
            status, status_error = safe_call(client.get_trail_status, Name=trail.get("Name"))
            if status_error:
                errors.append(f"{region}: {status_error}")
            trails.append(
                {
                    "name": trail.get("Name"),
                    "home_region": trail.get("HomeRegion"),
                    "region": region,
                    "is_multi_region": trail.get("IsMultiRegionTrail"),
                    "is_logging": status.get("IsLogging") if status else None,
                    "s3_bucket_name": trail.get("S3BucketName"),
                    "log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                }
            )

    return {
        "trail_count": len(trails),
        "multi_region_trail_count": sum(
            1 for trail in trails if trail.get("is_multi_region")
        ),
        "logging_trail_count": sum(
            1 for trail in trails if trail.get("is_logging")
        ),
        "trails": trails,
        "errors": errors,
    }
