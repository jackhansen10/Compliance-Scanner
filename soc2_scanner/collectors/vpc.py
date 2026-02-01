"""VPC flow logs evidence collector.

SOC 2 controls: CC2 (Communication and Information)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, paginate_call


def collect_vpc(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    flow_logs: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("ec2", region_name=region)
        region_logs, error = paginate_call(
            client, "describe_flow_logs", "FlowLogs"
        )
        if error:
            errors.append(format_error("ec2", region, error))
            continue
        flow_logs.extend(
            {
                "flow_log_id": log.get("FlowLogId"),
                "resource_id": log.get("ResourceId"),
                "region": region,
                "log_status": log.get("LogStatus"),
            }
            for log in region_logs
        )

    return {
        "flow_log_count": len(flow_logs),
        "active_flow_log_count": sum(
            1 for log in flow_logs if log.get("log_status") == "ACTIVE"
        ),
        "flow_logs_sample": flow_logs[:25],
        "errors": errors,
    }
