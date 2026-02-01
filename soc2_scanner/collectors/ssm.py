"""SSM evidence collector.

SOC 2 controls: CC7 (System Operations)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, paginate_call


def collect_ssm(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    instances: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("ssm", region_name=region)
        region_instances, error = paginate_call(
            client, "describe_instance_information", "InstanceInformationList"
        )
        if error:
            errors.append(format_error("ssm", region, error))
            continue
        instances.extend(
            {
                "instance_id": info.get("InstanceId"),
                "region": region,
                "ping_status": info.get("PingStatus"),
                "platform": info.get("PlatformName"),
            }
            for info in region_instances
        )

    return {
        "managed_instance_count": len(instances),
        "online_instance_count": sum(
            1 for info in instances if info.get("ping_status") == "Online"
        ),
        "instances_sample": instances[:25],
        "errors": errors,
    }
