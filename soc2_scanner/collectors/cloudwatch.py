"""CloudWatch evidence collector (alarms, logs).

SOC 2 controls: CC2, CC4 (monitoring and communication)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, paginate_call, safe_call


def collect_cloudwatch(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    alarms: List[Dict[str, Any]] = []
    log_groups: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("cloudwatch", region_name=region)
        region_alarms, alarm_error = paginate_call(
            client, "describe_alarms", "MetricAlarms"
        )
        if alarm_error:
            errors.append(format_error("cloudwatch", region, alarm_error))
        alarms.extend(
            {
                "name": alarm.get("AlarmName"),
                "region": region,
                "state": alarm.get("StateValue"),
            }
            for alarm in region_alarms
        )

        logs_client = session.client("logs", region_name=region)
        region_logs, logs_error = paginate_call(
            logs_client, "describe_log_groups", "logGroups"
        )
        if logs_error:
            errors.append(format_error("cloudwatch-logs", region, logs_error))
        log_groups.extend(
            {
                "name": group.get("logGroupName"),
                "region": region,
                "retention_days": group.get("retentionInDays"),
            }
            for group in region_logs
        )

    return {
        "alarm_count": len(alarms),
        "log_group_count": len(log_groups),
        "alarms_sample": alarms[:25],
        "log_groups_sample": log_groups[:25],
        "errors": errors,
    }
