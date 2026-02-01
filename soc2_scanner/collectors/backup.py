"""AWS Backup evidence collector.

SOC 2 controls: CC5 (Control Activities)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_backup(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    plans: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("backup", region_name=region)
        response, error = safe_call(client.list_backup_plans)
        if error:
            errors.append(format_error("backup", region, error))
            continue
        for plan in response.get("BackupPlansList", []):
            plans.append(
                {
                    "plan_id": plan.get("BackupPlanId"),
                    "name": plan.get("BackupPlanName"),
                    "region": region,
                }
            )

    return {
        "backup_plan_count": len(plans),
        "plans_sample": plans[:25],
        "errors": errors,
    }
