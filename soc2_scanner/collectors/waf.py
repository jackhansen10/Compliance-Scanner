"""WAFv2 evidence collector.

SOC 2 controls: CC4 (Monitoring Activities)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_waf(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    web_acls: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("wafv2", region_name=region)
        response, error = safe_call(
            client.list_web_acls, Scope="REGIONAL"
        )
        if error:
            errors.append(format_error("wafv2", region, error))
            continue
        for acl in response.get("WebACLs", []):
            web_acls.append(
                {
                    "name": acl.get("Name"),
                    "id": acl.get("Id"),
                    "region": region,
                }
            )

    return {
        "web_acl_count": len(web_acls),
        "web_acls_sample": web_acls[:25],
        "errors": errors,
    }
