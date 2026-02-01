"""Security Hub evidence collector.

SOC 2 controls: CC3 (Risk Assessment)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_securityhub(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    hubs: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("securityhub", region_name=region)
        hub, hub_error = safe_call(client.describe_hub)
        if hub_error:
            errors.append(format_error("securityhub", region, hub_error))
            hubs.append(
                {
                    "region": region,
                    "enabled": False,
                    "product_subscriptions": 0,
                }
            )
            continue
        products, products_error = safe_call(client.list_enabled_products_for_import)
        if products_error:
            errors.append(format_error("securityhub", region, products_error))
        hubs.append(
            {
                "region": region,
                "enabled": hub is not None,
                "product_subscriptions": len(
                    products.get("ProductSubscriptions", []) if products else []
                ),
            }
        )

    return {
        "enabled_region_count": sum(1 for hub in hubs if hub.get("enabled")),
        "regions": hubs,
        "errors": errors,
    }
