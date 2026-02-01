"""AWS Config rules evidence collector.

SOC 2 controls: CC4, CC5 (monitoring and control activities)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, paginate_call, safe_call


def collect_config_rules(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("config", region_name=region)
        region_rules, rule_error = paginate_call(
            client, "describe_config_rules", "ConfigRules"
        )
        if rule_error:
            errors.append(format_error("config", region, rule_error))
        if not region_rules:
            continue
        compliance_map: Dict[str, str] = {}
        rule_names = [rule.get("ConfigRuleName") for rule in region_rules if rule.get("ConfigRuleName")]
        batch_size = 25
        for start in range(0, len(rule_names), batch_size):
            batch = rule_names[start : start + batch_size]
            compliance, compliance_error = safe_call(
                client.describe_compliance_by_config_rule,
                ConfigRuleNames=batch,
            )
            if compliance_error:
                errors.append(format_error("config", region, compliance_error))
                continue
            for item in compliance.get("ComplianceByConfigRules", []) if compliance else []:
                compliance_map[item.get("ConfigRuleName")] = item.get("Compliance", {}).get(
                    "ComplianceType"
                )
        for rule in region_rules:
            rules.append(
                {
                    "name": rule.get("ConfigRuleName"),
                    "region": region,
                    "state": rule.get("ConfigRuleState"),
                    "compliance": compliance_map.get(rule.get("ConfigRuleName")),
                }
            )

    return {
        "rule_count": len(rules),
        "noncompliant_count": sum(
            1 for rule in rules if rule.get("compliance") == "NON_COMPLIANT"
        ),
        "rules_sample": rules[:50],
        "errors": errors,
    }
