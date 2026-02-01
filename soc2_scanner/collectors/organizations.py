"""AWS Organizations evidence collector.

SOC 2 controls: CC1, CC5 (governance and control activities)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import format_error, safe_call


def collect_organizations(session: boto3.Session) -> Dict[str, Any]:
    client = session.client("organizations")
    organization, org_error = safe_call(client.describe_organization)
    roots, roots_error = safe_call(client.list_roots)
    policies, policies_error = safe_call(
        client.list_policies, Filter="SERVICE_CONTROL_POLICY"
    )
    accounts, accounts_error = safe_call(client.list_accounts)

    errors: List[str] = []
    if org_error:
        errors.append(format_error("organizations", None, org_error))
    if roots_error:
        errors.append(format_error("organizations", None, roots_error))
    if policies_error:
        errors.append(format_error("organizations", None, policies_error))
    if accounts_error:
        errors.append(format_error("organizations", None, accounts_error))

    return {
        "organization_present": organization is not None,
        "root_count": len(roots.get("Roots", [])) if roots else 0,
        "scp_count": len(policies.get("Policies", [])) if policies else 0,
        "account_count": len(accounts.get("Accounts", [])) if accounts else 0,
        "errors": errors,
    }
