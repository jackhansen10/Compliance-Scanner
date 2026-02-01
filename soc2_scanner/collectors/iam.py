"""IAM evidence collector.

SOC 2 controls: CC6 (Logical and Physical Access)
"""

from typing import Any, Dict

import boto3

from soc2_scanner.collectors.helpers import safe_call


def collect_iam(session: boto3.Session) -> Dict[str, Any]:
    iam = session.client("iam")
    summary, summary_error = safe_call(iam.get_account_summary)
    policy, policy_error = safe_call(iam.get_account_password_policy)
    users, users_error = safe_call(iam.list_users)

    account_summary = summary.get("SummaryMap", {}) if summary else {}
    root_mfa_enabled = account_summary.get("AccountMFAEnabled", 0) == 1

    return {
        "root_mfa_enabled": root_mfa_enabled,
        "password_policy_present": policy is not None,
        "user_count": len(users.get("Users", [])) if users else 0,
        "errors": [err for err in [summary_error, policy_error, users_error] if err],
    }
