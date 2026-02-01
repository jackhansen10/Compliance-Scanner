from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError

from soc2_scanner.controls import EvidenceContext, evaluate_control
from soc2_scanner.collectors import collect_organizations


@dataclass
class ScanConfig:
    controls: List[str]
    regions: List[str]
    profile: Optional[str]
    output_dir: str
    account_ids: List[str] = field(default_factory=list)
    all_accounts: bool = False
    role_name: str = "OrganizationAccountAccessRole"


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_output_dir(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)


def _hash_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _write_hash_file(target_path: str) -> str:
    digest = _hash_file(target_path)
    hash_path = f"{target_path}.sha256"
    with open(hash_path, "w", encoding="utf-8") as handle:
        handle.write(f"{digest}  {os.path.basename(target_path)}\n")
    return hash_path


def _get_account_identity(session: boto3.Session) -> Dict[str, Optional[str]]:
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return {
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "identity_error": None,
        }
    except (BotoCoreError, ClientError) as exc:
        return {
            "account_id": None,
            "arn": None,
            "identity_error": str(exc),
        }


def _resolve_regions(session: boto3.Session, regions: List[str]) -> List[str]:
    if regions:
        return regions
    if session.region_name:
        return [session.region_name]
    return ["us-east-1"]


def _assume_role_session(
    base_session: boto3.Session, account_id: str, role_name: str
) -> Tuple[Optional[boto3.Session], Optional[str]]:
    try:
        sts = base_session.client("sts")
        response = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="soc2-scanner",
        )
        credentials = response["Credentials"]
        return (
            boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=base_session.region_name,
            ),
            None,
        )
    except (BotoCoreError, ClientError) as exc:
        return None, str(exc)


def _list_org_accounts(
    session: boto3.Session,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        client = session.client("organizations")
        paginator = client.get_paginator("list_accounts")
        accounts: List[Dict[str, Any]] = []
        for page in paginator.paginate():
            accounts.extend(page.get("Accounts", []))
        return accounts, None
    except (BotoCoreError, ClientError) as exc:
        return [], str(exc)


def _needs_org_cache(controls: List[str]) -> bool:
    return any(control in {"CC1", "CC5"} for control in controls)


def _build_evidence_entries(
    controls: List[str], context: EvidenceContext
) -> List[Dict[str, Any]]:
    entries = []
    for control in controls:
        entries.append(evaluate_control(control, context))
    return entries


def run_scan(config: ScanConfig) -> Dict[str, Any]:
    _ensure_output_dir(config.output_dir)

    session = boto3.Session(
        profile_name=config.profile,
        region_name=config.regions[0] if config.regions else None,
    )

    identity = _get_account_identity(session)
    regions = _resolve_regions(session, config.regions)
    account_results: List[Dict[str, Any]] = []
    organization_error: Optional[str] = None

    org_cache: Optional[Dict[str, Any]] = None
    if _needs_org_cache(config.controls):
        org_cache = collect_organizations(session)

    account_ids: List[str] = []
    account_map: Dict[str, str] = {}
    if config.all_accounts:
        org_accounts, org_error = _list_org_accounts(session)
        if org_error:
            organization_error = org_error
        for account in org_accounts:
            if account.get("Status") == "ACTIVE":
                account_id = account.get("Id")
                if account_id:
                    account_ids.append(account_id)
                    account_map[account_id] = account.get("Name") or ""
    elif config.account_ids:
        account_ids = config.account_ids[:]

    if not account_ids:
        account_ids = [identity["account_id"] or ""]

    for account_id in dict.fromkeys(account_ids):
        if not account_id:
            continue
        if account_id == identity["account_id"]:
            account_session = session
            account_identity = identity
            assume_error = None
        else:
            account_session, assume_error = _assume_role_session(
                session, account_id, config.role_name
            )
            if account_session:
                account_identity = _get_account_identity(account_session)
            else:
                account_identity = {"account_id": account_id, "arn": None, "identity_error": assume_error}

        if not account_session:
            account_results.append(
                {
                    "account_id": account_id,
                    "account_name": account_map.get(account_id),
                    "caller_arn": None,
                    "identity_error": assume_error,
                    "evidence": [],
                }
            )
            continue

        context = EvidenceContext(session=account_session, regions=regions)
        if org_cache is not None:
            context.cache["organizations"] = org_cache
        evidence_entries = _build_evidence_entries(config.controls, context)
        account_results.append(
            {
                "account_id": account_identity["account_id"],
                "account_name": account_map.get(account_id),
                "caller_arn": account_identity["arn"],
                "identity_error": account_identity["identity_error"] or assume_error,
                "evidence": evidence_entries,
            }
        )

    primary_evidence = account_results[0]["evidence"] if account_results else []

    payload = {
        "generated_at": _utc_timestamp(),
        "controls": config.controls,
        "regions": regions,
        "account_id": identity["account_id"],
        "caller_arn": identity["arn"],
        "identity_error": identity["identity_error"],
        "organization_error": organization_error,
        "evidence": primary_evidence,
        "accounts": account_results if len(account_results) > 1 else [],
    }

    json_path = os.path.join(config.output_dir, "evidence.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    csv_path = os.path.join(config.output_dir, "evidence_summary.csv")
    summary_rows: List[Dict[str, Any]] = []
    for account in account_results:
        for entry in account.get("evidence", []):
            summary_rows.append(
                {
                    "account_id": account.get("account_id"),
                    "account_name": account.get("account_name"),
                    "control_id": entry.get("control_id"),
                    "title": entry.get("title"),
                    "status": entry.get("status"),
                    "gap_count": len(entry.get("gaps", [])),
                    "error_count": len(entry.get("errors", [])),
                }
            )
    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(csv_path, index=False)

    hash_path = _write_hash_file(json_path)

    return {
        "artifacts": [json_path, csv_path, hash_path],
        "identity_error": identity["identity_error"],
    }
