from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError

from soc2_scanner.controls import EvidenceContext, evaluate_control


@dataclass
class ScanConfig:
    controls: List[str]
    regions: List[str]
    profile: Optional[str]
    output_dir: str


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
    context = EvidenceContext(session=session, regions=regions)
    evidence_entries = _build_evidence_entries(config.controls, context)

    payload = {
        "generated_at": _utc_timestamp(),
        "controls": config.controls,
        "regions": regions,
        "account_id": identity["account_id"],
        "caller_arn": identity["arn"],
        "identity_error": identity["identity_error"],
        "evidence": evidence_entries,
    }

    json_path = os.path.join(config.output_dir, "evidence.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)

    csv_path = os.path.join(config.output_dir, "evidence_summary.csv")
    summary_rows = [
        {
            "control_id": entry.get("control_id"),
            "title": entry.get("title"),
            "status": entry.get("status"),
            "gap_count": len(entry.get("gaps", [])),
            "error_count": len(entry.get("errors", [])),
        }
        for entry in evidence_entries
    ]
    summary_df = pd.DataFrame(summary_rows)
    summary_df.to_csv(csv_path, index=False)

    hash_path = _write_hash_file(json_path)

    return {
        "artifacts": [json_path, csv_path, hash_path],
        "identity_error": identity["identity_error"],
    }
