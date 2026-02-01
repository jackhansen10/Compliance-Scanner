"""KMS evidence collector.

SOC 2 controls: CC6 (Logical and Physical Access)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import safe_call


def collect_kms(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    errors: List[str] = []
    keys_sampled: List[Dict[str, Any]] = []

    for region in regions:
        client = session.client("kms", region_name=region)
        keys_resp, keys_error = safe_call(client.list_keys, Limit=25)
        if keys_error:
            errors.append(f"{region}: {keys_error}")
            continue
        for key in keys_resp.get("Keys", []):
            meta, meta_error = safe_call(client.describe_key, KeyId=key["KeyId"])
            rotation, rotation_error = safe_call(
                client.get_key_rotation_status, KeyId=key["KeyId"]
            )
            if meta_error:
                errors.append(f"{region}: {meta_error}")
            if rotation_error:
                errors.append(f"{region}: {rotation_error}")
            metadata = meta.get("KeyMetadata", {}) if meta else {}
            keys_sampled.append(
                {
                    "key_id": key["KeyId"],
                    "region": region,
                    "key_manager": metadata.get("KeyManager"),
                    "key_state": metadata.get("KeyState"),
                    "rotation_enabled": rotation.get("KeyRotationEnabled")
                    if rotation
                    else None,
                }
            )

    return {
        "sampled_key_count": len(keys_sampled),
        "rotation_enabled_count": sum(
            1 for key in keys_sampled if key.get("rotation_enabled") is True
        ),
        "keys_sampled": keys_sampled,
        "errors": errors,
    }
