"""AWS Config recorder evidence collector.

SOC 2 controls: CC7 (System Operations)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import safe_call


def collect_config(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    recorders: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("config", region_name=region)
        recorder_resp, recorder_error = safe_call(
            client.describe_configuration_recorders
        )
        status_resp, status_error = safe_call(
            client.describe_configuration_recorder_status
        )
        channels_resp, channels_error = safe_call(
            client.describe_delivery_channels
        )

        if recorder_error:
            errors.append(f"{region}: {recorder_error}")
        if status_error:
            errors.append(f"{region}: {status_error}")
        if channels_error:
            errors.append(f"{region}: {channels_error}")

        status_map = {
            status.get("name"): status
            for status in (
                status_resp.get("ConfigurationRecordersStatus", [])
                if status_resp
                else []
            )
        }

        for recorder in (
            recorder_resp.get("ConfigurationRecorders", []) if recorder_resp else []
        ):
            status = status_map.get(recorder.get("name"), {})
            recorders.append(
                {
                    "name": recorder.get("name"),
                    "region": region,
                    "recording": status.get("recording"),
                    "last_status": status.get("lastStatus"),
                    "delivery_channel_count": len(
                        channels_resp.get("DeliveryChannels", [])
                        if channels_resp
                        else []
                    ),
                }
            )

    return {
        "recorder_count": len(recorders),
        "recording_count": sum(1 for rec in recorders if rec.get("recording")),
        "recorders": recorders,
        "errors": errors,
    }
