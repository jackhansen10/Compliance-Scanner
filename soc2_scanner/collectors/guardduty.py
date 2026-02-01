"""GuardDuty evidence collector.

SOC 2 controls: CC3 (Risk Assessment)
"""

from typing import Any, Dict, List

import boto3

from soc2_scanner.collectors.helpers import safe_call


def collect_guardduty(session: boto3.Session, regions: List[str]) -> Dict[str, Any]:
    detectors: List[Dict[str, Any]] = []
    errors: List[str] = []

    for region in regions:
        client = session.client("guardduty", region_name=region)
        detector_resp, detector_error = safe_call(client.list_detectors)
        if detector_error:
            errors.append(f"{region}: {detector_error}")
            continue
        for detector_id in detector_resp.get("DetectorIds", []):
            detector, detector_error = safe_call(
                client.get_detector, DetectorId=detector_id
            )
            if detector_error:
                errors.append(f"{region}: {detector_error}")
            detectors.append(
                {
                    "detector_id": detector_id,
                    "region": region,
                    "status": detector.get("Status") if detector else None,
                    "finding_publishing_frequency": detector.get(
                        "FindingPublishingFrequency"
                    )
                    if detector
                    else None,
                }
            )

    return {
        "detector_count": len(detectors),
        "enabled_detector_count": sum(
            1 for det in detectors if det.get("status") == "ENABLED"
        ),
        "detectors": detectors,
        "errors": errors,
    }
