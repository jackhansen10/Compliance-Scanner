import argparse
from typing import List

from soc2_scanner.scanner import ScanConfig, run_scan


DEFAULT_CONTROLS = ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8"]


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOC2 evidence collection and reporting",
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name from ~/.aws/credentials",
    )
    parser.add_argument(
        "--regions",
        help="Comma-separated AWS regions, e.g. us-east-1,us-west-2",
    )
    parser.add_argument(
        "--controls",
        help="Comma-separated SOC2 controls (default: CC1,CC2,CC3,CC4,CC5,CC6,CC7,CC8)",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for reports (default: reports)",
    )
    parser.add_argument(
        "--all-accounts",
        action="store_true",
        help="Scan all AWS Organization accounts using AssumeRole",
    )
    parser.add_argument(
        "--account-ids",
        help="Comma-separated AWS account IDs to scan",
    )
    parser.add_argument(
        "--role-name",
        default="OrganizationAccountAccessRole",
        help="Role name to assume in child accounts",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    controls = _split_csv(args.controls) if args.controls else DEFAULT_CONTROLS
    regions = _split_csv(args.regions) if args.regions else []
    account_ids = _split_csv(args.account_ids) if args.account_ids else []

    config = ScanConfig(
        controls=controls,
        regions=regions,
        profile=args.profile,
        output_dir=args.output,
        account_ids=account_ids,
        all_accounts=args.all_accounts,
        role_name=args.role_name,
    )

    result = run_scan(config)
    print("Evidence report created:")
    for path in result["artifacts"]:
        print(f"- {path}")
    if result.get("identity_error"):
        print("Warning: unable to resolve AWS account identity.")
        print(result["identity_error"])
