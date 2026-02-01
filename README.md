# SOC2 Scanner

Automated evidence collection for SOC 2 Type II controls. This tool is designed
to pull evidence from AWS services, map it to specific SOC 2 controls, and
generate audit-ready reports with timestamps and hashes for integrity.

## What it does

- Pulls evidence from AWS services (IAM, CloudTrail, Config, GuardDuty, more)
- Maps evidence to SOC 2 controls (CC1 through CC8)
- Generates audit-ready reports (JSON + CSV)
- Adds timestamps and SHA-256 hashes for integrity checks

## How it works (high-level)

1. Connects to AWS using your configured credentials
2. Collects evidence per control (service-specific)
3. Generates reports with integrity metadata

The current implementation includes a working CLI, report generation, and
AWS-only evidence collectors for each CC control.

## Repo structure

- `soc2_scanner/collectors/` — AWS service data collection
- `soc2_scanner/controls/` — per-control analysis and gap logic (CC1–CC8)
- `soc2_scanner/scanner.py` — orchestration and report generation
- `tests/` — basic test coverage

## Setup

1. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Make sure your AWS credentials are configured:

   ```bash
   aws configure
   ```

   Or use a specific profile with `--profile`.

3. Ensure these AWS services are enabled in your account:
   - AWS Config, CloudTrail, GuardDuty, Security Hub, Inspector
   - CloudWatch Logs/Alarms, AWS Backup, SSM
   - Organizations (for SCP evidence), Access Analyzer

## Usage

Run the scanner with defaults:

```bash
python -m soc2_scanner
```

Specify controls, regions, and output directory:

```bash
python -m soc2_scanner \
  --profile my-audit-profile \
  --regions us-east-1,us-west-2 \
  --controls CC1,CC2,CC3,CC4,CC5,CC6,CC7,CC8 \
  --output reports
```

Scan across AWS Organizations accounts (assume role into each child account):

```bash
python -m soc2_scanner \
  --all-accounts \
  --role-name OrganizationAccountAccessRole \
  --external-id "my-external-id" \
  --regions us-east-1 \
  --output reports
```

Scan a specific set of account IDs:

```bash
python -m soc2_scanner \
  --account-ids 111111111111,222222222222 \
  --role-name OrganizationAccountAccessRole \
  --external-id "my-external-id" \
  --regions us-east-1 \
  --output reports
```

Use a JSON or YAML config file (CLI args override config values):

```json
{
  "profile": "my-audit-profile",
  "regions": "us-east-1,us-west-2",
  "controls": "CC1,CC2,CC3,CC4,CC5,CC6,CC7,CC8",
  "output": "reports",
  "all_accounts": true,
  "role_name": "OrganizationAccountAccessRole",
  "external_id": "my-external-id",
  "external_ids": {
    "111111111111": "child-external-id-1",
    "222222222222": "child-external-id-2"
  }
}
```

```bash
python -m soc2_scanner --config soc2-config.json
```

```yaml
profile: my-audit-profile
regions: us-east-1,us-west-2
controls: CC1,CC2,CC3,CC4,CC5,CC6,CC7,CC8
output: reports
all_accounts: true
role_name: OrganizationAccountAccessRole
external_id: my-external-id
external_ids:
  "111111111111": child-external-id-1
  "222222222222": child-external-id-2
```

```bash
python -m soc2_scanner --config soc2-config.yaml
```

Pass per-account external IDs on the CLI (JSON string):

```bash
python -m soc2_scanner \
  --all-accounts \
  --external-ids '{"111111111111":"child-external-id-1","222222222222":"child-external-id-2"}'
```

## Control coverage (AWS-only)

The scanner maps evidence to TSP 2017 Security criteria (CC1–CC8). Each control
includes a short gap list based on evidence presence.

- CC1 (Control Environment): Organizations, SCPs, CloudTrail
- CC2 (Communication & Info): CloudWatch Logs/Alarms, VPC Flow Logs, CloudTrail
- CC3 (Risk Assessment): Security Hub, GuardDuty, Inspector
- CC4 (Monitoring Activities): AWS Config rules, CloudWatch alarms
- CC5 (Control Activities): AWS Backup, Organizations, Config rules
- CC6 (Logical Access): IAM/MFA/password policy, Access Analyzer, CloudTrail
- CC7 (System Operations): AWS Config recorders, SSM, CloudTrail
- CC8 (Change Management): CodePipeline/CodeBuild, CloudTrail

## Output

Artifacts are written to the output directory:

- `evidence.json` — full evidence payload with metadata
- `evidence_summary.csv` — summary table by control
- `evidence.json.sha256` — hash of the JSON report for integrity

## Notes

- Evidence collection is AWS-only; non-AWS evidence (e.g., HR policies, ticketing
  systems) should be gathered separately.
- The scanner will still generate reports even if AWS identity resolution fails.

## Roadmap ideas

- Add multi-account support (Organizations + cross-account roles)
- Expand evidence depth per service (pagination, richer metadata)
- Export to PDF report format

## Running tests

Create a virtual environment, install dependencies, and run the test suite:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests
```
