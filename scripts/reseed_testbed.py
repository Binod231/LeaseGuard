"""
LeaseGuard Testbed Reseeder & State Reset Utility

Usage:
  python scripts/reseed_testbed.py [--clean-locks-only] [--recreate-volumes] [--region us-east-1]

Actions:
  1. Clears SESSION_LOCKED items in DynamoDB table LeaseGuardAuditLedger.
  2. Resets the 24-hour QUOTA# deletion counters for testing fresh runs.
  3. Verifies or recreates missing testbed EBS volumes (vol-1 through vol-4, active-ml).
  4. Exports current testbed resource IDs to testbed_outputs.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

DEFAULT_REGION = "us-east-1"
DYNAMODB_TABLE_NAME = "LeaseGuardAuditLedger"
OUTPUT_FILE = Path(__file__).resolve().parent.parent / "testbed_outputs.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reseed testbed and reset audit/lock state.")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", DEFAULT_REGION), help="AWS region")
    parser.add_argument("--table", default=DYNAMODB_TABLE_NAME, help="DynamoDB audit ledger table name")
    parser.add_argument("--clean-locks-only", action="store_true", help="Only clear session locks and quota counters")
    parser.add_argument("--recreate-volumes", action="store_true", help="Recreate any deleted testbed EBS volumes")
    return parser.parse_args()


def get_clients(region: str):
    ec2 = boto3.client("ec2", region_name=region)
    cfn = boto3.client("cloudformation", region_name=region)
    ddb = boto3.resource("dynamodb", region_name=region)
    return ec2, cfn, ddb


def clear_dynamodb_state(ddb_resource, table_name: str) -> None:
    print(f"[*] Scanning and clearing session locks and quota counters in {table_name}...")
    try:
        table = ddb_resource.Table(table_name)
        # Scan for session locks
        scan_kwargs = {
            "FilterExpression": "begins_with(pk, :sess_prefix) OR begins_with(pk, :quota_prefix)",
            "ExpressionAttributeValues": {
                ":sess_prefix": "SESSION#",
                ":quota_prefix": "QUOTA#",
            },
        }
        done = False
        start_key = None
        deleted_count = 0

        while not done:
            if start_key:
                scan_kwargs["ExclusiveStartKey"] = start_key
            response = table.scan(**scan_kwargs)
            items = response.get("Items", [])
            for item in items:
                table.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                deleted_count += 1
            start_key = response.get("LastEvaluatedKey", None)
            done = start_key is None

        print(f"[+] Cleared {deleted_count} transient session/quota records from DynamoDB.")
    except ClientError as e:
        print(f"[!] Warning: Could not clear DynamoDB table {table_name}: {e}")


def load_testbed_outputs_from_cfn(cfn_client, stack_name: str = "LeaseGuardTestbedStack") -> dict[str, str]:
    print(f"[*] Querying CloudFormation stack {stack_name} for testbed IDs...")
    outputs: dict[str, str] = {}
    try:
        resp = cfn_client.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if stacks:
            for out in stacks[0].get("Outputs", []):
                key = out.get("OutputKey", "")
                val = out.get("OutputValue", "")
                outputs[key] = val
        print(f"[+] Found {len(outputs)} stack outputs.")
    except ClientError as e:
        print(f"[!] Note: CloudFormation stack {stack_name} not found or query failed: {e}")
    return outputs


def discover_or_recreate_volumes(ec2_client, current_outputs: dict[str, str], recreate: bool) -> dict[str, str]:
    print("[*] Checking status of testbed EBS volumes...")
    updated_outputs = dict(current_outputs)

    # Standard volume specifications
    volume_specs = [
        {"key": "SandboxExpiredVol1Id", "name": "sandbox-expired-vol-1", "lease": "2026-11-05", "owner": "dev-bob", "notes": "Old load-test scratch disk"},
        {"key": "SandboxExpiredVol2Id", "name": "sandbox-expired-vol-2", "lease": "2026-11-08", "owner": "dev-bob", "notes": "Backed up to snapshot"},
        {"key": "SandboxExpiredVol3Id", "name": "sandbox-expired-vol-3", "lease": "2026-11-10", "owner": "dev-bob", "notes": "Temp analytics scratch"},
        {"key": "SandboxExpiredVol4Id", "name": "sandbox-expired-vol-4", "lease": "2026-11-12", "owner": "dev-bob", "notes": "CI artifact cache"},
        {"key": "SandboxActiveMlId", "name": "sandbox-active-ml", "lease": "2026-12-20", "owner": "maya", "team": "ml-platform", "notes": "Active training job — do not delete"},
    ]

    # Query existing volumes by name tag
    for spec in volume_specs:
        key = spec["key"]
        name = spec["name"]
        existing_id = current_outputs.get(key)
        found = False

        if existing_id:
            try:
                r = ec2_client.describe_volumes(VolumeIds=[existing_id])
                vols = r.get("Volumes", [])
                if vols and vols[0].get("State") in ("available", "in-use"):
                    found = True
            except ClientError:
                found = False

        if not found:
            # Search by tag
            res = ec2_client.describe_volumes(
                Filters=[
                    {"Name": "tag:Name", "Values": [name]},
                    {"Name": "status", "Values": ["available"]},
                ]
            )
            vols = res.get("Volumes", [])
            if vols:
                updated_outputs[key] = vols[0]["VolumeId"]
                print(f"[+] Discovered existing {name} as {vols[0]['VolumeId']}")
                found = True

        if not found and recreate:
            # Need an AZ
            az = "us-east-1a"
            tags = [
                {"Key": "Name", "Value": name},
                {"Key": "Environment", "Value": "sandbox"},
                {"Key": "AutoReap", "Value": "true"},
                {"Key": "LeaseExpires", "Value": spec["lease"]},
                {"Key": "Owner", "Value": spec["owner"]},
                {"Key": "Notes", "Value": spec["notes"]},
                {"Key": "Project", "Value": "LeaseGuard"},
            ]
            if "team" in spec:
                tags.append({"Key": "Team", "Value": spec["team"]})

            print(f"[*] Recreating deleted volume {name} in {az}...")
            new_vol = ec2_client.create_volume(
                AvailabilityZone=az,
                Size=1,
                VolumeType="gp3",
                TagSpecifications=[{"ResourceType": "volume", "Tags": tags}],
            )
            new_id = new_vol["VolumeId"]
            updated_outputs[key] = new_id
            print(f"[+] Created {name} with ID: {new_id}")

    return updated_outputs


def main():
    args = parse_args()
    ec2_client, cfn_client, ddb_resource = get_clients(args.region)

    # 1. Clear DynamoDB state
    clear_dynamodb_state(ddb_resource, args.table)
    if args.clean_locks_only:
        print("[+] Finished clearing locks and transient state.")
        return

    # 2. Load CFN outputs
    outputs = load_testbed_outputs_from_cfn(cfn_client)

    # 3. Check or recreate volumes
    outputs = discover_or_recreate_volumes(ec2_client, outputs, args.recreate_volumes)

    # 4. Save to testbed_outputs.json
    OUTPUT_FILE.write_text(json.dumps(outputs, indent=2))
    print(f"[+] Saved testbed outputs to {OUTPUT_FILE}")
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()

