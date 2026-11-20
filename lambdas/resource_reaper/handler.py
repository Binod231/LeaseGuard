"""
LeaseGuard — Resource Reaper Lambda
(stop_instance, terminate_instance, delete_volume, get_security_status)

Implements Layers 3-4 of the Five-Layer Defence-in-Depth:
  Layer 3  — DynamoDB Stateful Policy Engine + Active Intrusion Tripwire
  Layer 4  — Dynamic Single-ARN STS Scoping

SECURITY_MODE=v1  →  Intentionally vulnerable baseline.
  • Skips session-lock check   (Step A)
  • Skips prod/tag tripwire     (Step B – prod guard)
  • Skips blast-radius quota    (Step C)
  • Still performs lease-date check and STS execution (Step B partial + D)
  → Injected tool calls fall through to Layer 5 IAM ABAC for authentic proof.

SECURITY_MODE=v2  →  Fully hardened.
  • All four steps enforced: Lock → Tags → Quota → STS.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SECURITY_MODE: str = os.environ.get("SECURITY_MODE", "v2")
TABLE_NAME: str = os.environ.get("DYNAMODB_TABLE", "LeaseGuardAuditLedger")
EXECUTION_ROLE_ARN: str = os.environ.get("EXECUTION_ROLE_ARN", "")
STS_EXTERNAL_ID: str = os.environ.get("STS_EXTERNAL_ID", "leaseguard-reaper-exec")
AWS_REGION: str = os.environ.get("AWS_REGION", "us-east-1")

MAX_DELETIONS_PER_24H: int = 3

# Map function names → EC2 API action strings
EC2_ACTION_MAP: dict[str, str] = {
    "stop_instance": "ec2:StopInstances",
    "terminate_instance": "ec2:TerminateInstances",
    "delete_volume": "ec2:DeleteVolume",
}

# Actions that consume blast-radius quota
DESTRUCTIVE_ACTIONS: set[str] = {"terminate_instance", "delete_volume"}

# ---------------------------------------------------------------------------
# AWS clients (re-used across warm invocations)
# ---------------------------------------------------------------------------
ec2_client = boto3.client("ec2", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sts_client = boto3.client("sts", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)


# ═══════════════════════════════════════════════════════════════════════════
# DynamoDB helpers
# ═══════════════════════════════════════════════════════════════════════════
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _epoch(dt: datetime, offset_hours: int = 0) -> int:
    """Return Unix epoch seconds, optionally shifted by *offset_hours*."""
    from datetime import timedelta

    return int((dt + timedelta(hours=offset_hours)).timestamp())


def check_session_locked(session_id: str) -> dict | None:
    """Return the lock record if SESSION_LOCKED, else None."""
    try:
        resp = table.get_item(
            Key={"pk": f"SESSION#{session_id}", "sk": "LOCK"},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if item and item.get("status") == "SESSION_LOCKED":
            return item
    except Exception:
        pass
    return None


def write_session_lock(
    session_id: str,
    resource_id: str,
    action: str,
    reason: str,
    now: datetime,
) -> None:
    """Write an intrusion-lockdown flag to DynamoDB."""
    table.put_item(
        Item={
            "pk": f"SESSION#{session_id}",
            "sk": "LOCK",
            "status": "SESSION_LOCKED",
            "reason": reason,
            "triggered_at": now.isoformat(),
            "offending_resource": resource_id,
            "offending_action": action,
            "expires_at": _epoch(now, offset_hours=24),
        }
    )


def write_audit(
    session_id: str,
    action: str,
    resource_id: str,
    verdict: str,
    now: datetime,
    *,
    sts_policy_digest: str = "",
    sts_target_arn: str = "",
    tags: dict | None = None,
    defense_layer: str = "",
) -> None:
    """Append an immutable audit event."""
    date_str = now.strftime("%Y-%m-%d")
    sk = f"{now.isoformat()}#{session_id}#{resource_id}"
    table.put_item(
        Item={
            "pk": f"AUDIT#{date_str}",
            "sk": sk,
            "session_id": session_id,
            "action": action,
            "resource_id": resource_id,
            "verdict": verdict,
            "defense_layer": defense_layer,
            "sts_policy_digest": sts_policy_digest,
            "sts_target_arn": sts_target_arn,
            "tags_at_execution": tags or {},
            "expires_at": _epoch(now, offset_hours=24 * 30),  # 30-day TTL
        }
    )


def write_quota_record(
    session_id: str, action: str, resource_id: str, now: datetime
) -> None:
    """Record a deletion for the blast-radius rolling window."""
    date_str = now.strftime("%Y-%m-%d")
    table.put_item(
        Item={
            "pk": f"QUOTA#{date_str}",
            "sk": f"DELETE#{now.isoformat()}#{resource_id}",
            "session_id": session_id,
            "resource_id": resource_id,
            "action": action,
            "expires_at": _epoch(now, offset_hours=24),
        }
    )


def count_deletions_last_24h() -> int:
    """Count ALLOWED deletions in the current UTC day's quota partition."""
    date_str = _now_utc().strftime("%Y-%m-%d")
    try:
        resp = table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"QUOTA#{date_str}",
                ":prefix": "DELETE#",
            },
            Select="COUNT",
        )
        return resp.get("Count", 0)
    except Exception:
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# AWS tag helpers
# ═══════════════════════════════════════════════════════════════════════════
def fetch_live_tags(resource_id: str) -> dict[str, str]:
    """
    Re-fetch tags directly from AWS APIs.
    NEVER trust LLM-supplied parameters for security decisions.
    """
    tags: dict[str, str] = {}
    try:
        if resource_id.startswith("i-"):
            resp = ec2_client.describe_instances(InstanceIds=[resource_id])
            for resv in resp.get("Reservations", []):
                for inst in resv.get("Instances", []):
                    for t in inst.get("Tags", []):
                        tags[t["Key"]] = t["Value"]
        elif resource_id.startswith("vol-"):
            resp = ec2_client.describe_volumes(VolumeIds=[resource_id])
            for vol in resp.get("Volumes", []):
                for t in vol.get("Tags", []):
                    tags[t["Key"]] = t["Value"]
    except ClientError:
        pass  # Empty tags → will be caught by policy checks
    return tags


# ═══════════════════════════════════════════════════════════════════════════
# STS single-ARN session policy (Layer 4)
# ═══════════════════════════════════════════════════════════════════════════
def _build_resource_arn(resource_id: str, account_id: str) -> str:
    if resource_id.startswith("i-"):
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:instance/{resource_id}"
    elif resource_id.startswith("vol-"):
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:volume/{resource_id}"
    raise ValueError(f"Unknown resource prefix: {resource_id}")


def build_single_arn_session_policy(action: str, resource_arn: str) -> str:
    """
    Build an inline STS session policy granting exactly ONE EC2 action
    on exactly ONE resource ARN.  AWS evaluates the INTERSECTION of this
    policy and the role's identity policy (Layer 5 ABAC).
    """
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": EC2_ACTION_MAP[action],
                    "Resource": resource_arn,
                }
            ],
        }
    )


# ═══════════════════════════════════════════════════════════════════════════
# Action handlers
# ═══════════════════════════════════════════════════════════════════════════
def handle_get_security_status(session_id: str) -> dict[str, Any]:
    """Return current security posture (no mutations)."""
    lock = check_session_locked(session_id)
    quota_used = count_deletions_last_24h()
    return {
        "security_mode": SECURITY_MODE,
        "session_locked": lock is not None,
        "lock_reason": (lock or {}).get("reason", ""),
        "deletions_last_24h": quota_used,
        "deletions_remaining": max(0, MAX_DELETIONS_PER_24H - quota_used),
        "max_deletions_per_24h": MAX_DELETIONS_PER_24H,
    }


def handle_reaper_action(
    action: str, resource_id: str, session_id: str
) -> dict[str, Any]:
    """
    Deterministic policy enforcement pipeline:
      Step A  →  Intrusion lockdown check   (v2 only)
      Step B  →  Authoritative tag + lease  (prod guard v2 only; lease always)
      Step C  →  Blast-radius quota         (v2 only, destructive only)
      Step D  →  Single-ARN STS execution   (always)
    """
    now = _now_utc()

    # ── Step A: Intrusion lockdown check (v2 only) ────────────────────────
    if SECURITY_MODE == "v2":
        lock = check_session_locked(session_id)
        if lock:
            write_audit(
                session_id, action, resource_id,
                "BLOCKED_LOCKED_SESSION", now,
                defense_layer="L3_SESSION_LOCK",
            )
            return {
                "error": "SessionLockedError",
                "message": (
                    "Session is locked due to a prior policy violation. "
                    "All destructive operations are blocked for the "
                    "remainder of this session."
                ),
                "lock_reason": lock.get("reason", ""),
                "defense_layer": "L3_SESSION_LOCK",
            }

    # ── Step B: Authoritative tag & lease verification ────────────────────
    tags = fetch_live_tags(resource_id)

    if SECURITY_MODE == "v2":
        env_tag = tags.get("Environment", "")
        auto_reap = tags.get("AutoReap", "")

        # --- Prod / tag boundary check (trips intrusion lockdown) ---
        if (
            env_tag in ("prod", "staging")
            or env_tag != "sandbox"
            or auto_reap != "true"
        ):
            write_session_lock(
                session_id, resource_id, action,
                "POLICY_VIOLATION_ATTEMPT", now,
            )
            write_audit(
                session_id, action, resource_id,
                "BLOCKED_POLICY_TRIPWIRE", now,
                defense_layer="L3_POLICY_TRIPWIRE",
                tags=tags,
            )
            return {
                "error": "PolicyViolationError",
                "message": (
                    f"INTRUSION LOCKDOWN TRIGGERED: Resource {resource_id} "
                    f"has Environment={env_tag}, AutoReap={auto_reap}. "
                    f"This violates the sandbox-only execution fence. "
                    f"Session is now locked."
                ),
                "defense_layer": "L3_POLICY_TRIPWIRE",
            }

    # --- Lease-date check (both v1 and v2) ---
    lease_str = tags.get("LeaseExpires", "")
    if lease_str:
        try:
            lease_date = datetime.strptime(lease_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            if lease_date.date() >= now.date():
                write_audit(
                    session_id, action, resource_id,
                    "BLOCKED_LEASE_ACTIVE", now,
                    defense_layer="L3_LEASE_CHECK",
                    tags=tags,
                )
                return {
                    "error": "LeaseActiveError",
                    "message": (
                        f"Resource {resource_id} lease expires "
                        f"{lease_str}, which is not past due. "
                        f"Cannot act on resources with active leases."
                    ),
                    "lease_expires": lease_str,
                    "defense_layer": "L3_LEASE_CHECK",
                }
        except ValueError:
            write_audit(
                session_id, action, resource_id,
                "BLOCKED_LEASE_ACTIVE", now,
                defense_layer="L3_LEASE_CHECK",
                tags=tags,
            )
            return {
                "error": "InvalidLeaseDate",
                "message": (
                    f"Resource {resource_id} has an unparseable "
                    f"LeaseExpires tag: '{lease_str}'."
                ),
                "defense_layer": "L3_LEASE_CHECK",
            }
    elif SECURITY_MODE == "v2":
        # Missing LeaseExpires in v2 → policy violation
        write_session_lock(
            session_id, resource_id, action,
            "MISSING_LEASE_TAG", now,
        )
        write_audit(
            session_id, action, resource_id,
            "BLOCKED_POLICY_TRIPWIRE", now,
            defense_layer="L3_POLICY_TRIPWIRE",
            tags=tags,
        )
        return {
            "error": "PolicyViolationError",
            "message": (
                f"Resource {resource_id} is missing a LeaseExpires tag. "
                f"Session locked."
            ),
            "defense_layer": "L3_POLICY_TRIPWIRE",
        }

    # ── Step C: Blast-radius circuit breaker (v2 only, destructive only) ──
    if SECURITY_MODE == "v2" and action in DESTRUCTIVE_ACTIONS:
        quota_used = count_deletions_last_24h()
        if quota_used >= MAX_DELETIONS_PER_24H:
            write_audit(
                session_id, action, resource_id,
                "BLOCKED_QUOTA", now,
                defense_layer="L3_QUOTA_BREAKER",
                tags=tags,
            )
            return {
                "error": "QuotaExceededError",
                "message": (
                    f"Blast-radius quota exceeded: "
                    f"{quota_used}/{MAX_DELETIONS_PER_24H} permanent "
                    f"deletions used in the current 24-hour window."
                ),
                "deletions_used": quota_used,
                "max_allowed": MAX_DELETIONS_PER_24H,
                "defense_layer": "L3_QUOTA_BREAKER",
            }

    # ── Step D: Execute via single-ARN STS (Layer 4 → Layer 5) ────────────
    return _execute_via_sts(action, resource_id, session_id, tags, now)


def _execute_via_sts(
    action: str,
    resource_id: str,
    session_id: str,
    tags: dict[str, str],
    now: datetime,
) -> dict[str, Any]:
    """
    Assume LeaseGuardSingleArnExecutionRole with an inline session policy
    scoped to exactly one EC2 action on exactly one resource ARN, then
    execute the action with those ephemeral credentials.
    """
    # Derive account ID from this Lambda's own ARN (no extra API call)
    account_id = os.environ.get("AWS_ACCOUNT_ID", "")
    if not account_id:
        # Fallback: extract from Lambda function ARN
        func_arn = os.environ.get("AWS_LAMBDA_LOG_GROUP_NAME", "")
        try:
            account_id = sts_client.get_caller_identity()["Account"]
        except Exception:
            account_id = "000000000000"

    resource_arn = _build_resource_arn(resource_id, account_id)
    session_policy = build_single_arn_session_policy(action, resource_arn)
    policy_digest = hashlib.sha256(session_policy.encode()).hexdigest()[:16]

    try:
        # --- Assume role with single-ARN inline session policy ---
        sts_resp = sts_client.assume_role(
            RoleArn=EXECUTION_ROLE_ARN,
            RoleSessionName=f"lg-{session_id[:12]}-{resource_id[:19]}"[:64],
            DurationSeconds=900,
            ExternalId=STS_EXTERNAL_ID,
            Policy=session_policy,
        )

        creds = sts_resp["Credentials"]
        scoped_ec2 = boto3.client(
            "ec2",
            region_name=AWS_REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        # --- Execute the exactly-one-action ---
        if action == "stop_instance":
            scoped_ec2.stop_instances(InstanceIds=[resource_id])
        elif action == "terminate_instance":
            scoped_ec2.terminate_instances(InstanceIds=[resource_id])
        elif action == "delete_volume":
            scoped_ec2.delete_volume(VolumeId=resource_id)

        # --- Record success ---
        write_audit(
            session_id, action, resource_id, "ALLOWED", now,
            sts_policy_digest=f"sha256:{policy_digest}",
            sts_target_arn=resource_arn,
            tags=tags,
            defense_layer="L4_SINGLE_ARN_STS",
        )
        if action in DESTRUCTIVE_ACTIONS:
            write_quota_record(session_id, action, resource_id, now)

        return {
            "status": "success",
            "action": action,
            "resource_id": resource_id,
            "defense_layer": "L4_SINGLE_ARN_STS",
            "sts_target_arn": resource_arn,
            "sts_policy_digest": f"sha256:{policy_digest}",
            "tags": {
                "Environment": tags.get("Environment", ""),
                "AutoReap": tags.get("AutoReap", ""),
                "LeaseExpires": tags.get("LeaseExpires", ""),
                "Owner": tags.get("Owner", ""),
            },
        }

    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ("UnauthorizedOperation", "AccessDeniedException",
                          "AccessDenied"):
            write_audit(
                session_id, action, resource_id, "BLOCKED_IAM", now,
                sts_policy_digest=f"sha256:{policy_digest}",
                sts_target_arn=resource_arn,
                tags=tags,
                defense_layer="L5_IAM_ABAC",
            )
            return {
                "error": "IAMDenied",
                "message": (
                    f"AWS IAM ABAC (Layer 5) denied "
                    f"{EC2_ACTION_MAP.get(action, action)} on "
                    f"{resource_id}.  The hard cloud boundary held."
                ),
                "aws_error_code": error_code,
                "defense_layer": "L5_IAM_ABAC",
                "sts_target_arn": resource_arn,
                "sts_policy_digest": f"sha256:{policy_digest}",
            }
        # Non-auth errors: re-raise
        write_audit(
            session_id, action, resource_id, "ERROR", now,
            sts_policy_digest=f"sha256:{policy_digest}",
            sts_target_arn=resource_arn,
            tags=tags,
            defense_layer="L4_SINGLE_ARN_STS",
        )
        raise


# ═══════════════════════════════════════════════════════════════════════════
# Bedrock Agent entry point
# ═══════════════════════════════════════════════════════════════════════════
def _parse_params(event: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in event.get("parameters", [])}


def _format_response(
    action_group: str, function_name: str, body: dict
) -> dict:
    """Return a Bedrock Agent FunctionSchema-format response."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": function_name,
            "functionResponse": {
                "responseBody": {
                    "TEXT": {"body": json.dumps(body, default=str)},
                },
            },
        },
    }


def lambda_handler(event: dict, context) -> dict:
    """Bedrock Agent Action Group entry point (FunctionSchema format)."""
    action_group = event.get("actionGroup", "")
    function_name = event.get("function", "")
    session_id = event.get("sessionId", "unknown")
    params = _parse_params(event)

    if function_name == "get_security_status":
        result = handle_get_security_status(session_id)

    elif function_name in ("stop_instance", "terminate_instance", "delete_volume"):
        resource_id = params.get("resource_id", "").strip()
        if not resource_id:
            result = {
                "error": "MissingParameter",
                "message": "resource_id is required.",
            }
        else:
            result = handle_reaper_action(function_name, resource_id, session_id)

    else:
        result = {
            "error": "UnknownFunction",
            "message": f"Function '{function_name}' is not recognised.",
        }

    return _format_response(action_group, function_name, result)

