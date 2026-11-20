#!/usr/bin/env python3
"""LeaseGuard CDK Application — FinOps Triage & Autonomous Sandbox Cost-Reaper Agent."""

import os
import aws_cdk as cdk

from stacks.leaseguard_stack import LeaseGuardStack
from stacks.testbed_stack import LeaseGuardTestbedStack

app = cdk.App()

security_mode = app.node.try_get_context("security_mode") or "v2"
foundation_model_id = (
    app.node.try_get_context("foundation_model_id") or "amazon.nova-pro-v1:0"
)

account = (
    os.environ.get("CDK_DEFAULT_ACCOUNT")
    or os.environ.get("AWS_ACCOUNT_ID")
    or "848175179383"
)
region = os.environ.get("CDK_DEFAULT_REGION") or "us-east-1"
env = cdk.Environment(account=account, region=region)

# --- Core Agent Stack (Guardrail + Agent + Lambdas + DynamoDB + IAM) ---
agent_stack = LeaseGuardStack(
    app,
    "LeaseGuardStack",
    security_mode=security_mode,
    foundation_model_id=foundation_model_id,
    env=env,
)

# --- Low-Cost Testbed Stack (dummy prod/sandbox EC2 + EBS targets) ---
testbed_stack = LeaseGuardTestbedStack(
    app,
    "LeaseGuardTestbedStack",
    env=env,
)

# Tag all resources for cost tracking
cdk.Tags.of(app).add("Project", "LeaseGuard")
cdk.Tags.of(app).add("ManagedBy", "CDK")

app.synth()

