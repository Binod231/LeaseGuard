# LeaseGuard: FinOps Triage & Autonomous Sandbox Cost-Reaper Agent

An interactive FinOps copilot built on **Amazon Bedrock Managed Agents** that autonomously reasons over messy cloud resource signals (idle times, unattached EBS volumes, snapshot coverage, and ownership tags) while enforcing a **5-layer deterministic security fence**.

---

## Architecture & Defense-in-Depth

Even if the reasoning LLM encounters prompt injection or adversarial jailbreaks, five independent AWS-native controls prevent it from modifying production workloads, mutating tags, or exceeding safety quotas:

```
[Developer / UI]
       │
       ▼
[Layer 1: Amazon Bedrock Guardrails]
  • Input Prompt Attack Filter (HIGH)
  • Denied Topics (ProductionOverride, InternalRecon)
  • Sensitive Data Masking (Account ID, Access Keys)
       │
       ▼
[Amazon Bedrock Managed Agent (Amazon Nova Pro)]
  • Autonomous FinOps reasoning & triage
       │
       ▼
[Layer 2: Bedrock Action Confirmation]
  • Human Gatekeeping on terminate_instance & delete_volume
       │
       ▼
[Layer 3: Stateful Policy Engine & Active Intrusion Tripwire (DynamoDB + Lambda)]
  • Step A: SESSION_LOCKED intrusion lockdown
  • Step B: Authoritative AWS tag & lease date verification
  • Step C: 24-hour blast-radius quota breaker (< 3 permanent deletions)
       │
       ▼
[Layer 4: Dynamic Single-ARN STS Inline Session Scoping]
  • AssumeRole on LeaseGuardSingleArnExecutionRole
  • Inline policy: exactly 1 action on strictly 1 resource ARN (900s TTL)
       │
       ▼
[Layer 5: Scoped IAM ABAC Hardware Boundary]
  • Allow: Environment=sandbox AND AutoReap=true
  • Explicit Deny: Environment ∈ {prod, staging}
  • Explicit Deny: ec2:CreateTags, ec2:DeleteTags, iam:*
```

Architecture diagram file: [`docs/architecture.mmd`](docs/architecture.mmd).

---

## Key Features

1. **FinOps Inventory & Backup Intelligence:** Calculates monthly waste across idle compute and storage, and verifies whether unattached EBS volumes have recent snapshot backups before proposing cleanup.
2. **Deterministic Security Fence:** Free-text tags are treated as untrusted data (`<untrusted_tag_data>`), preventing indirect prompt injection.
3. **Session Intrusion Lockdown:** If an attacker attempts a production violation, DynamoDB sets `SESSION_LOCKED`, disabling all destructive tools for that session.
4. **Reproducible Security Comparison Mode (`-c security_mode=v1|v2`):**
   - `v1` (Vulnerable baseline): Raw tags exposed, session lock disabled; demonstrates how Layer 5 IAM ABAC still prevents production compromise.
   - `v2` (Hardened production): Full 5-layer enforcement passes all 7 stress tests cleanly.
5. **Low-Cost AWS Testbed:** Provisions dummy test targets in `us-east-1` (stopped instances and small volumes) costing under $2/month.

---

## Deployment & Teardown

### Prerequisites
- Python 3.12+
- Node.js & AWS CDK CLI
- Configured AWS credentials (`us-east-1`)

### 1. Install Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Deploy Hardened Agent (v2)
```bash
cd infra
npx aws-cdk deploy --all -c security_mode=v2
```

### 3. Model Configuration
The default model is **Amazon Nova Pro** (`amazon.nova-pro-v1:0`), which is fully compatible with Bedrock Agents and standard AWS credits. To use Claude 3.5 Sonnet instead, specify:
```bash
npx aws-cdk deploy --all -c foundation_model_id=anthropic.claude-3-5-sonnet-20240620-v1:0
```

### 4. Deploy Baseline for Failure Reproduction (v1)
```bash
npx aws-cdk deploy --all -c security_mode=v1
```

### 5. Clean Teardown
```bash
npx aws-cdk destroy --all
```

---

## Testing & Verification

### Run Unit Tests
```bash
pytest tests/test_policy_engine.py -v
```

### Run Automated 7-Prompt Stress Test Suite
```bash
python scripts/reseed_testbed.py
python stress_test/run_suite.py --security-mode v2 --verify-iam
```

### Launch Inspector UI
```bash
streamlit run ui/app.py
```

---

## License
Distributed under the OSI-approved MIT License. See [LICENSE](LICENSE).
