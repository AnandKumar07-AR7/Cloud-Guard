# CloudGuard — Remediation Lifecycle & Safe Automation

## 1. Overview
Remediation in CloudGuard is governed by a strict safety pipeline designed to eliminate unauthorized, arbitrary, or destructive changes to cloud infrastructure.

> [!CAUTION]
> **Remediation Allowlist**: Remediation is restricted strictly to approved and deterministic strategies:
> - `S3-001` (and `s3-public-access-block-disabled`): Enforce S3 Public Access Block.
> - `SG-001` (and `ec2-sg-open-ssh`): Revoke unrestricted SSH ingress (0.0.0.0/0).
> 
> All other findings cannot be remediated directly. Attempting to execute unapproved remediation returns `HTTP 400: No supported remediation strategy`.

---

## 2. Finding Lifecycle

```mermaid
stateDiagram-v2
    [*] --> OPEN: Scan Discovery
    OPEN --> INVESTIGATING: Analyst Review / AI Run
    INVESTIGATING --> REMEDIATION_PLANNED: Plan Created (Approved Rule)
    INVESTIGATING --> ACKNOWLEDGED: Risk Accepted / Dismissed
    REMEDIATION_PLANNED --> REMEDIATION_IN_PROGRESS: Plan Executed
    REMEDIATION_IN_PROGRESS --> VERIFYING: Post-Action Scan
    VERIFYING --> RESOLVED: Verification Confirmed Fixed
    VERIFYING --> REMEDIATION_FAILED: Verification Detected Issue Still Active
    REMEDIATION_FAILED --> OPEN: Returned to Active Queue
    RESOLVED --> [*]
    ACKNOWLEDGED --> [*]
```

---

## 3. 6-Stage Governed Remediation Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor Creator as Analyst / Policy Engine
    actor Approver as Designated Approver (Admin)
    participant Core as Remediation Service
    participant Policy as Automation Policy Engine
    participant Cloud as AWS / Mock Provider
    participant Audit as Hash-Chained Audit Trail

    Note over Creator,Core: 1. PLAN GENERATION
    Creator->>Core: POST /api/v1/remediations/plans?finding_id={id}
    Core->>Core: Verify Rule in Allowlist (S3-001, SG-001)
    Core->>Audit: Record PLAN_CREATED event
    Core-->>Creator: RemediationPlan (Status: DRAFT)

    Note over Creator,Core: 2. VALIDATION
    Creator->>Core: POST /api/v1/remediations/plans/{id}/validate
    Core->>Cloud: Check resource exists & preconditions
    Core->>Core: Validate safety diff & parameters
    Core->>Audit: Record VALIDATION_PASSED event
    Core-->>Creator: RemediationPlan (Status: VALIDATED)

    Note over Creator,Policy: 3. POLICY EVALUATION & APPROVAL GATE
    alt Automation Policy Applies (Tier 1 Auto)
        Core->>Policy: Evaluate Automation Policy
        Policy->>Policy: Check Priority, Tier & Kill Switch
        Policy-->>Core: Auto-Approve Decision
    else Manual Approval Required
        Creator->>Approver: Submit Plan for Review
        Approver->>Core: POST /api/v1/remediations/plans/{id}/approve
        Core->>Core: Verify Separation of Duties (Creator != Approver)
        Core->>Audit: Record PLAN_APPROVED event
    end

    Note over Core,Cloud: 4. EXECUTION
    Core->>Core: Verify Kill Switch Not Active
    Core->>Cloud: Apply safe configuration change
    Cloud-->>Core: Mutation Success Response
    Core->>Audit: Record EXECUTION_SUCCESS event

    Note over Core,Cloud: 5. VERIFICATION
    Core->>Cloud: Trigger targeted re-scan of resource
    Cloud-->>Core: Fresh configuration state
    Core->>Core: Re-evaluate detection rule
    alt Resource Compliant
        Core->>Core: Mark Plan VERIFIED & Finding RESOLVED
        Core->>Audit: Record VERIFICATION_CONFIRMED event
    else Misconfiguration Remains
        Core->>Core: Mark Plan FAILED & Finding OPEN
        Core->>Audit: Record VERIFICATION_FAILED event
    end
```

---

## 4. Key Remediation Safeguards
1. **Separation of Duties**: In environments requiring multi-party authorization, the user who created the remediation plan cannot approve it. Self-approval attempts are blocked with `HTTP 400 / 403`.
2. **Emergency Kill Switch**: The global kill switch halts all execution immediately. When active, any invocation of `/execute` or automated policy evaluation fails with `KillSwitchActiveError`.
3. **Rollback Capabilities**: Every executed strategy captures a snapshot of the pre-remediation configuration to facilitate rollback via the MCP Control Plane or API.
