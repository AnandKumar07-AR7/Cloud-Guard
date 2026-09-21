"""
CloudGuard — Phase 7 Final Acceptance Test Matrix

Explicitly implements and executes tests for:
- REM-01 through REM-36 (All 36 mandatory Phase 7 acceptance requirements)
- AUDIT-01 through AUDIT-10 (Audit immutability and secret sanitization)
- RBAC Matrix (ADMIN, SECURITY_ANALYST, OPERATOR, VIEWER across all permissions)
- State Machine & Finding Coupling (FindingStatus vs RemediationState decoupling)
- Real PostgreSQL Concurrency (REM-29 with concurrent threads and with_for_update locking)
"""
import uuid
import pytest
import concurrent.futures
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from main import app
from core.database import SessionLocal, engine
from core.db_models import (
    ScanDBModel, ResourceDBModel, FindingDBModel,
    RemediationPlanDBModel, RemediationActionDBModel,
    RemediationExecutionDBModel, RemediationAuditEventDBModel
)
from core.remediation.models import RemediationAction
from core.remediation.state import RemediationState, RemediationSafety, is_valid_transition
from core.remediation.strategy import STRATEGIES, get_strategy, RemediationStrategyContext
from core.remediation.audit import sanitize_audit_details, log_remediation_event
from core.providers.demo.remediation import DemoRemediationProvider, DEMO_STATE
from core.providers.aws.remediation import AWSRemediationProvider
from core.security.models import FindingStatus
from services.remediation_service import RemediationService


# ── Helper for clean test finding creation in real PostgreSQL ─────────────────

def create_db_finding(
    db,
    rule_id: str = "S3-001",
    account_id: str = "123456789012",
    resource_id: str = None,
    service: str = "s3",
    resource_type: str = "s3_bucket",
) -> FindingDBModel:
    """Create a persistent real finding in PostgreSQL for test isolation."""
    sid = str(uuid.uuid4())
    rid = resource_id or f"arn:aws:s3:::test-bucket-{uuid.uuid4().hex[:8]}"
    
    scan = ScanDBModel(
        scan_id=sid,
        correlation_id=str(uuid.uuid4()),
        provider="demo",
        account_id=account_id,
        mode="demo",
        status="COMPLETED",
    )
    db.add(scan)
    
    res = db.scalar(select(ResourceDBModel).where(ResourceDBModel.resource_id == rid))
    if not res:
        res = ResourceDBModel(
            resource_id=rid,
            provider="demo",
            account_id=account_id,
            region="us-east-1",
            service=service,
            resource_type=resource_type,
        )
        db.add(res)
    db.flush()
    
    fid = str(uuid.uuid4())
    finding = FindingDBModel(
        finding_id=fid,
        canonical_id=str(uuid.uuid4()),
        scan_id=sid,
        resource_id=rid,
        rule_id=rule_id,
        resource_type=resource_type,
        service=service,
        account_id=account_id,
        region="us-east-1",
        severity="high",
        risk_score=7.5,
        category="security",
        status="OPEN",
        rule_version="1.0.0",
        evidence={
            "rule_id": rule_id,
            "observed_value": "public",
            "expected_value": "private",
            "field_path": "configuration",
        },
        title=f"Test Finding for {rule_id}",
        description="Test Finding Description",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@pytest.fixture(autouse=True)
def clean_remediations_db():
    """Ensure clean remediation tables and demo state between tests."""
    DEMO_STATE["s3_blocks"].clear()
    DEMO_STATE["sg_blocks"].clear()
    with SessionLocal() as db:
        if db.bind.dialect.name == "sqlite":
            for table in ("remediation_audit_events", "remediation_executions", "remediation_actions", "remediation_plans"):
                db.execute(text(f"DELETE FROM {table};"))
        else:
            db.execute(text(
                "TRUNCATE TABLE remediation_audit_events, remediation_executions, "
                "remediation_actions, remediation_plans CASCADE;"
            ))
        db.commit()
    yield
    DEMO_STATE["s3_blocks"].clear()
    DEMO_STATE["sg_blocks"].clear()
    with SessionLocal() as db:
        if db.bind.dialect.name == "sqlite":
            for table in ("remediation_audit_events", "remediation_executions", "remediation_actions", "remediation_plans"):
                db.execute(text(f"DELETE FROM {table};"))
        else:
            db.execute(text(
                "TRUNCATE TABLE remediation_audit_events, remediation_executions, "
                "remediation_actions, remediation_plans CASCADE;"
            ))
        db.commit()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# PART 2 — MANDATORY REMEDIATION TEST MATRIX (REM-01 -> REM-36)
# ==============================================================================

# ── A. PLAN CREATION ─────────────────────────────────────────────────────────

def test_REM_01_create_plan_authorized(client, analyst_headers, admin_headers):
    """REM-01: Authenticated authorized user can create a remediation plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id

    # Analyst can create
    resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    plan = resp.json()
    assert plan["state"] == "DRAFT"
    assert plan["finding_id"] == fid
    assert len(plan["proposed_actions"]) > 0

    # Admin can also create for a new finding
    with SessionLocal() as db:
        f2 = create_db_finding(db, rule_id="SG-001", service="ec2", resource_type="security_group", resource_id="sg-12345678")
        fid2 = f2.finding_id
    resp2 = client.post(f"/api/v1/remediations/plans?finding_id={fid2}", headers=admin_headers)
    assert resp2.status_code == 201


def test_REM_02_create_plan_unauthenticated(client):
    """REM-02: Unauthenticated user cannot create a plan."""
    resp = client.post("/api/v1/remediations/plans?finding_id=some-finding-id")
    assert resp.status_code == 401


def test_REM_03_create_plan_viewer_forbidden(client, viewer_headers):
    """REM-03: VIEWER cannot create a plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=viewer_headers)
    assert resp.status_code == 403


def test_REM_04_create_plan_operator_forbidden(client, operator_headers):
    """REM-04: OPERATOR cannot create a plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=operator_headers)
    assert resp.status_code == 403


def test_REM_05_create_plan_unknown_finding_rejected(client, analyst_headers):
    """REM-05: Unknown finding ID is rejected."""
    fake_id = str(uuid.uuid4())
    resp = client.post(f"/api/v1/remediations/plans?finding_id={fake_id}", headers=analyst_headers)
    assert resp.status_code == 400
    assert "not found" in resp.json()["message"].lower()


def test_REM_06_create_plan_duplicate_active_rejected(client, analyst_headers):
    """REM-06: Duplicate remediation plans are rejected if an active plan exists."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id

    # First plan
    resp1 = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    assert resp1.status_code == 201

    # Duplicate plan creation attempt
    resp2 = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    assert resp2.status_code == 400
    assert "already exists" in resp2.json()["message"]


def test_REM_07_create_plan_unsupported_rule_rejected(client, analyst_headers):
    """REM-07: Unknown or unsupported rule IDs are rejected."""
    with SessionLocal() as db:
        # CT-001 is a cloudtrail rule with no auto-remediation strategy
        f = create_db_finding(db, rule_id="CT-001")
        fid = f.finding_id
    resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    assert resp.status_code == 400
    assert "no supported remediation strategy" in resp.json()["message"].lower()


# ── B. STRATEGY AND ACTION SAFETY ─────────────────────────────────────────────

def test_REM_08_strategy_only_explicit_allowlisted_actions():
    """REM-08: Only explicitly allowlisted remediation actions can be generated."""
    allowed_action_types = {"ENABLE_S3_PUBLIC_ACCESS_BLOCK", "DISABLE_SECURITY_GROUP_INGRESS"}
    for rule_id, strategy in STRATEGIES.items():
        assert strategy.action_type in allowed_action_types


def test_REM_09_unknown_remediation_action_rejected():
    """REM-09: Unknown remediation actions are rejected by provider."""
    provider = DemoRemediationProvider()
    action = RemediationAction(
        action_type="DROP_ALL_TABLES",
        provider="demo",
        service="s3",
        resource_identifier="test-bucket",
        description="Dangerous action",
        safety=RemediationSafety.HIGH_RISK,
        parameters={},
    )
    with pytest.raises(ValueError, match="Unsupported action type"):
        provider.validate_action(action)


def test_REM_10_unknown_parameters_rejected_fail_closed():
    """REM-10: Unknown parameters are rejected, fail closed."""
    provider = DemoRemediationProvider()
    action = RemediationAction(
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        provider="demo",
        service="s3",
        resource_identifier="test-bucket",
        description="Valid action with malicious extra param",
        safety=RemediationSafety.MEDIUM_RISK,
        parameters={"bucket_name": "my-bucket", "malicious_payload": "rm -rf /"},
    )
    with pytest.raises(ValueError, match="Unknown parameters"):
        provider.validate_action(action)


def test_REM_11_invalid_parameter_types_values_rejected():
    """REM-11: Invalid parameter types or invalid parameter values are rejected."""
    provider = DemoRemediationProvider()
    # Integer instead of string
    action1 = RemediationAction(
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        provider="demo",
        service="s3",
        resource_identifier="test-bucket",
        description="Invalid type",
        safety=RemediationSafety.MEDIUM_RISK,
        parameters={"bucket_name": 12345},
    )
    with pytest.raises(ValueError, match="Invalid 'bucket_name' parameter"):
        provider.validate_action(action1)

    # Empty string
    action2 = RemediationAction(
        action_type="DISABLE_SECURITY_GROUP_INGRESS",
        provider="demo",
        service="ec2",
        resource_identifier="sg-123",
        description="Empty value",
        safety=RemediationSafety.MEDIUM_RISK,
        parameters={"group_id": "   "},
    )
    with pytest.raises(ValueError, match="Invalid 'group_id' parameter"):
        provider.validate_action(action2)


def test_REM_12_destructive_actions_strictly_blocked():
    """REM-12: DESTRUCTIVE remediation actions are strictly blocked."""
    provider = DemoRemediationProvider()
    action = RemediationAction(
        action_type="ENABLE_S3_PUBLIC_ACCESS_BLOCK",
        provider="demo",
        service="s3",
        resource_identifier="test-bucket",
        description="Destructive marked action",
        safety=RemediationSafety.DESTRUCTIVE,
        parameters={"bucket_name": "my-bucket"},
    )
    with pytest.raises(ValueError, match="DESTRUCTIVE remediation actions are strictly blocked"):
        provider.validate_action(action)


def test_REM_13_no_arbitrary_commands_or_api_calls():
    """REM-13: No arbitrary command execution, shell execution, or arbitrary AWS API operation is possible."""
    aws_provider = AWSRemediationProvider("test_key", "test_secret")
    # Attempting to invoke an arbitrary boto3 method
    action = RemediationAction(
        action_type="TERMINATE_INSTANCES",
        provider="aws",
        service="ec2",
        resource_identifier="i-12345678",
        description="Arbitrary EC2 termination",
        safety=RemediationSafety.HIGH_RISK,
        parameters={"InstanceIds": ["i-12345678"]},
    )
    with pytest.raises(ValueError, match="Unsupported AWS action type"):
        aws_provider.validate_action(action)


# ── C. VALIDATION ─────────────────────────────────────────────────────────────

def test_REM_14_validate_plan_authorized_analyst(client, analyst_headers):
    """REM-14: Authorized SECURITY_ANALYST can validate a remediation plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]

    val_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    assert val_resp.status_code == 200
    assert val_resp.json()["state"] == "PENDING_APPROVAL"
    assert val_resp.json()["validation_result"] == "VALID"


def test_REM_15_validate_plan_unauthorized_roles_forbidden(client, analyst_headers, viewer_headers, operator_headers):
    """REM-15: Unauthorized roles (VIEWER, OPERATOR) cannot validate."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]

    # Viewer
    v_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=viewer_headers)
    assert v_resp.status_code == 403

    # Operator
    o_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=operator_headers)
    assert o_resp.status_code == 403


def test_REM_16_validate_invalid_state_transition_rejected(client, analyst_headers, admin_headers):
    """REM-16: Invalid state transitions during validation are rejected."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]

    # Validate first time -> transitions to PENDING_APPROVAL
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)

    # Second validation attempt on PENDING_APPROVAL must be rejected
    val_resp2 = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    assert val_resp2.status_code == 400
    assert "must be in draft state" in val_resp2.json()["message"].lower()


def test_REM_17_validation_failure_prevents_approval_execution(client, analyst_headers, admin_headers):
    """REM-17: Validation failure prevents approval/execution."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]

    # Corrupt action parameters in DB to trigger provider validation failure
    with SessionLocal() as db:
        action = db.scalar(select(RemediationActionDBModel).where(RemediationActionDBModel.remediation_id == plan_id))
        action.parameters = {"invalid_param": "bad"}
        db.commit()

    val_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    assert val_resp.status_code == 400
    assert "validation failed" in val_resp.json()["message"].lower()

    # Plan remains in DRAFT (or INVALID) upon failure; attempting approval must fail
    app_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    assert app_resp.status_code == 400
    assert "must be in pending_approval state" in app_resp.json()["message"].lower()


# ── D. APPROVAL AND SEPARATION OF DUTIES ───────────────────────────────────────

def test_REM_18_approve_plan_authorized_approver(client, analyst_headers, admin_headers, analyst2_headers):
    """REM-18: Authorized approver can approve a validated plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    # Created and validated by test_analyst
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)

    # Approved by test_analyst2 (independent analyst)
    app_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=analyst2_headers)
    assert app_resp.status_code == 200
    assert app_resp.json()["state"] == "APPROVED"
    assert app_resp.json()["approved_by"] is not None


def test_REM_19_approval_separation_of_duties_self_approval_forbidden(client, analyst_headers):
    """REM-19: Plan creator cannot approve their own remediation plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)

    # Self-approval attempt
    self_app = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=analyst_headers)
    assert self_app.status_code == 403
    assert "separation of duties" in self_app.json()["message"].lower()


def test_REM_20_approve_plan_unauthorized_roles_forbidden(client, analyst_headers, viewer_headers, operator_headers):
    """REM-20: Unauthorized roles (OPERATOR, VIEWER) cannot approve."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)

    assert client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=operator_headers).status_code == 403


def test_REM_21_rejected_plan_cannot_be_executed(client, analyst_headers, admin_headers, operator_headers):
    """REM-21: Rejected plans cannot be executed."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)

    # Reject plan
    rej_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/reject", headers=admin_headers)
    assert rej_resp.status_code == 200
    assert rej_resp.json()["state"] == "REJECTED"

    # Try executing rejected plan
    exec_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert exec_resp.status_code == 400
    assert "cannot execute plan in state 'rejected'" in exec_resp.json()["message"].lower()


def test_REM_22_invalid_approval_state_transition_rejected(client, analyst_headers, admin_headers):
    """REM-22: Invalid approval state transitions are rejected (e.g. approving a DRAFT plan directly)."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]

    # Approving directly from DRAFT must fail
    app_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    assert app_resp.status_code == 400
    assert "must be in pending_approval state" in app_resp.json()["message"].lower()


# ── E. EXECUTION ─────────────────────────────────────────────────────────────

def test_REM_23_execute_plan_authorized_operator(client, analyst_headers, admin_headers, operator_headers):
    """REM-23: Authorized OPERATOR can execute an approved remediation plan."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)

    exec_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert exec_resp.status_code == 200
    assert exec_resp.json()["state"] == "EXECUTED"
    assert exec_resp.json()["execution_started_at"] is not None


def test_REM_24_execute_plan_viewer_forbidden(client, analyst_headers, admin_headers, viewer_headers):
    """REM-24: VIEWER cannot execute."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)

    assert client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=viewer_headers).status_code == 403


def test_REM_25_execute_plan_analyst_forbidden(client, analyst_headers, admin_headers):
    """REM-25: SECURITY_ANALYST cannot execute (RBAC separation)."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)

    assert client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=analyst_headers).status_code == 403


def test_REM_26_execute_before_approval_rejected(client, analyst_headers, operator_headers):
    """REM-26: Execution before approval is rejected."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]

    # Execute on DRAFT
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert resp.status_code == 400
    assert "must be in approved state" in resp.json()["message"].lower()


def test_REM_27_execution_failure_transitions_to_failed(client, analyst_headers, admin_headers, operator_headers):
    """REM-27: Execution failure transitions to EXECUTION_FAILED correctly."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)

    # Corrupt action parameters in DB so execution fails
    with SessionLocal() as db:
        action = db.scalar(select(RemediationActionDBModel).where(RemediationActionDBModel.remediation_id == plan_id))
        action.action_type = "INVALID_UNSUPPORTED_ACTION"
        db.commit()

    exec_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert exec_resp.status_code == 200
    assert exec_resp.json()["state"] == "EXECUTION_FAILED"


# ── F. CONCURRENCY AND IDEMPOTENCY ───────────────────────────────────────────

def test_REM_28_duplicate_sequential_execution_rejected(client, analyst_headers, admin_headers, operator_headers):
    """REM-28: Duplicate sequential execution requests cannot execute the same plan twice."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)

    # First execution succeeds
    resp1 = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert resp1.status_code == 200
    assert resp1.json()["state"] == "EXECUTED"

    # Second execution attempt is blocked
    resp2 = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert resp2.status_code == 400
    assert "must be in approved state" in resp2.json()["message"].lower()


def test_REM_29_concurrent_execution_race_condition_safe():
    """
    REM-29: Concurrent execution requests are safe.
    REAL concurrency test running simultaneous execution attempts against REAL PostgreSQL.
    Proves that with_for_update() ensures exactly one execution claims the plan.
    """
    service = RemediationService()

    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
        plan = service.create_plan(db, fid, "user-analyst")
        service.validate_plan(db, plan.remediation_id, "user-analyst")
        service.approve_plan(db, plan.remediation_id, "user-admin")
        plan_id = plan.remediation_id

    results = []
    errors = []

    def execute_attempt(worker_id):
        with SessionLocal() as db:
            try:
                res = service.execute_plan(db, plan_id, f"operator-{worker_id}")
                return ("SUCCESS", res.state.value)
            except Exception as e:
                return ("ERROR", str(e))

    # Run 5 concurrent execution attempts simultaneously
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(execute_attempt, i) for i in range(5)]
        for f in concurrent.futures.as_completed(futures):
            status, msg = f.result()
            if status == "SUCCESS":
                results.append(msg)
            else:
                errors.append(msg)

    # Exactly ONE thread must succeed
    assert len(results) == 1, f"Expected exactly 1 success, got {len(results)}: {results}"
    assert results[0] == "EXECUTED"
    # All other 4 threads must fail due to row-level lock state transition
    assert len(errors) == 4
    for err in errors:
        assert "must be in approved state" in err.lower()

    # Verify real PostgreSQL database executions table has exactly 1 execution record
    with SessionLocal() as db:
        executions = db.scalars(
            select(RemediationExecutionDBModel).where(RemediationExecutionDBModel.remediation_id == plan_id)
        ).all()
        assert len(executions) == 1


def test_REM_30_executing_or_terminal_cannot_be_executed_again(client, analyst_headers, admin_headers, operator_headers):
    """REM-30: Plans already in terminal states cannot be executed again."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)

    # Plan is now VERIFIED_FIXED (terminal)
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert resp.status_code == 400


# ── G. INDEPENDENT VERIFICATION ───────────────────────────────────────────────

def test_REM_31_execution_success_not_automatic_remediation_success(client, analyst_headers, admin_headers, operator_headers):
    """REM-31: Execution success does NOT automatically mean remediation success."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)

    exec_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    # Plan is EXECUTED, NOT VERIFIED_FIXED yet
    assert exec_resp.json()["state"] == "EXECUTED"

    # Finding is VERIFICATION_PENDING, NOT RESOLVED yet
    with SessionLocal() as db:
        finding = db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid))
        assert finding.status == FindingStatus.VERIFICATION_PENDING.value


def test_REM_32_independent_verification_queries_provider_state(client, analyst_headers, admin_headers, operator_headers):
    """REM-32: Independent verification queries provider state separately from execution."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)

    # Independent verify queries demo provider state
    ver_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)
    assert ver_resp.status_code == 200
    assert ver_resp.json()["state"] == "VERIFIED_FIXED"


def test_REM_33_successful_verification_transitions_states(client, analyst_headers, admin_headers, operator_headers):
    """REM-33: Successful verification transitions Remediation to VERIFIED_FIXED and Finding to RESOLVED."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    ver_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)

    assert ver_resp.json()["state"] == "VERIFIED_FIXED"
    with SessionLocal() as db:
        finding = db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid))
        assert finding.status == FindingStatus.RESOLVED.value


def test_REM_34_failed_verification_transitions_states(client, analyst_headers, admin_headers, operator_headers):
    """REM-34: Verification failure transitions Remediation to VERIFICATION_FAILED and Finding to STILL_VULNERABLE."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)

    # Manually clear the demo provider state before verification to simulate a failed fix
    DEMO_STATE["s3_blocks"].clear()

    ver_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)
    assert ver_resp.json()["state"] == "VERIFICATION_FAILED"
    with SessionLocal() as db:
        finding = db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid))
        assert finding.status == FindingStatus.STILL_VULNERABLE.value


def test_REM_35_verification_failure_no_automatic_rollback(client, analyst_headers, admin_headers, operator_headers):
    """REM-35: Verification failure does NOT automatically execute rollback."""
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)

    # Force verification failure
    DEMO_STATE["s3_blocks"].clear()
    ver_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)
    assert ver_resp.json()["state"] == "VERIFICATION_FAILED"

    # Verify no rollback execution was created or executed
    with SessionLocal() as db:
        plan = db.scalar(select(RemediationPlanDBModel).where(RemediationPlanDBModel.remediation_id == plan_id))
        assert plan.state == RemediationState.VERIFICATION_FAILED.value
        # Executions count remains 1
        assert len(plan.executions) == 1


# ── H. AUDIT ─────────────────────────────────────────────────────────────────

def test_REM_36_lifecycle_audit_events_complete_and_sanitized(client, analyst_headers, admin_headers, operator_headers):
    """
    REM-36: Every significant lifecycle transition creates an audit event.
    Events include event_id, remediation_id, actor_user_id, timestamp, states, sanitized details.
    """
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)

    audit_resp = client.get(f"/api/v1/remediations/plans/{plan_id}/audit", headers=analyst_headers)
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    assert len(events) >= 5  # PLAN_CREATED, PLAN_VALIDATED, PLAN_APPROVED, PLAN_EXECUTED, VERIFICATION_COMPLETED

    event_types = [e["event_type"] for e in events]
    assert "PLAN_CREATED" in event_types
    assert "PLAN_VALIDATED" in event_types
    assert "PLAN_APPROVED" in event_types
    assert "VERIFICATION_COMPLETED" in event_types

    for e in events:
        assert e["event_id"] is not None
        assert e["remediation_id"] == plan_id
        assert e["actor_user_id"] is not None
        assert e["timestamp"] is not None
        assert isinstance(e["safe_details"], dict)


# ==============================================================================
# PART 3 — IMMUTABLE AUDIT VERIFICATION (AUDIT-01 -> AUDIT-10)
# ==============================================================================

def test_AUDIT_01_normal_users_cannot_update_audit_records(client, admin_headers):
    """AUDIT-01: Normal API users cannot update audit records (no PUT/PATCH endpoints)."""
    resp_put = client.put("/api/v1/remediations/plans/some-id/audit", json={}, headers=admin_headers)
    assert resp_put.status_code in (404, 405)
    resp_patch = client.patch("/api/v1/remediations/plans/some-id/audit", json={}, headers=admin_headers)
    assert resp_patch.status_code in (404, 405)


def test_AUDIT_02_normal_users_cannot_delete_audit_records(client, admin_headers):
    """AUDIT-02: Normal API users cannot delete audit records (no DELETE endpoint)."""
    resp_del = client.delete("/api/v1/remediations/plans/some-id/audit", headers=admin_headers)
    assert resp_del.status_code in (404, 405)


def test_AUDIT_03_no_service_method_permits_audit_mutation():
    """AUDIT-03: No normal repository/service method permits mutation of an existing audit event."""
    service = RemediationService()
    assert not hasattr(service, "update_audit_event")
    assert not hasattr(service, "delete_audit_event")
    assert not hasattr(service, "modify_audit_record")


def test_AUDIT_04_passwords_not_stored_in_audit():
    """AUDIT-04: Passwords are not stored in audit details."""
    dirty = {"user_password": "PlainPassword123!", "normal_info": "safe"}
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["user_password"] == "***REDACTED***"
    assert cleaned["normal_info"] == "safe"


def test_AUDIT_05_aws_access_keys_not_stored_in_audit():
    """AUDIT-05: AWS access keys are not stored in audit details."""
    dirty = {"aws_access_key": "AKIAIOSFODNN7EXAMPLE", "info": "configured"}
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["aws_access_key"] == "***REDACTED***"


def test_AUDIT_06_aws_secret_keys_not_stored_in_audit():
    """AUDIT-06: AWS secret keys are not stored in audit details."""
    dirty = {"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["secret_key"] == "***REDACTED***"


def test_AUDIT_07_jwt_access_tokens_not_stored_in_audit():
    """AUDIT-07: JWT access tokens are not stored."""
    dirty = {"auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozGzXv"}
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["auth_token"] == "***REDACTED***"


def test_AUDIT_08_refresh_tokens_not_stored_in_audit():
    """AUDIT-08: Refresh tokens are not stored."""
    dirty = {"refresh_token": "7b8f0a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a"}
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["refresh_token"] == "***REDACTED***"


def test_AUDIT_09_password_hashes_not_stored_in_audit():
    """AUDIT-09: Password hashes are not stored."""
    dirty = {"hash_val": "$argon2id$v=19$m=65536,t=3,p=4$somehashvalue"}
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["hash_val"] == "***REDACTED***"


def test_AUDIT_10_sensitive_fields_sanitized_or_rejected():
    """AUDIT-10: Sensitive fields supplied accidentally in details are sanitized or rejected."""
    dirty = {
        "credential_payload": {"nested_secret": "my-secret"},
        "api_key": "supersecretkey12345",
        "description": "normal operation"
    }
    cleaned = sanitize_audit_details(dirty)
    assert cleaned["api_key"] == "***REDACTED***"
    assert cleaned["credential_payload"] == "***REDACTED***"
    assert cleaned["description"] == "normal operation"


# ==============================================================================
# PART 4 — RBAC FINAL MATRIX TESTS
# ==============================================================================

def test_RBAC_matrix_all_roles_and_endpoints(
    client, admin_headers, analyst_headers, analyst2_headers, operator_headers, viewer_headers
):
    """
    Verify complete permission matrix across all 4 roles:
    Permission                   ADMIN   SECURITY_ANALYST   OPERATOR   VIEWER
    remediations.read            YES     YES                YES        YES
    remediations.create          YES     YES                NO         NO
    remediations.validate        YES     YES                NO         NO
    remediations.approve         YES     YES*               NO         NO
    remediations.execute         YES     NO                 YES        NO
    remediations.cancel          YES     YES                NO         NO
    remediations.audit.read      YES     YES                YES        NO
    """
    # 1. remediations.create
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id

    assert client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=operator_headers).status_code == 403
    p_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    assert p_resp.status_code == 201
    plan_id = p_resp.json()["remediation_id"]

    # 2. remediations.read
    assert client.get(f"/api/v1/remediations/plans/{plan_id}", headers=viewer_headers).status_code == 200
    assert client.get(f"/api/v1/remediations/plans/{plan_id}", headers=operator_headers).status_code == 200
    assert client.get(f"/api/v1/remediations/plans/{plan_id}", headers=analyst_headers).status_code == 200
    assert client.get(f"/api/v1/remediations/plans/{plan_id}", headers=admin_headers).status_code == 200

    # 3. remediations.validate
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=operator_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers).status_code == 200

    # 4. remediations.approve (SECURITY_ANALYST may approve only when NOT creator)
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=operator_headers).status_code == 403
    # Self-approval by creator analyst is forbidden
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=analyst_headers).status_code == 403
    # Approval by different analyst succeeds
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=analyst2_headers).status_code == 200

    # 5. remediations.execute
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=analyst_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers).status_code == 200

    # 6. remediations.audit.read
    assert client.get(f"/api/v1/remediations/plans/{plan_id}/audit", headers=viewer_headers).status_code == 403
    assert client.get(f"/api/v1/remediations/plans/{plan_id}/audit", headers=operator_headers).status_code == 200
    assert client.get(f"/api/v1/remediations/plans/{plan_id}/audit", headers=analyst_headers).status_code == 200
    assert client.get(f"/api/v1/remediations/plans/{plan_id}/audit", headers=admin_headers).status_code == 200

    # 7. remediations.cancel (test on fresh plan)
    with SessionLocal() as db:
        f_cancel = create_db_finding(db, rule_id="S3-001")
        fid_cancel = f_cancel.finding_id
    p_cancel = client.post(f"/api/v1/remediations/plans?finding_id={fid_cancel}", headers=analyst_headers).json()["remediation_id"]
    assert client.post(f"/api/v1/remediations/plans/{p_cancel}/cancel", headers=viewer_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{p_cancel}/cancel", headers=operator_headers).status_code == 403
    assert client.post(f"/api/v1/remediations/plans/{p_cancel}/cancel", headers=analyst_headers).status_code == 200


# ==============================================================================
# PART 5 — FINDING STATE VS REMEDIATION STATE INDEPENDENCE
# ==============================================================================

def test_finding_and_remediation_state_independence(client, analyst_headers, admin_headers, operator_headers):
    """
    Verify FindingStatus and RemediationState remain decoupled across all 5 milestones:
    1. Plan created: Finding = OPEN, Remediation = DRAFT
    2. Plan validated/approved: Finding = OPEN, Remediation = PENDING_APPROVAL / APPROVED
    3. Execution: Finding = VERIFICATION_PENDING, Remediation = EXECUTED
    4. Successful verification: Finding = RESOLVED, Remediation = VERIFIED_FIXED
    """
    with SessionLocal() as db:
        f = create_db_finding(db, rule_id="S3-001")
        fid = f.finding_id

    # 1. Plan created
    plan_resp = client.post(f"/api/v1/remediations/plans?finding_id={fid}", headers=analyst_headers)
    plan_id = plan_resp.json()["remediation_id"]
    assert plan_resp.json()["state"] == "DRAFT"
    with SessionLocal() as db:
        assert db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid)).status == FindingStatus.OPEN.value

    # 2. Plan validated & approved
    val_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    assert val_resp.json()["state"] == "PENDING_APPROVAL"
    with SessionLocal() as db:
        assert db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid)).status == FindingStatus.OPEN.value

    app_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    assert app_resp.json()["state"] == "APPROVED"
    with SessionLocal() as db:
        assert db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid)).status == FindingStatus.OPEN.value

    # 3. Execution
    exec_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert exec_resp.json()["state"] == "EXECUTED"
    with SessionLocal() as db:
        assert db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid)).status == FindingStatus.VERIFICATION_PENDING.value

    # 4. Successful verification
    ver_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)
    assert ver_resp.json()["state"] == "VERIFIED_FIXED"
    with SessionLocal() as db:
        assert db.scalar(select(FindingDBModel).where(FindingDBModel.finding_id == fid)).status == FindingStatus.RESOLVED.value


# ==============================================================================
# PART 6 & 7 — PROVIDER & STATE MACHINE AUDIT
# ==============================================================================

def test_state_machine_valid_and_invalid_transitions():
    """Test every valid and blocked invalid transition in the state machine."""
    # Valid transitions
    assert is_valid_transition(RemediationState.DRAFT, RemediationState.VALIDATED)
    assert is_valid_transition(RemediationState.DRAFT, RemediationState.PENDING_APPROVAL)
    assert is_valid_transition(RemediationState.DRAFT, RemediationState.CANCELLED)
    assert is_valid_transition(RemediationState.VALIDATED, RemediationState.PENDING_APPROVAL)
    assert is_valid_transition(RemediationState.PENDING_APPROVAL, RemediationState.APPROVED)
    assert is_valid_transition(RemediationState.PENDING_APPROVAL, RemediationState.REJECTED)
    assert is_valid_transition(RemediationState.APPROVED, RemediationState.EXECUTING)
    assert is_valid_transition(RemediationState.EXECUTING, RemediationState.EXECUTED)
    assert is_valid_transition(RemediationState.EXECUTING, RemediationState.EXECUTION_FAILED)
    assert is_valid_transition(RemediationState.EXECUTED, RemediationState.VERIFYING)
    assert is_valid_transition(RemediationState.VERIFYING, RemediationState.VERIFIED_FIXED)
    assert is_valid_transition(RemediationState.VERIFYING, RemediationState.VERIFICATION_FAILED)

    # Invalid transitions
    assert not is_valid_transition(RemediationState.DRAFT, RemediationState.EXECUTED)
    assert not is_valid_transition(RemediationState.DRAFT, RemediationState.VERIFIED_FIXED)
    assert not is_valid_transition(RemediationState.REJECTED, RemediationState.EXECUTING)
    assert not is_valid_transition(RemediationState.CANCELLED, RemediationState.EXECUTING)
    assert not is_valid_transition(RemediationState.VERIFIED_FIXED, RemediationState.EXECUTING)
    assert not is_valid_transition(RemediationState.EXECUTION_FAILED, RemediationState.EXECUTING)
    assert not is_valid_transition(RemediationState.VERIFICATION_FAILED, RemediationState.APPROVED)
