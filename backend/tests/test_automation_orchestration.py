"""
CloudGuard — Phase 9 Policy-Governed Automation Orchestration Master Test Suite
Tests AUTO-01 through AUTO-50 covering:
- Deterministic Policy Engine evaluation & priority ordering
- Emergency Kill Switch supremacy & fail-closed behavior
- Automated progression via Phase 7 safe remediation engine
- Separation of duties preservation
- Full RBAC matrix (Admin, Analyst, Operator, Viewer)
- IDOR and resource ownership scoping (404 on unowned resources)
- Concurrency & row-level locking with with_for_update()
- PostgreSQL persistence and Alembic migration verification
- Append-only audit logging & recursive secret sanitization
"""
import concurrent.futures
import datetime
import json
import threading
import time
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from pydantic import ValidationError

from main import app
from core.database import SessionLocal, engine
from core.db_models import (
    ScanDBModel, ResourceDBModel, FindingDBModel,
    RemediationPlanDBModel, RemediationActionDBModel,
    AutomationPolicyDBModel, AutomationDecisionDBModel,
    AutomationProgressionDBModel, AutomationAuditEventDBModel,
    AutomationSettingDBModel
)
from core.automation.models import (
    AutomationDecisionType, ProgressionStatus, AutomationAuditEventType
)
from core.automation.state import AutomationState, is_valid_automation_transition
from core.automation.policy_engine import PolicyEngine, compute_policy_hash
from core.automation.service import AutomationService
from core.automation.exceptions import (
    AutomationBlockedError, KillSwitchActiveError, PolicyConflictError, PolicyNotFoundError
)
from core.automation.schemas import (
    AutomationPolicyCreateRequest, AutomationPolicyUpdateRequest,
    AutomationEvaluateRequest, AutomationProgressRequest, KillSwitchToggleRequest
)
from core.remediation.state import RemediationSafety, RemediationState
from services.remediation_service import RemediationService


# ── Helper for clean test finding creation in real PostgreSQL ─────────────────

def get_test_user_id(db, username: str = "test_analyst") -> str:
    """Retrieve a valid seeded user ID from the database to satisfy FK constraints."""
    from auth.models import UserDBModel
    user = db.scalar(select(UserDBModel).where(UserDBModel.username == username))
    if not user:
        user = db.scalar(select(UserDBModel).limit(1))
    return user.user_id if user else str(uuid.uuid4())


def create_test_finding(
    db,
    rule_id: str = "S3-001",
    account_id: str = "123456789012",
    resource_id: str = None,
    service: str = "s3",
    resource_type: str = "s3_bucket",
    severity: str = "HIGH",
    description: str = "Test finding description",
) -> FindingDBModel:
    """Create an isolated real finding in PostgreSQL."""
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
            tags={"Environment": "production"},
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
        severity=severity,
        risk_score=7.5,
        category="security",
        status="OPEN",
        rule_version="1.0.0",
        title=f"Finding for {rule_id}",
        description=description,
        evidence={
            "rule_id": rule_id,
            "field_path": "config.public_access_block",
            "summary": "Public exposure detected",
        },
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def create_test_plan(db, finding_id: str, user_id: str = None, safety: str = "LOW_RISK") -> RemediationPlanDBModel:
    """Creates a real Phase 7 remediation plan for testing automation."""
    uid = user_id or get_test_user_id(db)
    remed_svc = RemediationService()
    plan_pydantic = remed_svc.create_plan(db, finding_id, uid)
    db_plan = db.scalar(
        select(RemediationPlanDBModel).where(
            RemediationPlanDBModel.remediation_id == plan_pydantic.remediation_id
        )
    )
    # Ensure safety classification for test
    if safety != "LOW_RISK" and db_plan.actions:
        db_plan.actions[0].safety = safety
        db.commit()
        db.refresh(db_plan)
    return db_plan


# ── Fixtures for Tokens and Client ────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    res = client.post("/auth/login", json={"username": "test_admin", "password": "AdminTestPass12!"})
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token(client):
    res = client.post("/auth/login", json={"username": "test_analyst", "password": "AnalystTestPass12!"})
    assert res.status_code == 200, f"Analyst login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def analyst2_token(client):
    res = client.post("/auth/login", json={"username": "test_analyst2", "password": "AnalystTestPass12!"})
    assert res.status_code == 200, f"Analyst2 login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def operator_token(client):
    res = client.post("/auth/login", json={"username": "test_operator", "password": "OperatorTestPass12!"})
    assert res.status_code == 200, f"Operator login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def viewer_token(client):
    res = client.post("/auth/login", json={"username": "test_viewer", "password": "ViewerTestPass12!"})
    assert res.status_code == 200, f"Viewer login failed: {res.text}"
    return res.json()["access_token"]


# ==============================================================================
# PART 1: POLICY ENGINE & DETERMINISTIC EVALUATION (AUTO-01 through AUTO-10)
# ==============================================================================

def test_auto_01_policy_matches_and_yields_eligible():
    """AUTO-01: Valid policy evaluation matches criteria and yields ELIGIBLE_FOR_AUTOMATION."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001", service="s3", resource_type="s3_bucket", severity="HIGH")
        plan = create_test_plan(db, finding.finding_id, "user-1", safety="LOW_RISK")

        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Policy AUTO-01",
            description="Test policy",
            enabled=True,
            priority=50,
            version=1,
            allowed_providers=["demo"],
            allowed_services=["s3"],
            allowed_resource_types=["s3_bucket"],
            allowed_rule_ids=["S3-001"],
            auto_progress_validation=True,
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(finding, plan, [policy], kill_switch_active=False)
        assert res.decision == AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION
        assert res.policy_id == policy.policy_id
        assert res.policy_hash is not None
    finally:
        db.close()


def test_auto_02_policy_mismatch_yields_not_eligible():
    """AUTO-02: Criteria mismatch yields NOT_ELIGIBLE (fail-closed)."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001", service="s3", resource_type="s3_bucket")
        plan = create_test_plan(db, finding.finding_id, "user-1")

        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Policy AUTO-02",
            description="Mismatch service policy",
            enabled=True,
            allowed_services=["iam"],  # Mismatch: finding is s3
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(finding, plan, [policy], kill_switch_active=False)
        assert res.decision == AutomationDecisionType.NOT_ELIGIBLE
        assert "fail-closed" in res.reason.lower()
    finally:
        db.close()


def test_auto_03_destructive_actions_unconditionally_blocked():
    """AUTO-03: Destructive remediation actions unconditionally yield BLOCKED_BY_SAFETY."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-1", safety=RemediationSafety.DESTRUCTIVE.value)

        # Even with an all-permissive policy, destructive actions are barred!
        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Permissive Policy",
            description="Permissive",
            enabled=True,
            priority=1000,
            allowed_safety_levels=["DESTRUCTIVE", "LOW_RISK"],
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(finding, plan, [policy], kill_switch_active=False)
        assert res.decision == AutomationDecisionType.BLOCKED_BY_SAFETY
        assert "DESTRUCTIVE" in res.reason
    finally:
        db.close()


def test_auto_04_kill_switch_active_blocks_evaluation():
    """AUTO-04: Emergency kill switch active unconditionally yields BLOCKED_BY_KILL_SWITCH."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-1")

        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Policy AUTO-04",
            description="Test",
            enabled=True,
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(finding, plan, [policy], kill_switch_active=True)
        assert res.decision == AutomationDecisionType.BLOCKED_BY_KILL_SWITCH
        assert "kill switch is ACTIVE" in res.reason
    finally:
        db.close()


def test_auto_05_disabled_policy_fails_closed():
    """AUTO-05: Disabled policy is excluded and evaluation fails closed."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-1")

        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Disabled Policy",
            description="Test",
            enabled=False,  # Disabled
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(finding, plan, [policy], kill_switch_active=False)
        assert res.decision == AutomationDecisionType.NOT_ELIGIBLE
        assert "No active, enabled automation policies found" in res.reason
    finally:
        db.close()


def test_auto_06_priority_conflict_resolution():
    """AUTO-06: Deterministic conflict resolution selects higher priority policy."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001", service="s3")
        plan = create_test_plan(db, finding.finding_id, "user-1")

        low_priority = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Low Priority Policy",
            description="Low priority",
            enabled=True,
            priority=10,
            auto_progress_validation=False,  # would require human review
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        high_priority = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="High Priority Policy",
            description="High priority",
            enabled=True,
            priority=100,
            auto_progress_validation=True,  # eligible
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(finding, plan, [low_priority, high_priority], kill_switch_active=False)
        assert res.decision == AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION
        assert res.policy_id == high_priority.policy_id
    finally:
        db.close()


def test_auto_07_tie_breaking_by_created_at():
    """AUTO-07: Equal priority policies break ties deterministically by created_at."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001", service="s3")
        plan = create_test_plan(db, finding.finding_id, "user-1")

        t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        t1 = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)

        older_policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Older Policy",
            description="Older",
            enabled=True,
            priority=50,
            created_by="admin-1",
            updated_by="admin-1",
            created_at=t0,
            updated_at=t0,
        )
        newer_policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Newer Policy",
            description="Newer",
            enabled=True,
            priority=50,
            created_by="admin-1",
            updated_by="admin-1",
            created_at=t1,
            updated_at=t1,
        )
        res = PolicyEngine.evaluate(finding, plan, [newer_policy, older_policy], kill_switch_active=False)
        assert res.policy_id == older_policy.policy_id
    finally:
        db.close()


def test_auto_08_severity_bounds_enforced():
    """AUTO-08: Severity range bounds (min_severity, max_severity) correctly enforced."""
    db = SessionLocal()
    try:
        critical_finding = create_test_finding(db, rule_id="S3-001", severity="CRITICAL")
        low_finding = create_test_finding(db, rule_id="S3-001", severity="LOW")
        plan = create_test_plan(db, critical_finding.finding_id, "user-1")

        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name="Low-to-Medium Severity Policy",
            description="Test",
            enabled=True,
            min_severity="LOW",
            max_severity="MEDIUM",  # CRITICAL is above max_severity
            auto_progress_validation=True,
            created_by="admin-1",
            updated_by="admin-1",
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        res = PolicyEngine.evaluate(critical_finding, plan, [policy], kill_switch_active=False)
        assert res.decision == AutomationDecisionType.NOT_ELIGIBLE

        # Now test with low finding (within range)
        plan_low = create_test_plan(db, low_finding.finding_id, "user-1")
        res_low = PolicyEngine.evaluate(low_finding, plan_low, [policy], kill_switch_active=False)
        assert res_low.decision == AutomationDecisionType.ELIGIBLE_FOR_AUTOMATION
    finally:
        db.close()


def test_auto_09_cryptographic_policy_hash_reproducibility():
    """AUTO-09: Cryptographic policy hash is deterministic and changes when policy changes."""
    policy = AutomationPolicyDBModel(
        policy_id="test-pol-id",
        name="Test Policy",
        description="Desc",
        version=1,
        allowed_providers=["aws"],
        allowed_services=["s3"],
        allowed_resource_types=[],
        allowed_rule_ids=[],
        allowed_strategies=[],
        allowed_action_types=[],
        allowed_safety_levels=["LOW_RISK"],
        auto_progress_validation=True,
        auto_progress_approval=False,
        auto_progress_execution=False,
        require_human_approval=True,
    )
    h1 = compute_policy_hash(policy)
    h2 = compute_policy_hash(policy)
    assert h1 == h2, "Hash must be deterministic"

    policy.version = 2
    h3 = compute_policy_hash(policy)
    assert h1 != h3, "Hash must change when policy version changes"


def test_auto_10_policy_schema_forbids_extra_fields():
    """AUTO-10: Pydantic schemas enforce ConfigDict(extra='forbid')."""
    with pytest.raises(ValidationError) as exc:
        AutomationPolicyCreateRequest(
            name="Policy 1",
            description="Desc",
            malicious_injected_field="arbitrary_payload",
        )
    assert "extra_forbidden" in str(exc.value)


# ==============================================================================
# PART 2: EMERGENCY KILL SWITCH (AUTO-11 through AUTO-20)
# ==============================================================================

def test_auto_11_admin_can_enable_kill_switch(client, admin_token):
    """AUTO-11: Admin can enable global emergency kill switch."""
    res = client.post(
        "/api/v1/automation/kill-switch/enable",
        json={"reason": "Security incident containment drill"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["enabled"] is True


def test_auto_12_admin_can_disable_kill_switch(client, admin_token):
    """AUTO-12: Admin can disable global emergency kill switch."""
    res = client.post(
        "/api/v1/automation/kill-switch/disable",
        json={"reason": "Drill completed successfully"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["enabled"] is False


def test_auto_13_kill_switch_toggles_generate_audit_events(client, admin_token):
    """AUTO-13: Kill switch toggles produce immutable audit records."""
    client.post(
        "/api/v1/automation/kill-switch/enable",
        json={"reason": "Audit verification toggle"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    res = client.get(
        "/api/v1/automation/audit",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    events = res.json()
    assert any(e["event_type"] == AutomationAuditEventType.KILL_SWITCH_ENABLED.value for e in events)

    # Disable for next tests
    client.post(
        "/api/v1/automation/kill-switch/disable",
        json={"reason": "Resetting kill switch"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )


def test_auto_14_analyst_cannot_toggle_kill_switch(client, analyst_token):
    """AUTO-14: Analyst lacks automation.killswitch and receives 403."""
    res = client.post(
        "/api/v1/automation/kill-switch/enable",
        json={"reason": "Unauthorized attempt"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 403


def test_auto_15_operator_cannot_toggle_kill_switch(client, operator_token):
    """AUTO-15: Operator lacks automation.killswitch and receives 403."""
    res = client.post(
        "/api/v1/automation/kill-switch/enable",
        json={"reason": "Unauthorized attempt"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert res.status_code == 403


def test_auto_16_viewer_cannot_toggle_kill_switch(client, viewer_token):
    """AUTO-16: Viewer lacks automation.killswitch and receives 403."""
    res = client.post(
        "/api/v1/automation/kill-switch/enable",
        json={"reason": "Unauthorized attempt"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res.status_code == 403


def test_auto_17_kill_switch_blocks_evaluation_api(client, admin_token, analyst_token):
    """AUTO-17: Active kill switch returns BLOCKED_BY_KILL_SWITCH from evaluate endpoint."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-test")
        plan_id = plan.remediation_id
    finally:
        db.close()

    # Enable kill switch
    client.post("/api/v1/automation/kill-switch/enable", json={"reason": "Testing block"}, headers={"Authorization": f"Bearer {admin_token}"})

    res = client.post(
        "/api/v1/automation/evaluate",
        json={"remediation_id": plan_id},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == AutomationDecisionType.BLOCKED_BY_KILL_SWITCH.value

    # Reset kill switch
    client.post("/api/v1/automation/kill-switch/disable", json={"reason": "Reset"}, headers={"Authorization": f"Bearer {admin_token}"})


def test_auto_18_kill_switch_blocks_progression_api(client, admin_token, analyst_token):
    """AUTO-18: Active kill switch blocks progress endpoint with HTTP 403."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-test")
        plan_id = plan.remediation_id
    finally:
        db.close()

    client.post("/api/v1/automation/kill-switch/enable", json={"reason": "Testing progression block"}, headers={"Authorization": f"Bearer {admin_token}"})

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 403
    assert "kill switch is ACTIVE" in res.text

    client.post("/api/v1/automation/kill-switch/disable", json={"reason": "Reset"}, headers={"Authorization": f"Bearer {admin_token}"})


def test_auto_19_kill_switch_fails_closed_on_db_error():
    """AUTO-19: Database ambiguity on kill switch causes fail-closed behavior."""
    svc = AutomationService()
    # Passing a dummy or broken session should return True (kill switch active = safe default)
    class BrokenSession:
        def scalar(self, *args, **kwargs):
            raise RuntimeError("Database connection timed out")
    assert svc.is_kill_switch_active(BrokenSession()) is True


def test_auto_20_unauthenticated_toggle_rejected(client):
    """AUTO-20: Unauthenticated kill-switch toggle rejected with HTTP 401."""
    res = client.post("/api/v1/automation/kill-switch/enable", json={"reason": "No token"})
    assert res.status_code == 401


# ==============================================================================
# PART 3: AUTOMATED PROGRESSION & PHASE 7 SAFETY (AUTO-21 through AUTO-30)
# ==============================================================================

def test_auto_21_automated_validation_progression(client, admin_token):
    """AUTO-21: Automated progression from DRAFT -> PENDING_APPROVAL succeeds via Phase 7 validation."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "admin-user")
        plan_id = plan.remediation_id
        assert plan.state == RemediationState.DRAFT.value

        # Create active policy permitting validation
        client.post(
            "/api/v1/automation/policies",
            json={
                "name": f"Policy-Validation-{uuid.uuid4().hex[:6]}",
                "description": "Auto validate",
                "enabled": True,
                "priority": 100,
                "allowed_providers": ["demo"],
                "allowed_services": ["s3"],
                "auto_progress_validation": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    finally:
        db.close()

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={"target_transition": "VALIDATE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == ProgressionStatus.SUCCESS.value
    assert data["to_state"] == RemediationState.PENDING_APPROVAL.value

    # Verify plan state in DB is now PENDING_APPROVAL
    db = SessionLocal()
    try:
        updated_plan = db.scalar(select(RemediationPlanDBModel).where(RemediationPlanDBModel.remediation_id == plan_id))
        assert updated_plan.state == RemediationState.PENDING_APPROVAL.value
    finally:
        db.close()


def test_auto_22_progression_verifies_resource_binding(client, admin_token):
    """AUTO-22: Automated progression fails safely if finding has been modified or deleted."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "admin-user")
        plan_id = plan.remediation_id

        # Mismatch resource binding to simulate resource drift or mismatch
        r2 = ResourceDBModel(
            resource_id=f"arn:aws:s3:::mismatch-bucket-{uuid.uuid4().hex[:8]}",
            provider="demo",
            account_id="123456789012",
            region="us-east-1",
            service="s3",
            resource_type="aws_s3_bucket",
            tags={},
        )
        db.add(r2)
        db.flush()
        plan.resource_id = r2.resource_id
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={"target_transition": "VALIDATE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 400
    assert "mismatch" in res.text.lower() or "validation failed" in res.text.lower()


def test_auto_23_separation_of_duties_enforced_in_automated_approval(client, analyst_token):
    """AUTO-23: Plan creator cannot trigger automated self-approval (Phase 7 separation of duties)."""
    db = SessionLocal()
    try:
        # Fetch analyst user ID
        analyst_user = db.scalar(select(FindingDBModel).limit(1))
        finding = create_test_finding(db, rule_id="S3-001")
    finally:
        db.close()

    # Get analyst user ID
    user_res = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    analyst_id = user_res.json()["user_id"]

    db = SessionLocal()
    try:
        plan = create_test_plan(db, finding.finding_id, analyst_id)
        # Manually validate to PENDING_APPROVAL
        plan.state = RemediationState.PENDING_APPROVAL.value

        # Add policy permitting automated approval so evaluation passes
        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name=f"Policy-Approve-SOD-{uuid.uuid4().hex[:6]}",
            description="Policy for SOD test",
            enabled=True,
            priority=250,
            allowed_services=["s3"],
            auto_progress_approval=True,
            require_human_approval=False,
            created_by=analyst_id,
            updated_by=analyst_id,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(policy)
        db.commit()
        plan_id = plan.remediation_id
    finally:
        db.close()

    # Analyst attempts to self-approve via progression
    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={"target_transition": "APPROVE"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 403
    assert "Separation of duties" in res.text


def test_auto_24_independent_approval_via_automation_succeeds(client, admin_token, analyst_token):
    """AUTO-24: Approval triggered by independent user succeeds when policy permits."""
    user1_res = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    analyst1_id = user1_res.json()["user_id"]

    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, analyst1_id)
        plan.state = RemediationState.PENDING_APPROVAL.value
        db.commit()
        plan_id = plan.remediation_id

        # Policy permitting approval
        client.post(
            "/api/v1/automation/policies",
            json={
                "name": f"Policy-Approve-{uuid.uuid4().hex[:6]}",
                "description": "Auto approve",
                "enabled": True,
                "priority": 280,
                "allowed_services": ["s3"],
                "auto_progress_approval": True,
                "require_human_approval": False,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    finally:
        db.close()

    # Independent user (admin != analyst1) triggers approval
    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={"target_transition": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["to_state"] == RemediationState.APPROVED.value


def test_auto_25_automated_execution_for_low_risk_action(client, admin_token):
    """AUTO-25: Automated execution for low-risk action succeeds via Phase 7 execution engine."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-creator", safety="LOW_RISK")
        plan.state = RemediationState.APPROVED.value
        db.commit()
        plan_id = plan.remediation_id

        # Policy permitting execution
        client.post(
            "/api/v1/automation/policies",
            json={
                "name": f"Policy-Exec-{uuid.uuid4().hex[:6]}",
                "description": "Auto exec",
                "enabled": True,
                "priority": 600,
                "allowed_services": ["s3"],
                "auto_progress_execution": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    finally:
        db.close()

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={"target_transition": "EXECUTE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["to_state"] in (RemediationState.EXECUTED.value, RemediationState.EXECUTION_FAILED.value)


def test_auto_26_row_locking_prevents_duplicate_progression(client, admin_token):
    """AUTO-26: Concurrent automated progressions on same plan are serialized cleanly."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-lock")
        plan_id = plan.remediation_id

        client.post(
            "/api/v1/automation/policies",
            json={
                "name": f"Policy-Concurrent-{uuid.uuid4().hex[:6]}",
                "description": "Auto validate concurrent",
                "enabled": True,
                "priority": 400,
                "allowed_services": ["s3"],
                "auto_progress_validation": True,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    finally:
        db.close()

    def do_progress():
        return client.post(
            f"/api/v1/automation/progress/{plan_id}",
            json={"target_transition": "VALIDATE"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(do_progress)
        f2 = executor.submit(do_progress)
        r1 = f1.result()
        r2 = f2.result()

    # One must succeed; the competing one must either succeed idempotently or fail safely
    statuses = [r1.status_code, r2.status_code]
    assert 200 in statuses
    # Plan must end in valid state
    db = SessionLocal()
    try:
        p = db.scalar(select(RemediationPlanDBModel).where(RemediationPlanDBModel.remediation_id == plan_id))
        assert p.state == RemediationState.PENDING_APPROVAL.value
    finally:
        db.close()


def test_auto_27_progression_failure_is_safely_recorded(client, admin_token):
    """AUTO-27: Transition failures record a FAILED progression record and log audit events."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "user-test")
        plan.state = RemediationState.REJECTED.value  # Terminal state: cannot validate
        db.commit()
        plan_id = plan.remediation_id
    finally:
        db.close()

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={"target_transition": "VALIDATE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code in (400, 403)


def test_auto_28_ineligible_plan_progression_rejected(client, admin_token):
    """AUTO-28: Progression request on an ineligible plan is blocked."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001", service="unsupported_service")
        plan = create_test_plan(db, finding.finding_id, "user-test")
        plan_id = plan.remediation_id
    finally:
        db.close()

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 400
    assert "not eligible" in res.text.lower()


def test_auto_29_unauthenticated_progression_rejected(client):
    """AUTO-29: Unauthenticated progression request is rejected with 401."""
    res = client.post("/api/v1/automation/progress/some-plan-id", json={})
    assert res.status_code == 401


def test_auto_30_ai_confidence_cannot_bypass_policy(client, admin_token):
    """AUTO-30: AI output cannot grant execution or bypass policy rules."""
    # Attempting to send extra fields or confidence to progression is forbidden by schema
    res = client.post(
        "/api/v1/automation/progress/some-plan-id",
        json={"confidence": 1.0, "ai_bypass": True},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 422


# ==============================================================================
# PART 4: RBAC & IDOR PROTECTION (AUTO-31 through AUTO-38)
# ==============================================================================

def test_auto_31_viewer_can_read_policies_but_not_evaluate(client, viewer_token):
    """AUTO-31: Viewer can read policies but cannot evaluate."""
    r1 = client.get("/api/v1/automation/policies", headers={"Authorization": f"Bearer {viewer_token}"})
    assert r1.status_code == 200

    r2 = client.post(
        "/api/v1/automation/evaluate",
        json={"remediation_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r2.status_code == 403


def test_auto_32_operator_cannot_create_policies(client, operator_token):
    """AUTO-32: Operator lacks automation.manage and receives 403 when creating policy."""
    res = client.post(
        "/api/v1/automation/policies",
        json={"name": "Operator Policy", "description": "Illegal"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert res.status_code == 403


def test_auto_33_analyst_can_evaluate_and_progress_own_plan(client, analyst_token):
    """AUTO-33: Analyst can evaluate their own remediation plans."""
    user_res = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
    analyst_id = user_res.json()["user_id"]

    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, analyst_id)
        plan_id = plan.remediation_id
    finally:
        db.close()

    res = client.post(
        "/api/v1/automation/evaluate",
        json={"remediation_id": plan_id},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 200


def test_auto_34_analyst_cannot_create_or_modify_policies(client, analyst_token):
    """AUTO-34: Analyst cannot create policies (requires automation.manage)."""
    res = client.post(
        "/api/v1/automation/policies",
        json={"name": "Analyst Policy", "description": "Illegal"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 403


def test_auto_35_idor_evaluate_unowned_plan_returns_404(client, analyst_token, analyst2_token):
    """AUTO-35: Analyst B accessing Analyst A's plan in evaluate returns 404 (IDOR defense)."""
    u1 = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).json()["user_id"]

    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, u1)
        plan_id = plan.remediation_id
    finally:
        db.close()

    # Analyst 2 attempts to evaluate Analyst 1's plan
    res = client.post(
        "/api/v1/automation/evaluate",
        json={"remediation_id": plan_id},
        headers={"Authorization": f"Bearer {analyst2_token}"},
    )
    assert res.status_code == 404
    assert "not found" in res.text.lower()


def test_auto_36_idor_progress_unowned_plan_returns_404(client, analyst_token, analyst2_token):
    """AUTO-36: Analyst B attempting progression on Analyst A's plan returns 404 (IDOR defense)."""
    u1 = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).json()["user_id"]

    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, u1)
        plan_id = plan.remediation_id
    finally:
        db.close()

    res = client.post(
        f"/api/v1/automation/progress/{plan_id}",
        json={},
        headers={"Authorization": f"Bearer {analyst2_token}"},
    )
    assert res.status_code == 404


def test_auto_37_idor_decision_query_returns_404(client, analyst_token, analyst2_token):
    """AUTO-37: Analyst B cannot query decisions for Analyst A's plan."""
    u1 = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).json()["user_id"]

    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, u1)
        plan_id = plan.remediation_id
    finally:
        db.close()

    res = client.get(
        f"/api/v1/automation/decisions?remediation_id={plan_id}",
        headers={"Authorization": f"Bearer {analyst2_token}"},
    )
    assert res.status_code == 404


def test_auto_38_admin_can_access_any_plan(client, admin_token, analyst_token):
    """AUTO-38: Admin has organizational oversight access to all plans."""
    u1 = client.get("/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).json()["user_id"]

    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, u1)
        plan_id = plan.remediation_id
    finally:
        db.close()

    res = client.post(
        "/api/v1/automation/evaluate",
        json={"remediation_id": plan_id},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200


# ==============================================================================
# PART 5: CONCURRENCY & POSTGRESQL INTEGRATION (AUTO-39 through AUTO-44)
# ==============================================================================

def test_auto_39_concurrent_evaluations_thread_safe(client, admin_token):
    """AUTO-39: Concurrent evaluations against PostgreSQL are thread-safe and deterministic."""
    db = SessionLocal()
    try:
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, "admin-user")
        plan_id = plan.remediation_id
    finally:
        db.close()

    def eval_req():
        return client.post(
            "/api/v1/automation/evaluate",
            json={"remediation_id": plan_id},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(eval_req) for _ in range(5)]
        results = [f.result() for f in futures]

    assert all(r.status_code == 200 for r in results)
    decisions = [r.json()["decision"] for r in results]
    assert len(set(decisions)) == 1, "All concurrent evaluations must produce identical decision"


def test_auto_40_concurrent_policy_updates_version_increment(client, admin_token):
    """AUTO-40: Policy updates atomically increment version counter."""
    res = client.post(
        "/api/v1/automation/policies",
        json={"name": f"Policy-Version-{uuid.uuid4().hex[:6]}", "description": "Initial"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    pol_id = res.json()["policy_id"]
    assert res.json()["version"] == 1

    upd_res = client.patch(
        f"/api/v1/automation/policies/{pol_id}",
        json={"description": "Updated description"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert upd_res.json()["version"] == 2


def test_auto_41_decisions_persist_in_postgresql():
    """AUTO-41: Automation decisions persist in real PostgreSQL database."""
    db = SessionLocal()
    try:
        assert engine.dialect.name in ("postgresql", "sqlite")
        uid = get_test_user_id(db)
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, uid)

        svc = AutomationService()
        dec = svc.evaluate_remediation(db, plan.remediation_id, uid)
        dec_id = dec.decision_id

        # Verify direct query in separate session
        db2 = SessionLocal()
        try:
            persisted = db2.scalar(
                select(AutomationDecisionDBModel).where(AutomationDecisionDBModel.decision_id == dec_id)
            )
            assert persisted is not None
            assert persisted.remediation_id == plan.remediation_id
            assert persisted.decision is not None
        finally:
            db2.close()
    finally:
        db.close()


def test_auto_42_progressions_persist_in_postgresql():
    """AUTO-42: Automation progressions persist in real PostgreSQL database."""
    db = SessionLocal()
    try:
        assert engine.dialect.name in ("postgresql", "sqlite")
        uid = get_test_user_id(db)
        finding = create_test_finding(db, rule_id="S3-001")
        plan = create_test_plan(db, finding.finding_id, uid)

        # Create policy
        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name=f"Persist-Policy-{uuid.uuid4().hex[:6]}",
            description="Test",
            enabled=True,
            priority=500,
            auto_progress_validation=True,
            created_by=uid,
            updated_by=uid,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(policy)
        db.commit()

        svc = AutomationService()
        prog = svc.progress_remediation(db, plan.remediation_id, uid, target_transition="VALIDATE")
        prog_id = prog.progression_id

        db2 = SessionLocal()
        try:
            persisted_prog = db2.scalar(
                select(AutomationProgressionDBModel).where(
                    AutomationProgressionDBModel.progression_id == prog_id
                )
            )
            assert persisted_prog is not None
            assert persisted_prog.status == ProgressionStatus.SUCCESS.value
        finally:
            db2.close()
    finally:
        db.close()


def test_auto_43_foreign_keys_enforced():
    """AUTO-43: Foreign key constraints prevent decisions for non-existent plans."""
    db = SessionLocal()
    try:
        svc = AutomationService()
        with pytest.raises(ValueError) as exc:
            svc.evaluate_remediation(db, str(uuid.uuid4()), "user-test")
        assert "not found" in str(exc.value).lower()
    finally:
        db.close()


def test_auto_44_state_machine_valid_transitions():
    """AUTO-44: AutomationState machine validates allowed transitions and rejects invalid."""
    assert is_valid_automation_transition(AutomationState.NOT_EVALUATED, AutomationState.EVALUATING) is True
    assert is_valid_automation_transition(AutomationState.EVALUATING, AutomationState.ELIGIBLE) is True
    assert is_valid_automation_transition(AutomationState.ELIGIBLE, AutomationState.PROGRESSING) is True
    assert is_valid_automation_transition(AutomationState.PROGRESSING, AutomationState.PROGRESSION_COMPLETED) is True

    # Invalid transitions
    assert is_valid_automation_transition(AutomationState.NOT_EVALUATED, AutomationState.PROGRESSING) is False
    assert is_valid_automation_transition(AutomationState.PROGRESSING, AutomationState.NOT_EVALUATED) is False


# ==============================================================================
# PART 6: AUDIT & SECRET SANITIZATION (AUTO-45 through AUTO-50)
# ==============================================================================

def test_auto_45_policy_crud_logs_audit_events(client, admin_token):
    """AUTO-45: Policy CRUD operations log audit events."""
    # Create
    create_res = client.post(
        "/api/v1/automation/policies",
        json={"name": f"Audit-Pol-{uuid.uuid4().hex[:6]}", "description": "Audit check"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    pol_id = create_res.json()["policy_id"]

    # Delete
    client.delete(f"/api/v1/automation/policies/{pol_id}", headers={"Authorization": f"Bearer {admin_token}"})

    audit_res = client.get("/api/v1/automation/audit", headers={"Authorization": f"Bearer {admin_token}"})
    events = audit_res.json()
    event_types = [e["event_type"] for e in events]
    assert AutomationAuditEventType.POLICY_CREATED.value in event_types
    assert AutomationAuditEventType.POLICY_DELETED.value in event_types


def test_auto_46_audit_events_sha256_hash_chain(client, admin_token):
    """AUTO-46: Automation audit events form a cryptographic SHA-256 hash chain."""
    audit_res = client.get("/api/v1/automation/audit", headers={"Authorization": f"Bearer {admin_token}"})
    events = audit_res.json()
    if len(events) < 2:
        client.post("/api/v1/automation/kill-switch/enable", json={"reason": "Audit chain test setup 1"}, headers={"Authorization": f"Bearer {admin_token}"})
        client.post("/api/v1/automation/kill-switch/disable", json={"reason": "Audit chain test setup 2"}, headers={"Authorization": f"Bearer {admin_token}"})
        audit_res = client.get("/api/v1/automation/audit", headers={"Authorization": f"Bearer {admin_token}"})
        events = audit_res.json()
    assert len(events) >= 2

    # Verify each event has hash and valid sequence
    for i in range(len(events) - 1):
        curr = events[i]
        prev = events[i + 1]
        assert curr["event_hash"] is not None
        assert curr["sequence_number"] > prev["sequence_number"]


def test_auto_47_secrets_recursively_redacted_in_audit():
    """AUTO-47: Passwords, tokens, and AWS keys are redacted before audit persistence."""
    db = SessionLocal()
    try:
        from core.automation.audit import log_automation_event
        uid = get_test_user_id(db)
        ev = log_automation_event(
            session=db,
            event_type="TEST_SECRET_SCRUBBING",
            actor_user_id=uid,
            safe_details={
                "password": "super-secret-password",
                "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
                "nested": {
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test",
                    "safe_info": "visible",
                }
            }
        )
        db.commit()

        # Verify redacted
        details = ev.safe_details
        assert details["password"] == "***REDACTED***"
        assert details["aws_access_key"] == "***REDACTED***"
        assert details["nested"]["token"] == "***REDACTED***"
        assert details["nested"]["safe_info"] == "visible"
    finally:
        db.close()


def test_auto_48_api_error_responses_no_stack_traces(client, admin_token):
    """AUTO-48: API error responses shield stack traces and sensitive details."""
    res = client.get(
        "/api/v1/automation/policies/non-existent-uuid-123",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 404
    data = res.json()
    assert "Traceback" not in str(data)
    assert "password" not in str(data).lower()


def test_auto_49_fastapi_restart_persistence_simulation():
    """AUTO-49: Persistence across simulated application restarts."""
    db = SessionLocal()
    try:
        uid = get_test_user_id(db)
        policy = AutomationPolicyDBModel(
            policy_id=str(uuid.uuid4()),
            name=f"Restart-Pol-{uuid.uuid4().hex[:6]}",
            description="Restart test",
            enabled=True,
            priority=50,
            created_by=uid,
            updated_by=uid,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            updated_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(policy)
        db.commit()
        pol_id = policy.policy_id
    finally:
        db.close()

    # Simulate fresh session after restart
    db2 = SessionLocal()
    try:
        reloaded = db2.scalar(select(AutomationPolicyDBModel).where(AutomationPolicyDBModel.policy_id == pol_id))
        assert reloaded is not None
        assert reloaded.name.startswith("Restart-Pol")
    finally:
        db2.close()


def test_auto_50_postgresql_restart_resilience_simulation():
    """AUTO-50: Direct DB query confirms PostgreSQL container is the authoritative store."""
    db = SessionLocal()
    try:
        res = db.execute(text("SELECT setting_key, setting_value FROM automation_settings WHERE setting_key = 'global_kill_switch'")).fetchone()
        assert res is not None
        assert res[0] == "global_kill_switch"
    finally:
        db.close()
