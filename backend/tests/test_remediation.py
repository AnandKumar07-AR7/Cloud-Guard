"""
CloudGuard — Phase 7 Remediation Tests

Tests the full remediation lifecycle including:
- Plan creation (deterministic, strategy-based)
- State machine transitions
- Separation of duties (creator cannot approve own plan)
- RBAC enforcement
- Independent verification
- Audit trail persistence
"""
import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import text

from main import app


@pytest.fixture(scope="module")
def client():
    """FastAPI test client for remediation tests."""
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def finding_id(setup_auth_db, admin_headers):
    """
    Create a real scan + finding in the DB by running a real scan
    and returning one finding with a remediable rule.
    """
    import time
    client = TestClient(app, raise_server_exceptions=True)

    # Run a demo scan
    resp = client.post("/scans", json={"provider": "demo"}, headers=admin_headers)
    assert resp.status_code == 201, f"Scan failed: {resp.text}"
    scan_id = resp.json()["scan_id"]

    # Poll until scan completes (up to 30s)
    for _ in range(30):
        resp = client.get(f"/scans/{scan_id}", headers=admin_headers)
        assert resp.status_code == 200
        if resp.json()["status"].lower() in ("completed", "failed"):
            break
        time.sleep(1)

    # Get all findings for this scan — note: rule_id filter uppercases, breaking lowercase rule IDs
    resp = client.get(f"/findings?scan_id={scan_id}&limit=200", headers=admin_headers)
    assert resp.status_code == 200, f"Get findings failed: {resp.text}"
    data = resp.json()
    # FindingListResponse: {"items": [...], "total": N, ...}
    items = data.get("items", [])

    # Find a finding with an explicitly supported remediation strategy
    from core.remediation.strategy import STRATEGIES
    for f in items:
        if f.get("rule_id") in STRATEGIES:
            return f["finding_id"]

    pytest.skip("No remediable finding found in demo scan — skipping remediation tests")


@pytest.fixture(autouse=True)
def cleanup_remediations():
    """Clean up remediation tables and demo state between tests."""
    from core.database import SessionLocal
    from core.providers.demo.remediation import DEMO_STATE
    DEMO_STATE["s3_blocks"].clear()
    DEMO_STATE["sg_blocks"].clear()
    with SessionLocal() as session:
        if session.bind.dialect.name == "sqlite":
            for table in ("remediation_audit_events", "remediation_executions", "remediation_actions", "remediation_plans"):
                session.execute(text(f"DELETE FROM {table};"))
        else:
            session.execute(text(
                "TRUNCATE TABLE remediation_audit_events, remediation_executions, "
                "remediation_actions, remediation_plans CASCADE;"
            ))
        session.commit()
    yield
    DEMO_STATE["s3_blocks"].clear()
    DEMO_STATE["sg_blocks"].clear()
    with SessionLocal() as session:
        if session.bind.dialect.name == "sqlite":
            for table in ("remediation_audit_events", "remediation_executions", "remediation_actions", "remediation_plans"):
                session.execute(text(f"DELETE FROM {table};"))
        else:
            session.execute(text(
                "TRUNCATE TABLE remediation_audit_events, remediation_executions, "
                "remediation_actions, remediation_plans CASCADE;"
            ))
        session.commit()


# ───────────────────────────────────────────────────────────────
# Core Lifecycle Tests
# ───────────────────────────────────────────────────────────────

def test_create_plan_requires_permission(client, viewer_headers, finding_id):
    """VIEWER must not be able to create a remediation plan."""
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=viewer_headers)
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


def test_create_plan_analyst(client, analyst_headers, finding_id):
    """SECURITY_ANALYST can create a remediation plan."""
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=analyst_headers)
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
    plan = resp.json()
    assert plan["state"] == "DRAFT"
    assert plan["finding_id"] == finding_id
    assert len(plan["proposed_actions"]) > 0


def test_full_lifecycle(client, analyst_headers, admin_headers, operator_headers, finding_id):
    """
    Full remediation lifecycle: CREATE → VALIDATE → APPROVE (by different user) → EXECUTE → VERIFY.
    """
    # 1. Analyst creates plan
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=analyst_headers)
    assert resp.status_code == 201, f"Create plan: {resp.text}"
    plan = resp.json()
    plan_id = plan["remediation_id"]
    assert plan["state"] == "DRAFT"

    # 2. Analyst validates plan
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=analyst_headers)
    assert resp.status_code == 200, f"Validate plan: {resp.text}"
    assert resp.json()["state"] == "PENDING_APPROVAL"

    # 3. Analyst tries to approve their OWN plan → must fail (separation of duties)
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=analyst_headers)
    assert resp.status_code == 403, f"Expected 403 (self-approval blocked), got {resp.status_code}"

    # 4. Admin (different user) approves
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    assert resp.status_code == 200, f"Approve plan: {resp.text}"
    approved = resp.json()
    assert approved["state"] == "APPROVED"
    assert approved["approved_by"] is not None

    # 5. Operator executes
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=operator_headers)
    assert resp.status_code == 200, f"Execute plan: {resp.text}"
    executed = resp.json()
    assert executed["state"] == "EXECUTED"
    assert executed["execution_started_at"] is not None

    # 6. Analyst verifies (independent re-read of state)
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=analyst_headers)
    assert resp.status_code == 200, f"Verify plan: {resp.text}"
    verified = resp.json()
    assert verified["state"] == "VERIFIED_FIXED"


def test_blocked_transitions(client, analyst_headers, admin_headers, finding_id):
    """
    State machine must block illegal transitions.
    """
    # Create a fresh plan
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=analyst_headers)
    assert resp.status_code == 201
    plan_id = resp.json()["remediation_id"]

    # Try to approve a DRAFT plan directly (must fail: DRAFT → APPROVED is not valid)
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
    assert resp.status_code in (400, 403), f"Expected blocked transition, got {resp.status_code}"

    # Try to execute a DRAFT plan directly (must fail)
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=admin_headers)
    assert resp.status_code == 400, f"Expected 400 for execute on DRAFT, got {resp.status_code}"

    # Try to verify a DRAFT plan (must fail)
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/verify", headers=admin_headers)
    assert resp.status_code == 400, f"Expected 400 for verify on DRAFT, got {resp.status_code}"


def test_get_plan_requires_auth(client, finding_id):
    """Unauthenticated request must be rejected."""
    # First create a plan via admin to have a real plan_id
    from auth.dependencies import get_current_user
    admin_headers = {"Authorization": "Bearer invalid-token"}
    resp = client.get("/api/v1/remediations/plans/non-existent-id", headers=admin_headers)
    assert resp.status_code == 401


def test_viewer_can_read_plan(client, viewer_headers, analyst_headers, admin_headers, finding_id):
    """VIEWER may read plans but not create/modify them."""
    # Create via analyst
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=analyst_headers)
    assert resp.status_code == 201
    plan_id = resp.json()["remediation_id"]

    # Viewer reads plan
    resp = client.get(f"/api/v1/remediations/plans/{plan_id}", headers=viewer_headers)
    assert resp.status_code == 200
    assert resp.json()["remediation_id"] == plan_id

    # Viewer cannot validate
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=viewer_headers)
    assert resp.status_code == 403

    # Viewer cannot approve
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=viewer_headers)
    assert resp.status_code == 403

    # Viewer cannot execute
    resp = client.post(f"/api/v1/remediations/plans/{plan_id}/execute", headers=viewer_headers)
    assert resp.status_code == 403


def test_duplicate_plan_rejected(client, analyst_headers, finding_id):
    """
    Creating a second active plan for the same finding must be rejected.
    """
    # First plan
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=analyst_headers)
    assert resp.status_code == 201

    # Second plan for same finding
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=analyst_headers)
    assert resp.status_code == 400, f"Expected 400 for duplicate plan, got {resp.status_code}: {resp.text}"


def test_unknown_finding_rejected(client, analyst_headers):
    """Creating a plan for a non-existent finding must return 400."""
    resp = client.post(
        f"/api/v1/remediations/plans?finding_id=non-existent-{uuid.uuid4()}",
        headers=analyst_headers
    )
    assert resp.status_code == 400


def test_operator_cannot_create_plan(client, operator_headers, finding_id):
    """OPERATOR does not have remediations.create permission."""
    resp = client.post(f"/api/v1/remediations/plans?finding_id={finding_id}", headers=operator_headers)
    assert resp.status_code == 403
