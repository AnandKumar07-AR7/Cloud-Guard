"""
CloudGuard — Phase 7 Database-Enforced Append-Only Audit Integrity Test Suite

Implements tests:
- AUDIT-DB-01: INSERT ALLOWED
- AUDIT-DB-02: UPDATE BLOCKED AT POSTGRESQL LEVEL
- AUDIT-DB-03: DELETE BLOCKED AT POSTGRESQL LEVEL
- AUDIT-DB-04: INSERT STILL WORKS
- AUDIT-DB-05: HASH CHAIN VALID
- AUDIT-DB-06: PREVIOUS HASH LINKAGE
- AUDIT-DB-07: HASH DETERMINISM
- AUDIT-DB-08: SECRET SANITIZATION BEFORE HASHING
- AUDIT-DB-09: CONCURRENT AUDIT WRITES
- AUDIT-DB-10: POSTGRESQL CONTAINER RESTART
"""
import uuid
import time
import subprocess
import concurrent.futures
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from core.database import SessionLocal, engine
from core.db_models import (
    ScanDBModel, ResourceDBModel, FindingDBModel,
    RemediationPlanDBModel, RemediationAuditEventDBModel
)
from core.remediation.audit import (
    log_remediation_event, verify_audit_chain,
    compute_event_hash, format_canonical_timestamp
)
from services.remediation_service import RemediationService


@pytest.fixture
def db():
    """Yield real PostgreSQL session."""
    session = SessionLocal()
    yield session
    session.close()


def _create_test_plan(db) -> RemediationPlanDBModel:
    """Helper to persist a plan for audit event attachment."""
    uid = uuid.uuid4().hex[:8]
    sid = f"scan-{uid}"
    rid = f"arn:aws:s3:::audit-bucket-{uid}"
    fid = f"finding-{uid}"
    rem_id = f"plan-{uid}"

    scan = ScanDBModel(
        scan_id=sid,
        correlation_id=str(uuid.uuid4()),
        provider="demo",
        account_id="123456789012",
        mode="demo",
        status="COMPLETED",
    )
    db.add(scan)

    res = ResourceDBModel(
        resource_id=rid,
        provider="aws",
        account_id="123456789012",
        region="us-east-1",
        service="s3",
        resource_type="s3_bucket",
    )
    db.add(res)

    finding = FindingDBModel(
        finding_id=fid,
        canonical_id=f"canon-{uid}",
        scan_id=sid,
        resource_id=rid,
        rule_id="S3-001",
        resource_type="s3_bucket",
        service="s3",
        account_id="123456789012",
        region="us-east-1",
        severity="high",
        risk_score=75.0,
        category="security",
        status="OPEN",
        title="S3 Bucket Public Read",
        description="Publicly readable S3 bucket finding",
    )
    db.add(finding)
    db.flush()

    plan = RemediationPlanDBModel(
        remediation_id=rem_id,
        finding_id=fid,
        scan_id=sid,
        resource_id=rid,
        rule_id="S3-001",
        state="DRAFT",
        title="Block S3 Public Access",
        description="Audit Integrity Test Plan",
        created_by="user-auditor",
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def test_audit_db_01_insert_allowed(db):
    """AUDIT-DB-01: Verify audit events can be created and persisted in PostgreSQL."""
    plan = _create_test_plan(db)

    ev = log_remediation_event(
        session=db,
        remediation_id=plan.remediation_id,
        event_type="PLAN_CREATED",
        actor_user_id="user-auditor",
        new_state="DRAFT",
    )
    db.commit()

    persisted = db.scalar(
        select(RemediationAuditEventDBModel).where(
            RemediationAuditEventDBModel.event_id == ev.event_id
        )
    )
    assert persisted is not None
    assert persisted.remediation_id == plan.remediation_id
    assert persisted.sequence_number == 1
    assert persisted.event_hash is not None
    assert len(persisted.event_hash) == 64


def test_audit_db_02_update_blocked_at_postgresql_level(db):
    """AUDIT-DB-02: Against REAL PostgreSQL, direct SQL UPDATE must be rejected by the trigger."""
    if engine.dialect.name != "postgresql":
        pytest.skip("Test requires real PostgreSQL dialect")

    plan = _create_test_plan(db)
    ev = log_remediation_event(
        session=db,
        remediation_id=plan.remediation_id,
        event_type="PLAN_CREATED",
        actor_user_id="user-auditor",
    )
    db.commit()

    with pytest.raises(DBAPIError) as exc_info:
        db.execute(
            text("UPDATE remediation_audit_events SET event_type = 'TAMPERED' WHERE event_id = :eid"),
            {"eid": ev.event_id}
        )
        db.commit()

    db.rollback()
    err_str = str(exc_info.value).lower()
    assert "append-only" in err_str or "prohibited" in err_str


def test_audit_db_03_delete_blocked_at_postgresql_level(db):
    """AUDIT-DB-03: Against REAL PostgreSQL, direct SQL DELETE must be rejected by the trigger."""
    if engine.dialect.name != "postgresql":
        pytest.skip("Test requires real PostgreSQL dialect")

    plan = _create_test_plan(db)
    ev = log_remediation_event(
        session=db,
        remediation_id=plan.remediation_id,
        event_type="PLAN_CREATED",
        actor_user_id="user-auditor",
    )
    db.commit()

    with pytest.raises(DBAPIError) as exc_info:
        db.execute(
            text("DELETE FROM remediation_audit_events WHERE event_id = :eid"),
            {"eid": ev.event_id}
        )
        db.commit()

    db.rollback()
    err_str = str(exc_info.value).lower()
    assert "append-only" in err_str or "prohibited" in err_str


def test_audit_db_04_insert_still_works(db):
    """AUDIT-DB-04: Verify database protection does not block subsequent INSERT operations."""
    plan = _create_test_plan(db)

    ev1 = log_remediation_event(
        session=db,
        remediation_id=plan.remediation_id,
        event_type="PLAN_CREATED",
        actor_user_id="user-1",
    )
    db.commit()

    ev2 = log_remediation_event(
        session=db,
        remediation_id=plan.remediation_id,
        event_type="PLAN_VALIDATED",
        actor_user_id="user-1",
    )
    db.commit()

    assert ev1.event_id != ev2.event_id
    assert ev2.sequence_number == 2
    assert ev2.previous_event_hash == ev1.event_hash


def test_audit_db_05_hash_chain_valid(db):
    """AUDIT-DB-05: Create multiple events: Event 1 -> Event 2 -> Event 3. verify_audit_chain must return VALID."""
    plan = _create_test_plan(db)

    log_remediation_event(db, plan.remediation_id, "PLAN_CREATED", "user-a")
    log_remediation_event(db, plan.remediation_id, "PLAN_VALIDATED", "user-a")
    log_remediation_event(db, plan.remediation_id, "PLAN_APPROVED", "user-b")
    db.commit()

    result = verify_audit_chain(db, plan.remediation_id)
    assert result["status"] == "VALID"
    assert result["verified"] is True
    assert result["events_count"] == 3
    assert result.get("head_hash") is not None


def test_audit_db_06_previous_hash_linkage(db):
    """AUDIT-DB-06: Verify each event correctly references the preceding event hash."""
    plan = _create_test_plan(db)

    e1 = log_remediation_event(db, plan.remediation_id, "PLAN_CREATED", "user-a")
    db.commit()
    e2 = log_remediation_event(db, plan.remediation_id, "PLAN_VALIDATED", "user-a")
    db.commit()
    e3 = log_remediation_event(db, plan.remediation_id, "PLAN_APPROVED", "user-b")
    db.commit()

    # Re-fetch from DB
    events = db.scalars(
        select(RemediationAuditEventDBModel)
        .where(RemediationAuditEventDBModel.remediation_id == plan.remediation_id)
        .order_by(RemediationAuditEventDBModel.sequence_number.asc())
    ).all()

    assert len(events) == 3
    assert events[0].previous_event_hash is None
    assert events[1].previous_event_hash == events[0].event_hash
    assert events[2].previous_event_hash == events[1].event_hash


def test_audit_db_07_hash_determinism():
    """AUDIT-DB-07: Verify identical canonical input produces the expected deterministic hash."""
    h1 = compute_event_hash(
        remediation_id="plan-fixed-123",
        sequence_number=1,
        event_type="PLAN_CREATED",
        timestamp_str="2026-09-07T00:00:00+00:00",
        previous_event_hash=None,
        actor_user_id="user-fixed",
        safe_details={"action": "enable_encryption", "target": "bucket-1"},
    )
    h2 = compute_event_hash(
        remediation_id="plan-fixed-123",
        sequence_number=1,
        event_type="PLAN_CREATED",
        timestamp_str="2026-09-07T00:00:00+00:00",
        previous_event_hash=None,
        actor_user_id="user-fixed",
        safe_details={"target": "bucket-1", "action": "enable_encryption"},  # reversed dict order
    )
    assert h1 == h2
    assert len(h1) == 64


def test_audit_db_08_secret_sanitization_before_hashing(db):
    """AUDIT-DB-08: Verify secret values are scrubbed before persistence and not in stored hash payload."""
    plan = _create_test_plan(db)

    raw_secret_data = {
        "password": "SuperSecretPassword123!",
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "nested": {
            "bearer_token": "Bearer secret-payload-token",
            "safe_config": "enabled"
        }
    }

    ev = log_remediation_event(
        session=db,
        remediation_id=plan.remediation_id,
        event_type="PLAN_CREATED",
        actor_user_id="user-auditor",
        safe_details=raw_secret_data,
    )
    db.commit()

    # Verify persisted details in PostgreSQL
    raw_details = str(ev.safe_details)
    assert "SuperSecretPassword123!" not in raw_details
    assert "AKIAIOSFODNN7EXAMPLE" not in raw_details
    assert "wJalrXUtnFEMI" not in raw_details
    assert "eyJhbGciOi" not in raw_details
    assert "secret-payload-token" not in raw_details

    # Chain validation must still pass on the sanitized stored event
    res = verify_audit_chain(db, plan.remediation_id)
    assert res["status"] == "VALID"
    assert res["verified"] is True


def test_audit_db_09_concurrent_audit_writes():
    """AUDIT-DB-09: Concurrent audit events for the same plan must serialize with monotonic sequence and valid hash chain."""
    if engine.dialect.name != "postgresql":
        pytest.skip("Test requires real PostgreSQL dialect")

    init_db = SessionLocal()
    plan = _create_test_plan(init_db)
    rem_id = plan.remediation_id
    init_db.close()

    total_threads = 8

    def _worker(thread_idx: int):
        thread_session = SessionLocal()
        try:
            log_remediation_event(
                session=thread_session,
                remediation_id=rem_id,
                event_type=f"THREAD_EVENT_{thread_idx}",
                actor_user_id=f"worker-{thread_idx}",
            )
            thread_session.commit()
            return True
        finally:
            thread_session.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=total_threads) as executor:
        futures = [executor.submit(_worker, i) for i in range(total_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert all(results)

    # Verification session
    verify_session = SessionLocal()
    try:
        events = verify_session.scalars(
            select(RemediationAuditEventDBModel)
            .where(RemediationAuditEventDBModel.remediation_id == rem_id)
            .order_by(RemediationAuditEventDBModel.sequence_number.asc())
        ).all()

        assert len(events) == total_threads

        # Verify strict 1..N monotonic sequence without duplicate or missing numbers
        sequences = [e.sequence_number for e in events]
        assert sequences == list(range(1, total_threads + 1))

        # Verify hash chain integrity
        chain_result = verify_audit_chain(verify_session, rem_id)
        assert chain_result["status"] == "VALID"
        assert chain_result["verified"] is True
        assert chain_result["events_count"] == total_threads
    finally:
        verify_session.close()


def test_audit_db_10_postgresql_container_restart():
    """AUDIT-DB-10: Events, hashes, integrity verification, and database-level triggers must survive Docker container restart."""
    if engine.dialect.name != "postgresql":
        pytest.skip("Test requires real PostgreSQL dialect")

    db = SessionLocal()
    plan = _create_test_plan(db)
    rem_id = plan.remediation_id

    log_remediation_event(db, rem_id, "PRE_RESTART_1", "user-1")
    log_remediation_event(db, rem_id, "PRE_RESTART_2", "user-2")
    db.commit()
    db.close()

    # Restart PostgreSQL container
    restart_res = subprocess.run(
        ["docker", "restart", "cloudguard-postgres"],
        capture_output=True,
        text=True,
        check=True
    )
    assert restart_res.returncode == 0

    # Wait for PostgreSQL to become ready
    ready = False
    for _ in range(30):
        time.sleep(1)
        try:
            check_s = SessionLocal()
            check_s.execute(text("SELECT 1"))
            check_s.close()
            ready = True
            break
        except Exception:
            continue

    assert ready, "PostgreSQL failed to restart within 30 seconds"

    # Verify events and hash chain persisted
    post_db = SessionLocal()
    try:
        events = post_db.scalars(
            select(RemediationAuditEventDBModel)
            .where(RemediationAuditEventDBModel.remediation_id == rem_id)
            .order_by(RemediationAuditEventDBModel.sequence_number.asc())
        ).all()

        assert len(events) == 2
        assert events[0].event_type == "PRE_RESTART_1"
        assert events[1].event_type == "PRE_RESTART_2"
        assert events[1].previous_event_hash == events[0].event_hash

        chain_res = verify_audit_chain(post_db, rem_id)
        assert chain_res["status"] == "VALID"
        assert chain_res["verified"] is True
        assert chain_res["events_count"] == 2

        # Verify UPDATE remains blocked by the database trigger
        with pytest.raises(DBAPIError) as exc_update:
            post_db.execute(
                text("UPDATE remediation_audit_events SET event_type = 'TAMPERED' WHERE event_id = :eid"),
                {"eid": events[0].event_id}
            )
            post_db.commit()
        post_db.rollback()
        assert "append-only" in str(exc_update.value).lower()

        # Verify DELETE remains blocked by the database trigger
        with pytest.raises(DBAPIError) as exc_delete:
            post_db.execute(
                text("DELETE FROM remediation_audit_events WHERE event_id = :eid"),
                {"eid": events[0].event_id}
            )
            post_db.commit()
        post_db.rollback()
        assert "append-only" in str(exc_delete.value).lower()

    finally:
        post_db.close()


def test_audit_db_tamper_detection(db):
    """Verify that tampering with an event's hash or sequence causes verify_audit_chain to return INVALID."""
    plan = _create_test_plan(db)

    e1 = log_remediation_event(db, plan.remediation_id, "EVENT_1", "user-1")
    e2 = log_remediation_event(db, plan.remediation_id, "EVENT_2", "user-1")
    db.commit()

    # Valid before tampering
    res_valid = verify_audit_chain(db, plan.remediation_id)
    assert res_valid["status"] == "VALID"
    assert res_valid["verified"] is True

    # Mutate in-memory object event_hash to simulate out-of-band tampering
    e2.event_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    res_tampered = verify_audit_chain(db, plan.remediation_id)
    assert res_tampered["status"] == "INVALID"
    assert res_tampered["verified"] is False
    assert "Tampered event detected" in res_tampered["error"]


def test_audit_api_verify_endpoint(db, analyst_headers):
    """Verify GET /api/v1/remediations/plans/{id}/audit/verify returns valid status for authenticated user."""
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    plan = _create_test_plan(db)
    log_remediation_event(db, plan.remediation_id, "API_TEST_1", "user-1")
    db.commit()

    resp = client.get(f"/api/v1/remediations/plans/{plan.remediation_id}/audit/verify", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "VALID"
    assert data["verified"] is True
    assert data["events_count"] == 1


