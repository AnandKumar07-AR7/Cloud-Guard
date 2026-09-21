import os
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.database import Base
from core.db_models import ScanDBModel
from core.security.models import FindingStatus
from services.repositories import ScanRepository, FindingRepository
from services.scan_service import ScanService

# Check if we have a real Postgres DB to test against
HAS_POSTGRES = bool(os.environ.get("DATABASE_URL"))

@pytest.fixture
def db_session():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url or not db_url.startswith("postgres"):
        pytest.skip("Skipping PostgreSQL integration test because DATABASE_URL is not configured for PostgreSQL")

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Clear scan and finding tables for test isolation via PostgreSQL TRUNCATE CASCADE
    session.execute(text("TRUNCATE TABLE scans, resources CASCADE;"))
    session.commit()
    
    yield session
    session.close()

def test_repository_pagination_and_filtering(db_session):
    # Save a scan with findings
    from services.scan_service import ScanService
    from core.providers.demo.provider import DemoProvider
    
    svc = ScanService(db=db_session)
    provider = DemoProvider(scenario="critical")
    record = svc.run_scan(provider)
    
    # Test filtering at DB level
    finding_repo = FindingRepository(db_session)
    critical_findings = finding_repo.list(severity="critical", limit=10)
    assert len(critical_findings) > 0
    assert all(f.severity.value == "critical" for f in critical_findings)
    
    # Test pagination
    page_1 = finding_repo.list(limit=2, offset=0)
    page_2 = finding_repo.list(limit=2, offset=2)
    assert len(page_1) == 2
    assert len(page_2) == 2
    assert page_1[0].finding_id != page_2[0].finding_id

def test_finding_history(db_session):
    from services.scan_service import ScanService
    from core.providers.demo.provider import DemoProvider
    
    svc = ScanService(db=db_session)
    
    # Run scan 1
    record1 = svc.run_scan(DemoProvider(scenario="critical"))
    f1 = record1.findings[0]
    
    # Run scan 2
    record2 = svc.run_scan(DemoProvider(scenario="critical"))
    
    repo = FindingRepository(db_session)
    history = repo.get_history(f1.canonical_id)
    
    assert len(history) == 2
    history_scan_ids = [h.scan_id for h in history]
    assert record1.scan_id in history_scan_ids
    assert record2.scan_id in history_scan_ids

def test_transaction_rollback_on_failure(db_session, monkeypatch):
    """Verify that a failure during scan persistence rolls back the entire transaction."""
    svc = ScanService(db=db_session)
    
    # Mock finding_repo.save to raise an exception halfway through
    original_save = svc.finding_repo.save
    
    def mock_save(*args, **kwargs):
        raise RuntimeError("Forced persistence failure!")
        
    monkeypatch.setattr(svc.finding_repo, "save", mock_save)
    
    from core.providers.demo.provider import DemoProvider
    record = svc.run_scan(DemoProvider(scenario="healthy"))
    
    # Scan should be marked FAILED
    assert record.status.value == "FAILED"
    assert "Forced persistence failure" in record.error_message
    
    # Verify rollback - the scan record shouldn't have associated findings/resources
    # wait, the rollback rolled back the full scan persist, but `_save_scan_state` 
    # saves the scan metadata again!
    db_scan = db_session.query(ScanDBModel).filter_by(scan_id=record.scan_id).first()
    assert db_scan is not None
    assert db_scan.status == "FAILED"
    
    # But findings/resources should NOT be persisted because of rollback
    from core.db_models import FindingDBModel, ResourceSnapshotDBModel
    findings = db_session.query(FindingDBModel).filter_by(scan_id=record.scan_id).all()
    resources = db_session.query(ResourceSnapshotDBModel).filter_by(scan_id=record.scan_id).all()
    assert len(findings) == 0
    assert len(resources) == 0

def test_restart_persistence(db_session):
    """Verify that closing the DB session and reopening retains data."""
    svc = ScanService(db=db_session)
    from core.providers.demo.provider import DemoProvider
    record = svc.run_scan(DemoProvider(scenario="healthy"))
    
    scan_id = record.scan_id
    
    # Commit and close session (simulate restart)
    db_session.commit()
    db_session.close()
    
    # New session
    from sqlalchemy.orm import Session
    new_session = Session(bind=db_session.bind)
    
    repo = ScanRepository(new_session)
    recovered_scan = repo.get(scan_id)
    assert recovered_scan is not None
    assert recovered_scan.scan_id == scan_id
    
    new_session.close()
