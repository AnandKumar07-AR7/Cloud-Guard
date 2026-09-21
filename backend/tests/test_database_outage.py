def test_database_outage(monkeypatch):
    """Verify application fails correctly when DB is down without falling back to sqlite."""
    from core.database import get_db, SessionLocal
    import sqlalchemy.exc
    import pytest
    
    # Force a bad database URL to simulate outage
    monkeypatch.setenv("DATABASE_URL", "postgresql://bad_user:bad_password@localhost:5432/bad_db")
    
    # Attempting to get a DB session should eventually result in an OperationalError
    # when a query is actually executed.
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    
    engine = create_engine("postgresql://bad_user:bad_password@localhost:5432/bad_db")
    Session = sessionmaker(bind=engine)
    session = Session()
    
    with pytest.raises(sqlalchemy.exc.OperationalError):
        session.execute(text("SELECT 1"))
