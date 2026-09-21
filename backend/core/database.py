"""
CloudGuard — PostgreSQL Database Configuration

Initializes SQLAlchemy engine and session management.
"""
from __future__ import annotations

import logging
import os
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from config.settings import settings

log = logging.getLogger(__name__)

# The database URL from environment or configuration.
SQLALCHEMY_DATABASE_URL = settings.database_url
is_testing = os.environ.get("TESTING") == "1"

if not SQLALCHEMY_DATABASE_URL:
    if is_testing:
        SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
        log.warning("DATABASE_URL is not set. Falling back to sqlite:///:memory: for testing.")
    else:
        raise RuntimeError("DATABASE_URL environment variable is not set. A real PostgreSQL database is required.")

# Create the SQLAlchemy engine. We use check_same_thread=False for SQLite compatibility in tests.
connect_args = {}
engine_kwargs = {}

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    from sqlalchemy.pool import NullPool
    connect_args["check_same_thread"] = False
    # NullPool: each request gets its own SQLite connection — avoids the
    # sqlite3.InterfaceError "bad parameter or other API misuse" that occurs
    # when StaticPool (single shared connection) is accessed from multiple
    # FastAPI worker threads concurrently.
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = settings.db_pool_size
    engine_kwargs["max_overflow"] = settings.db_max_overflow
    engine_kwargs["pool_timeout"] = settings.db_pool_timeout
    engine_kwargs["pool_recycle"] = settings.db_pool_recycle

    # PostgreSQL timeout safety parameters to protect against resource exhaustion
    options = []
    if settings.db_statement_timeout_ms > 0:
        options.append(f"-c statement_timeout={settings.db_statement_timeout_ms}")
    if settings.db_idle_in_transaction_timeout_ms > 0:
        options.append(f"-c idle_in_transaction_session_timeout={settings.db_idle_in_transaction_timeout_ms}")
    if settings.db_lock_timeout_ms > 0:
        options.append(f"-c lock_timeout={settings.db_lock_timeout_ms}")
    if options:
        connect_args["options"] = " ".join(options)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs
)

# Register custom SQL functions for SQLite test compatibility (e.g. NOW())
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event
    import datetime

    @event.listens_for(engine, "connect")
    def _sqlite_connect_hook(dbapi_connection, connection_record):
        if hasattr(dbapi_connection, "create_function"):
            dbapi_connection.create_function(
                "NOW", 0, lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Iterator[Session]:
    """
    FastAPI dependency that provides a SQLAlchemy session.
    Automatically closes the session after the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
