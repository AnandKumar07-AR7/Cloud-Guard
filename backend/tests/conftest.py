"""
Shared pytest fixtures and session setup for CloudGuard tests.

Session-scoped logging configuration ensures structlog is only configured once,
preventing 'PrintLogger has no attribute name' errors from reconfiguration.

Phase 6 additions:
- JWT_SECRET_KEY is set to a stable test-only value via os.environ BEFORE any imports.
  This prevents the insecure-default guard in auth/security.py from triggering
  in test context (PYTEST_CURRENT_TEST is set by pytest automatically).
- setup_auth_db() seeds the auth schema (roles, permissions, users) in the real
  test PostgreSQL database.
- admin_headers, analyst_headers, operator_headers, viewer_headers fixtures
  authenticate via real AuthService and return dict with Authorization: Bearer <token>.
  There is NO global bypass — all tests use real JWT tokens from real auth.
"""
import sys
import os

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dotenv import load_dotenv

load_dotenv()

# Set JWT_SECRET_KEY before any auth imports — test-only stable value.
# NEVER use this value outside of pytest.
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-production-DO-NOT-USE")

# If DATABASE_URL points to PostgreSQL but the server is not reachable,
# fall back to SQLite for seamless test execution without requiring Docker/Postgres.
db_url = os.environ.get("DATABASE_URL", "")
if not db_url:
    # Try PostgreSQL first if localhost:5432 is open
    import socket
    try:
        s = socket.create_connection(("localhost", 5432), timeout=0.5)
        s.close()
        os.environ["DATABASE_URL"] = "postgresql://postgres:postgres@localhost:5432/cloudguard"
    except Exception:
        os.environ["DATABASE_URL"] = "sqlite:///test_cloudguard.db"
elif db_url.startswith("postgres"):
    import socket
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(db_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        s = socket.create_connection((host, port), timeout=0.5)
        s.close()
    except Exception:
        os.environ["DATABASE_URL"] = "sqlite:///test_cloudguard.db"

# Ensure backend directory is always on the path for test imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
import pytest
from fastapi.testclient import TestClient

from core.providers.demo.fixtures.s3_fixtures import get_s3_fixtures
from core.providers.demo.fixtures.iam_fixtures import get_iam_fixtures
from core.providers.demo.fixtures.sg_fixtures import get_sg_fixtures
from core.providers.demo.fixtures.lambda_fixtures import get_lambda_fixtures
from core.security.engine import SecurityRuleEngine
from core.security.rules.s3_rules import S3_RULES
from core.security.rules.iam_rules import IAM_RULES
from core.security.rules.sg_rules import SG_RULES
from core.security.rules.lambda_rules import LAMBDA_RULES
from core.utils.logging import configure_logging


# ── Session-level setup ───────────────────────────────────────────────────────

def pytest_configure(config):
    """Configure structlog once before any test module is imported."""
    configure_logging(level="WARNING", fmt="text")


@pytest.fixture(autouse=True)
def reset_auth_rate_limiter():
    """Reset the in-process auth rate limiter before each test so tests don't pollute each other's quota."""
    try:
        from main import _auth_rate_limiter
        _auth_rate_limiter.reset_for_testing()
    except Exception:
        pass


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    from core.database import engine
    from core.db_models import Base
    from auth.models import (  # noqa: F401 — registers auth models with Base
        RoleDBModel, PermissionDBModel, UserDBModel, RefreshTokenDBModel
    )
    # Create all tables (Phase 1-5 + Phase 6 auth tables)
    Base.metadata.create_all(bind=engine)
    yield
    # Dispose engine and clean up test SQLite file if used
    if str(engine.url).startswith("sqlite"):
        engine.dispose()
        if os.path.exists("test_cloudguard.db"):
            try:
                os.remove("test_cloudguard.db")
            except OSError:
                pass


@pytest.fixture(scope="session", autouse=True)
def setup_auth_db(setup_test_db):
    """
    Seed roles, permissions, and a user for each role in the test database.
    Session-scoped so it runs once per test session.
    Uses real SQLAlchemy session — no bypass.
    """
    from core.database import SessionLocal
    from auth.permissions import CloudGuardRole, Permission, ROLE_PERMISSIONS
    from auth.models import RoleDBModel, PermissionDBModel, UserDBModel
    from auth.security import hash_password
    from sqlalchemy import text, insert
    from auth.models import role_permissions as rp_table

    db = SessionLocal()
    try:
        # Clear auth tables for test isolation
        db.execute(text("DELETE FROM mcp_audit_events"))
        db.execute(text("DELETE FROM mcp_tools"))
        db.execute(text("DELETE FROM mcp_servers"))
        db.execute(text("DELETE FROM automation_audit_events"))
        db.execute(text("DELETE FROM automation_progressions"))
        db.execute(text("DELETE FROM automation_decisions"))
        db.execute(text("DELETE FROM automation_policies"))
        db.execute(text("""
            INSERT INTO automation_settings (setting_key, setting_value, updated_at, updated_by)
            VALUES ('global_kill_switch', '{"enabled": false}', NOW(), NULL)
            ON CONFLICT (setting_key) DO UPDATE SET updated_by = NULL, setting_value = '{"enabled": false}'
        """))
        db.execute(text("DELETE FROM ai_tool_events"))
        db.execute(text("DELETE FROM ai_recommendations"))
        db.execute(text("DELETE FROM ai_runs"))
        db.execute(text("DELETE FROM refresh_tokens"))
        db.execute(text("DELETE FROM users"))
        db.execute(text("DELETE FROM role_permissions"))
        db.execute(text("DELETE FROM permissions"))
        db.execute(text("DELETE FROM roles"))
        db.commit()

        # Seed roles
        role_id_map: dict[str, str] = {}
        for role in CloudGuardRole:
            rid = str(uuid.uuid4())
            role_id_map[role.value] = rid
            db.add(RoleDBModel(
                role_id=rid,
                name=role.value,
                description=f"{role.value} role",
            ))
        db.flush()

        # Seed permissions
        perm_id_map: dict[str, str] = {}
        for pname in Permission.all_permissions():
            pid = str(uuid.uuid4())
            perm_id_map[pname] = pid
            db.add(PermissionDBModel(permission_id=pid, name=pname, description=pname))
        db.flush()

        # Assign permissions to roles
        for role, perms in ROLE_PERMISSIONS.items():
            rid = role_id_map[role.value]
            for pname in perms:
                pid = perm_id_map.get(pname)
                if pid:
                    db.execute(insert(rp_table).values(role_id=rid, permission_id=pid))
        db.flush()

        # Create one test user per role with known passwords
        test_users = [
            (CloudGuardRole.ADMIN,            "test_admin",    "AdminTestPass12!"),
            (CloudGuardRole.SECURITY_ANALYST, "test_analyst",  "AnalystTestPass12!"),
            (CloudGuardRole.SECURITY_ANALYST, "test_analyst2", "AnalystTestPass12!"),
            (CloudGuardRole.OPERATOR,         "test_operator", "OperatorTestPass12!"),
            (CloudGuardRole.VIEWER,           "test_viewer",   "ViewerTestPass12!"),
        ]
        for role, uname, passwd in test_users:
            db.add(UserDBModel(
                username=uname,
                password_hash=hash_password(passwd),
                role_id=role_id_map[role.value],
                is_active=True,
            ))
        db.commit()
    finally:
        db.close()


# ── Auth client helpers ────────────────────────────────────────────────────────
# These authenticate via real POST /auth/login — NOT a bypass.

def _get_auth_headers(username: str, password: str) -> dict:
    """Authenticate via real POST /auth/login and return Authorization header dict."""
    from main import app
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.post("/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, (
            f"Auth fixture login failed for {username!r}: {resp.text}"
        )
        token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def admin_headers(setup_auth_db) -> dict:
    """Auth headers for the test admin user (ADMIN role)."""
    return _get_auth_headers("test_admin", "AdminTestPass12!")


@pytest.fixture(scope="session")
def analyst_headers(setup_auth_db) -> dict:
    """Auth headers for the test security analyst user."""
    return _get_auth_headers("test_analyst", "AnalystTestPass12!")


@pytest.fixture(scope="session")
def analyst2_headers(setup_auth_db) -> dict:
    """Auth headers for the second test security analyst user."""
    return _get_auth_headers("test_analyst2", "AnalystTestPass12!")


@pytest.fixture(scope="session")
def operator_headers(setup_auth_db) -> dict:
    """Auth headers for the test operator user."""
    return _get_auth_headers("test_operator", "OperatorTestPass12!")


@pytest.fixture(scope="session")
def viewer_headers(setup_auth_db) -> dict:
    """Auth headers for the test viewer user."""
    return _get_auth_headers("test_viewer", "ViewerTestPass12!")


@pytest.fixture(scope="session")
def auth_client(setup_auth_db):
    """
    A TestClient pre-authenticated as test_admin.
    Kept for backward compatibility with Phase 1-5 tests that use this fixture.
    """
    from main import app
    client = TestClient(app, raise_server_exceptions=False)
    headers = _get_auth_headers("test_admin", "AdminTestPass12!")
    client.headers.update(headers)
    return client


# ── Resource Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def s3_resources():
    return get_s3_fixtures()


@pytest.fixture
def iam_resources():
    return get_iam_fixtures()


@pytest.fixture
def sg_resources():
    return get_sg_fixtures()


@pytest.fixture
def lambda_resources():
    return get_lambda_fixtures()


# ── Engine Fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def s3_engine():
    return SecurityRuleEngine(rules=S3_RULES)


@pytest.fixture
def iam_engine():
    return SecurityRuleEngine(rules=IAM_RULES)


@pytest.fixture
def sg_engine():
    return SecurityRuleEngine(rules=SG_RULES)


@pytest.fixture
def lambda_engine():
    return SecurityRuleEngine(rules=LAMBDA_RULES)


@pytest.fixture
def full_engine():
    return SecurityRuleEngine()
