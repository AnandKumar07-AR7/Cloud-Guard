"""
CloudGuard — Phase 6 Authentication & RBAC Test Suite

Tests are labeled AUTH-01 through AUTH-30+ covering:
  - Login success/failure
  - Token structure
  - Refresh token rotation + reuse detection
  - Logout
  - JWT validation
  - Password change
  - User management (admin)
  - RBAC: permission enforcement per role
  - 401 vs 403 distinction
  - No username enumeration
  - Disabled account behavior
  - Public endpoint accessibility

DESIGN: All auth tests use REAL tokens from REAL AuthService.login()
        via the real POST /auth/login endpoint.
        No mocking of authentication logic.
"""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from main import app
    return TestClient(app, raise_server_exceptions=False)


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-01: Successful login returns tokens
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_01_login_success(client, setup_auth_db):
    """AUTH-01: POST /auth/login with valid credentials returns 200 + tokens."""
    resp = client.post("/auth/login", json={
        "username": "test_admin",
        "password": "AdminTestPass12!",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    assert len(data["access_token"]) > 20
    assert len(data["refresh_token"]) > 20


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-02: Wrong password returns 401
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_02_login_wrong_password(client, setup_auth_db):
    """AUTH-02: Wrong password returns 401."""
    resp = client.post("/auth/login", json={
        "username": "test_admin",
        "password": "WrongPassword!",
    })
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-03: Non-existent username returns same 401 (no enumeration)
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_03_login_nonexistent_user_no_enumeration(client):
    """AUTH-03: Non-existent username returns 401 with same error as wrong password."""
    resp_bad_pass = client.post("/auth/login", json={
        "username": "test_admin",
        "password": "WrongPass123!",
    })
    resp_no_user = client.post("/auth/login", json={
        "username": "does_not_exist_xyz",
        "password": "AnyPassword123!",
    })
    assert resp_bad_pass.status_code == 401
    assert resp_no_user.status_code == 401
    # Both should return the same message (no info leak about existence)
    # The http_exception_handler returns the dict directly as the body
    msg_bad = resp_bad_pass.json().get("message", resp_bad_pass.json().get("detail", {}).get("message"))
    msg_missing = resp_no_user.json().get("message", resp_no_user.json().get("detail", {}).get("message"))
    assert msg_bad == msg_missing


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-04: JWT claims — minimal, correct structure
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_04_jwt_claims_structure(client, setup_auth_db):
    """AUTH-04: JWT contains required minimal claims (sub, role, jti, exp, type=access)."""
    from jose import jwt as jose_jwt
    import os

    resp = client.post("/auth/login", json={
        "username": "test_admin",
        "password": "AdminTestPass12!",
    })
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    # Decode without verification to inspect claims (test only)
    from config.settings import settings
    secret = os.environ["JWT_SECRET_KEY"]
    payload = jose_jwt.decode(
        token, secret, algorithms=["HS256"], audience=settings.jwt_audience, issuer=settings.jwt_issuer
    )

    assert payload["type"] == "access"
    assert "sub" in payload      # user_id
    assert "role" in payload
    assert "jti" in payload
    assert "exp" in payload
    assert "iat" in payload
    assert payload.get("iss") == settings.jwt_issuer
    assert payload.get("aud") == settings.jwt_audience
    # Password hash, email, permissions must NOT be in JWT
    assert "password_hash" not in payload
    assert "permissions" not in payload


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-05: GET /auth/me returns user profile (no password_hash)
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_05_get_me(client, admin_headers):
    """AUTH-05: GET /auth/me returns user profile without password_hash."""
    resp = client.get("/auth/me", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "test_admin"
    assert data["role"] == "ADMIN"
    assert "password_hash" not in data
    assert "user_id" in data
    assert data["is_active"] is True


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-06: GET /auth/me without token returns 401
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_06_me_without_token(client):
    """AUTH-06: /auth/me without token returns 401."""
    resp = client.get("/auth/me")
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-07: Invalid/tampered JWT returns 401
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_07_invalid_jwt(client):
    """AUTH-07: Tampered JWT returns 401."""
    bad_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.INVALID.SIGNATURE"
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {bad_token}"})
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-08: Refresh token rotation — new tokens issued, old revoked
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_08_refresh_token_rotation(client, setup_auth_db):
    """AUTH-08: POST /auth/refresh issues new access+refresh tokens."""
    # Login to get initial tokens
    login_resp = client.post("/auth/login", json={
        "username": "test_viewer",
        "password": "ViewerTestPass12!",
    })
    assert login_resp.status_code == 200
    initial_refresh = login_resp.json()["refresh_token"]

    # Refresh
    refresh_resp = client.post("/auth/refresh", json={"refresh_token": initial_refresh})
    assert refresh_resp.status_code == 200
    new_data = refresh_resp.json()
    assert "access_token" in new_data
    assert "refresh_token" in new_data
    # New tokens must differ from original
    assert new_data["refresh_token"] != initial_refresh


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-09: Reused refresh token triggers family-wide revocation
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_09_refresh_token_reuse_detection(client, setup_auth_db):
    """AUTH-09: Presenting a revoked refresh token triggers family invalidation."""
    login_resp = client.post("/auth/login", json={
        "username": "test_operator",
        "password": "OperatorTestPass12!",
    })
    assert login_resp.status_code == 200
    old_refresh = login_resp.json()["refresh_token"]

    # Use token once (rotates it, old one revoked)
    first_refresh = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert first_refresh.status_code == 200

    # Present old (revoked) token — reuse detected, family revoked
    reuse_resp = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert reuse_resp.status_code == 401

    # New token from first refresh also revoked now (family invalidation)
    new_refresh = first_refresh.json()["refresh_token"]
    family_resp = client.post("/auth/refresh", json={"refresh_token": new_refresh})
    assert family_resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-10: Invalid refresh token returns 401
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_10_invalid_refresh_token(client):
    """AUTH-10: Presenting a random string as refresh token returns 401."""
    resp = client.post("/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-11: Logout revokes token family
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_11_logout_revokes_refresh_token(client, setup_auth_db):
    """AUTH-11: POST /auth/logout revokes the refresh token family."""
    login_resp = client.post("/auth/login", json={
        "username": "test_viewer",
        "password": "ViewerTestPass12!",
    })
    access_token = login_resp.json()["access_token"]
    refresh_token = login_resp.json()["refresh_token"]

    # Logout
    logout_resp = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 204

    # Refresh token should now be invalid
    refresh_resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-12: Public endpoints accessible without token
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_12_public_endpoints_accessible(client):
    """AUTH-12: /health, /mode, / are accessible without auth."""
    assert client.get("/health").status_code == 200
    assert client.get("/mode").status_code == 200
    assert client.get("/").status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-13: Protected endpoints return 401 without token
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/scans",
    "/findings",
    "/rules",
    "/resources",
    "/posture",
    "/auth/me",
    "/auth/users",
])
def test_AUTH_13_protected_endpoints_require_auth(client, path):
    """AUTH-13: Protected endpoints return 401 when no token is provided."""
    resp = client.get(path)
    assert resp.status_code == 401, f"Expected 401 for {path}, got {resp.status_code}"


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-14: Admin can access all endpoints
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_14_admin_can_access_protected_endpoints(client, admin_headers):
    """AUTH-14: Admin can access scan, findings, rules, resources, posture."""
    for path in ["/scans", "/findings", "/rules", "/resources", "/posture"]:
        resp = client.get(path, headers=admin_headers)
        assert resp.status_code == 200, f"Admin got {resp.status_code} for {path}"


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-15: Viewer can read but not create scans
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_15_viewer_read_access(client, viewer_headers):
    """AUTH-15: Viewer can read scans but not create them (403 on POST /scans)."""
    get_resp = client.get("/scans", headers=viewer_headers)
    assert get_resp.status_code == 200

    post_resp = client.post("/scans", json={}, headers=viewer_headers)
    assert post_resp.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-16: Operator can read and create scans
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_16_operator_can_create_scans(client, operator_headers):
    """AUTH-16: Operator has scans.create permission — POST /scans returns 201."""
    resp = client.post("/scans", json={}, headers=operator_headers)
    assert resp.status_code in (200, 201), (
        f"Operator scan create returned {resp.status_code}: {resp.text}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-17: Security Analyst can read findings and investigation
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_17_analyst_can_read_findings(client, analyst_headers):
    """AUTH-17: Security Analyst has findings.read permission."""
    resp = client.get("/findings", headers=analyst_headers)
    assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-18: Only admin can manage users
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_18_user_management_admin_only(client, admin_headers, viewer_headers, analyst_headers):
    """AUTH-18: GET /auth/users — admin sees 200, viewer/analyst without users.read see 403."""
    admin_resp = client.get("/auth/users", headers=admin_headers)
    assert admin_resp.status_code == 200

    viewer_resp = client.get("/auth/users", headers=viewer_headers)
    assert viewer_resp.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-19: Admin can create a user
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_19_admin_create_user(client, admin_headers):
    """AUTH-19: Admin can POST /auth/users to create a new user."""
    unique_name = f"testuser_{uuid.uuid4().hex[:8]}"
    resp = client.post("/auth/users", json={
        "username": unique_name,
        "password": "SecurePass12!@#",
        "role": "VIEWER",
    }, headers=admin_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["username"] == unique_name
    assert data["role"] == "VIEWER"
    assert "password_hash" not in data
    assert "user_id" in data


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-20: Non-admin cannot create users
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_20_non_admin_cannot_create_user(client, viewer_headers, operator_headers):
    """AUTH-20: Viewer and Operator get 403 when attempting to create a user."""
    for headers in [viewer_headers, operator_headers]:
        resp = client.post("/auth/users", json={
            "username": f"testuser_{uuid.uuid4().hex[:8]}",
            "password": "SecurePass12!@#",
            "role": "VIEWER",
        }, headers=headers)
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-21: Password change requires correct current password
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_21_change_password_wrong_current(client, setup_auth_db):
    """AUTH-21: POST /auth/change-password with wrong current password returns 401."""
    login_resp = client.post("/auth/login", json={
        "username": "test_analyst",
        "password": "AnalystTestPass12!",
    })
    token = login_resp.json()["access_token"]
    resp = client.post(
        "/auth/change-password",
        json={"current_password": "WrongPassword!", "new_password": "NewPass12!@#"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-22: Disabled user cannot log in
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_22_disabled_user_cannot_login(client, admin_headers, setup_auth_db):
    """AUTH-22: Disabling a user prevents future logins."""
    # Create a user
    unique_name = f"disabletest_{uuid.uuid4().hex[:8]}"
    create_resp = client.post("/auth/users", json={
        "username": unique_name,
        "password": "DisablePass12!",
        "role": "VIEWER",
    }, headers=admin_headers)
    assert create_resp.status_code == 201
    user_id = create_resp.json()["user_id"]

    # Verify they can log in
    login_resp = client.post("/auth/login", json={
        "username": unique_name,
        "password": "DisablePass12!",
    })
    assert login_resp.status_code == 200

    # Disable the user
    disable_resp = client.post(f"/auth/users/{user_id}/disable", headers=admin_headers)
    assert disable_resp.status_code == 204

    # Login should now fail (same generic 401)
    login_resp2 = client.post("/auth/login", json={
        "username": unique_name,
        "password": "DisablePass12!",
    })
    assert login_resp2.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-23: Disabled user's existing token becomes invalid
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_23_disabled_user_token_rejected(client, admin_headers, setup_auth_db):
    """AUTH-23: Access token of a disabled user is rejected by get_current_user."""
    unique_name = f"tokentest_{uuid.uuid4().hex[:8]}"
    create_resp = client.post("/auth/users", json={
        "username": unique_name,
        "password": "TokenTestPass12!",
        "role": "VIEWER",
    }, headers=admin_headers)
    user_id = create_resp.json()["user_id"]

    login_resp = client.post("/auth/login", json={
        "username": unique_name,
        "password": "TokenTestPass12!",
    })
    token = login_resp.json()["access_token"]

    # Token works before disable
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200

    # Disable user
    client.post(f"/auth/users/{user_id}/disable", headers=admin_headers)

    # Token no longer works
    me_resp2 = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp2.status_code == 401


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-24: 401 vs 403 distinction
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_24_401_vs_403_distinction(client, viewer_headers):
    """AUTH-24: No token = 401; wrong role = 403."""
    # No token → 401 (unauthenticated)
    no_auth = client.post("/auth/users", json={"username": "x", "password": "y" * 12, "role": "VIEWER"})
    assert no_auth.status_code == 401

    # Valid token but wrong role → 403 (authenticated but unauthorized)
    viewer_create = client.post(
        "/auth/users",
        json={"username": "test_new", "password": "TestPass12!@", "role": "VIEWER"},
        headers=viewer_headers,
    )
    assert viewer_create.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-25: Admin can list users
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_25_admin_list_users(client, admin_headers):
    """AUTH-25: GET /auth/users returns paginated user list to admin."""
    resp = client.get("/auth/users", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)
    assert data["total"] > 0
    # Verify no password_hash in any user response
    for user in data["items"]:
        assert "password_hash" not in user


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-26: Admin can get user by ID
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_26_admin_get_user_by_id(client, admin_headers):
    """AUTH-26: GET /auth/users/{user_id} returns user details."""
    # Get own profile to get user_id
    me = client.get("/auth/me", headers=admin_headers)
    user_id = me.json()["user_id"]

    resp = client.get(f"/auth/users/{user_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["user_id"] == user_id
    assert "password_hash" not in resp.json()


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-27: Analyst can read users (users.read permission)
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_27_analyst_can_read_users(client, analyst_headers):
    """AUTH-27: Security Analyst has users.read permission — can GET /auth/users."""
    resp = client.get("/auth/users", headers=analyst_headers)
    assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-28: Role change requires admin
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_28_role_change_admin_only(client, admin_headers, viewer_headers, setup_auth_db):
    """AUTH-28: PATCH /auth/users/{id} to change role requires users.manage."""
    # Create a user
    unique_name = f"roletest_{uuid.uuid4().hex[:8]}"
    create_resp = client.post("/auth/users", json={
        "username": unique_name,
        "password": "RoleTestPass12!",
        "role": "VIEWER",
    }, headers=admin_headers)
    user_id = create_resp.json()["user_id"]

    # Admin can change role
    admin_resp = client.patch(
        f"/auth/users/{user_id}",
        json={"role": "OPERATOR"},
        headers=admin_headers,
    )
    assert admin_resp.status_code == 200
    assert admin_resp.json()["role"] == "OPERATOR"

    # Viewer cannot change roles
    viewer_resp = client.patch(
        f"/auth/users/{user_id}",
        json={"role": "ADMIN"},
        headers=viewer_headers,
    )
    assert viewer_resp.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-29: Duplicate username rejected
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_29_duplicate_username_rejected(client, admin_headers):
    """AUTH-29: Creating a user with an existing username returns 409."""
    unique_name = f"duptest_{uuid.uuid4().hex[:8]}"
    first = client.post("/auth/users", json={
        "username": unique_name,
        "password": "DupTestPass12!",
        "role": "VIEWER",
    }, headers=admin_headers)
    assert first.status_code == 201

    second = client.post("/auth/users", json={
        "username": unique_name,
        "password": "AnotherPass12!",
        "role": "OPERATOR",
    }, headers=admin_headers)
    assert second.status_code == 409


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-30: Short password rejected (< 12 chars)
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_30_short_password_rejected(client, admin_headers):
    """AUTH-30: Creating a user with < 12 char password returns 422."""
    resp = client.post("/auth/users", json={
        "username": f"shortpass_{uuid.uuid4().hex[:6]}",
        "password": "short",
        "role": "VIEWER",
    }, headers=admin_headers)
    assert resp.status_code == 422


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-31: Enable a disabled user
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_31_enable_user(client, admin_headers, setup_auth_db):
    """AUTH-31: Admin can re-enable a disabled user."""
    unique_name = f"reenabletest_{uuid.uuid4().hex[:8]}"
    create_resp = client.post("/auth/users", json={
        "username": unique_name,
        "password": "ReenablePass12!",
        "role": "VIEWER",
    }, headers=admin_headers)
    user_id = create_resp.json()["user_id"]

    # Disable
    client.post(f"/auth/users/{user_id}/disable", headers=admin_headers)
    disabled_login = client.post("/auth/login", json={
        "username": unique_name, "password": "ReenablePass12!",
    })
    assert disabled_login.status_code == 401

    # Re-enable
    enable_resp = client.post(f"/auth/users/{user_id}/enable", headers=admin_headers)
    assert enable_resp.status_code == 204

    # Now login works
    enabled_login = client.post("/auth/login", json={
        "username": unique_name, "password": "ReenablePass12!",
    })
    assert enabled_login.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-32: RBAC enforced from DB, not JWT claims
# ──────────────────────────────────────────────────────────────────────────────

def test_AUTH_32_rbac_authoritative_from_db(client, admin_headers, setup_auth_db):
    """
    AUTH-32: After an admin changes a user's role, authorization reflects
    the new role immediately — proving DB state is authoritative, not JWT claims.
    """
    unique_name = f"rbactest_{uuid.uuid4().hex[:8]}"
    create_resp = client.post("/auth/users", json={
        "username": unique_name,
        "password": "RbacTestPass12!",
        "role": "VIEWER",
    }, headers=admin_headers)
    assert create_resp.status_code == 201
    user_id = create_resp.json()["user_id"]

    # Get a token as VIEWER (can't create scans)
    login_resp = client.post("/auth/login", json={
        "username": unique_name,
        "password": "RbacTestPass12!",
    })
    viewer_token = login_resp.json()["access_token"]

    # Verify viewer can't create scan
    scan_resp = client.post("/scans", json={}, headers={
        "Authorization": f"Bearer {viewer_token}"
    })
    assert scan_resp.status_code == 403

    # Admin upgrades user to OPERATOR
    client.patch(f"/auth/users/{user_id}", json={"role": "OPERATOR"}, headers=admin_headers)

    # REUSE the OLD VIEWER token to prove authorization is checked against the DB dynamically,
    # not from stale permissions in the JWT!
    scan_resp2 = client.post("/scans", json={}, headers={
        "Authorization": f"Bearer {viewer_token}"
    })
    assert scan_resp2.status_code in (200, 201)


# ──────────────────────────────────────────────────────────────────────────────
# AUTH-REG: Public Registration & Privilege Escalation Prevention
# ──────────────────────────────────────────────────────────────────────────────

class TestPublicRegistrationPrivilegeEscalation:
    def test_registration_with_admin_role_rejected_with_403(self, client, setup_auth_db):
        """Direct HTTP registration attempting role=ADMIN must be rejected with 403."""
        uid = str(uuid.uuid4())[:8]
        resp = client.post("/auth/register", json={
            "username": f"attacker_admin_{uid}",
            "email": f"attacker_{uid}@defense.cloud",
            "password": "SecurePassword123!",
            "role": "ADMIN",
        })
        assert resp.status_code == 403
        data = resp.json()
        assert data["error_code"] == "AUTH_FORBIDDEN"
        assert "Privilege escalation rejected" in data["message"]

    def test_registration_with_security_analyst_role_rejected_with_403(self, client, setup_auth_db):
        """Direct HTTP registration attempting role=SECURITY_ANALYST must be rejected with 403."""
        uid = str(uuid.uuid4())[:8]
        resp = client.post("/auth/register", json={
            "username": f"attacker_analyst_{uid}",
            "email": f"analyst_{uid}@defense.cloud",
            "password": "SecurePassword123!",
            "role": "SECURITY_ANALYST",
        })
        assert resp.status_code == 403
        data = resp.json()
        assert data["error_code"] == "AUTH_FORBIDDEN"
        assert "Privilege escalation rejected" in data["message"]

    def test_registration_with_operator_role_rejected_with_403(self, client, setup_auth_db):
        """Direct HTTP registration attempting role=OPERATOR must be rejected with 403."""
        uid = str(uuid.uuid4())[:8]
        resp = client.post("/auth/register", json={
            "username": f"attacker_operator_{uid}",
            "email": f"operator_{uid}@defense.cloud",
            "password": "SecurePassword123!",
            "role": "OPERATOR",
        })
        assert resp.status_code == 403
        data = resp.json()
        assert data["error_code"] == "AUTH_FORBIDDEN"
        assert "Privilege escalation rejected" in data["message"]

    def test_registration_with_viewer_role_succeeds(self, client, setup_auth_db):
        """Direct HTTP registration with role=VIEWER succeeds with 201 and issues tokens."""
        uid = str(uuid.uuid4())[:8]
        resp = client.post("/auth/register", json={
            "username": f"legit_viewer_{uid}",
            "email": f"viewer_{uid}@defense.cloud",
            "password": "SecurePassword123!",
            "role": "VIEWER",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["role"] == "VIEWER"

    def test_registration_without_role_defaults_to_viewer(self, client, setup_auth_db):
        """Direct HTTP registration without role field defaults to VIEWER."""
        uid = str(uuid.uuid4())[:8]
        resp = client.post("/auth/signup", json={
            "username": f"default_viewer_{uid}",
            "email": f"default_{uid}@defense.cloud",
            "password": "SecurePassword123!",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["role"] == "VIEWER"

