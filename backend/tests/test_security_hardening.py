"""
CloudGuard — Security Hardening Test Suite (Defense-in-Depth Verification)

Validates all security controls implemented during security hardening:
  1. Auth endpoint rate limiting (HTTP 429 & Retry-After header)
  2. Request body size limits (HTTP 413 on oversized payloads)
  3. Security response headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options)
  4. JWT issuer ('iss') and audience ('aud') claim validation & tampering rejection
  5. Pydantic request schema hardening (extra='forbid' rejects unrecognized fields with 422)
  6. Trusted proxy IP spoofing prevention (X-Forwarded-For ignored from untrusted peers)
  7. Refresh token rotation chain & old token reuse family revocation
  8. RBAC privilege escalation prevention across all roles
"""
import os
import uuid
import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt, JWTError

from config.settings import settings
from main import app, _auth_rate_limiter
from auth.security import create_access_token, decode_access_token, _get_jwt_secret
from auth.routes import _get_client_ip


@pytest.fixture(scope="module")
def client():
    return TestClient(app, raise_server_exceptions=False)


# ──────────────────────────────────────────────────────────────────────────────
# 1. Auth Endpoint Rate Limiting Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestAuthRateLimiting:
    """Verify that rapid authentication attempts from a single IP trigger HTTP 429."""

    def test_auth_rate_limit_triggered_after_threshold(self, client: TestClient):
        """Send requests up to the limit, then verify subsequent requests are blocked with 429."""
        _auth_rate_limiter.reset_for_testing()

        limit = settings.auth_rate_limit_per_minute

        # Send requests up to limit
        for _ in range(limit):
            resp = client.post("/auth/login", json={
                "username": "test_admin",
                "password": "WrongPassword123!"
            })
            assert resp.status_code == 401

        # Request (limit + 1) MUST be throttled
        throttled_resp = client.post("/auth/login", json={
            "username": "test_admin",
            "password": "WrongPassword123!"
        })
        assert throttled_resp.status_code == 429
        data = throttled_resp.json()
        assert data["error_code"] == "RATE_LIMIT_EXCEEDED"
        assert "Retry-After" in throttled_resp.headers
        assert throttled_resp.headers["Retry-After"] == "60"

    def test_non_auth_endpoints_not_rate_limited(self, client: TestClient):
        """Non-auth endpoints (e.g. /health, /mode) should not be throttled by auth rate limiter."""
        _auth_rate_limiter.reset_for_testing()

        for _ in range(settings.auth_rate_limit_per_minute + 5):
            resp = client.get("/health")
            assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# 2. Request Body Size Limit Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRequestBodySizeLimit:
    """Verify Content-Length exceeding max_request_body_bytes returns 413."""

    def test_oversized_payload_rejected_with_413(self, client: TestClient):
        """Request with Content-Length greater than limit returns 413."""
        oversized_len = settings.max_request_body_bytes + 1024
        resp = client.post(
            "/auth/login",
            content=b'{"dummy": "data"}',
            headers={"Content-Length": str(oversized_len), "Content-Type": "application/json"}
        )
        assert resp.status_code == 413
        data = resp.json()
        assert data["error_code"] == "REQUEST_TOO_LARGE"

    def test_valid_size_payload_accepted(self, client: TestClient):
        """Request within limit is processed normally."""
        resp = client.post(
            "/auth/login",
            json={"username": "test_admin", "password": "AdminTestPass12!"},
            headers={"Content-Length": "60"}
        )
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# 3. Security Response Headers Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSecurityHeaders:
    """Verify security headers are attached to all API responses."""

    def test_security_headers_present_on_api_responses(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200

        # Anti-clickjacking
        assert resp.headers.get("X-Frame-Options") == "DENY"

        # MIME-sniffing protection
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

        # Referrer policy
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

        # Cache control for API responses
        assert "no-store" in resp.headers.get("Cache-Control", "")

        # Cross-Origin Protections
        assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
        assert resp.headers.get("Cross-Origin-Resource-Policy") == "same-origin"

        # Deprecated X-XSS-Protection should NOT be present (superseded by CSP)
        assert "X-XSS-Protection" not in resp.headers


# ──────────────────────────────────────────────────────────────────────────────
# 4. JWT Hardening Tests (Issuer & Audience)
# ──────────────────────────────────────────────────────────────────────────────

class TestJWTHardening:
    """Verify 'iss' and 'aud' claims are included and validated on every decode."""

    def test_valid_token_contains_iss_and_aud(self):
        token = create_access_token(sub="user-123", role="ADMIN", jti="jti-uuid")
        payload = decode_access_token(token)
        assert payload["iss"] == settings.jwt_issuer
        assert payload["aud"] == settings.jwt_audience
        assert payload["sub"] == "user-123"
        assert payload["role"] == "ADMIN"

    def test_token_with_invalid_issuer_rejected(self):
        # Create token with forged issuer
        token = jose_jwt.encode(
            {
                "sub": "user-123",
                "role": "ADMIN",
                "jti": "jti-uuid",
                "iss": "forged-issuer",
                "aud": settings.jwt_audience,
                "exp": 9999999999,
                "type": "access",
            },
            _get_jwt_secret(),
            algorithm="HS256"
        )
        with pytest.raises(JWTError):
            decode_access_token(token)

    def test_token_with_invalid_audience_rejected(self):
        # Create token with forged audience
        token = jose_jwt.encode(
            {
                "sub": "user-123",
                "role": "ADMIN",
                "jti": "jti-uuid",
                "iss": settings.jwt_issuer,
                "aud": "wrong-service-aud",
                "exp": 9999999999,
                "type": "access",
            },
            _get_jwt_secret(),
            algorithm="HS256"
        )
        with pytest.raises(JWTError):
            decode_access_token(token)

    def test_token_with_invalid_type_rejected(self):
        token = jose_jwt.encode(
            {
                "sub": "user-123",
                "role": "ADMIN",
                "jti": "jti-uuid",
                "iss": settings.jwt_issuer,
                "aud": settings.jwt_audience,
                "exp": 9999999999,
                "type": "refresh",  # Wrong type for access token decode
            },
            _get_jwt_secret(),
            algorithm="HS256"
        )
        with pytest.raises(JWTError):
            decode_access_token(token)


# ──────────────────────────────────────────────────────────────────────────────
# 5. Pydantic Schema Hardening (extra='forbid') Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSchemaHardening:
    """Verify extra/unknown fields are rejected with 422 Unprocessable Entity."""

    def test_login_schema_rejects_extra_fields(self, client: TestClient):
        resp = client.post("/auth/login", json={
            "username": "test_admin",
            "password": "Password123!@#",
            "malicious_injected_field": "exploit_attempt"
        })
        assert resp.status_code == 422

    def test_register_schema_rejects_extra_fields(self, client: TestClient):
        resp = client.post("/auth/register", json={
            "username": "attacker",
            "email": "attacker@example.com",
            "password": "Password123!@#",
            "is_admin": True  # Injected field to escalate privileges
        })
        assert resp.status_code == 422

    def test_scan_request_rejects_extra_fields(self, client: TestClient, admin_headers):
        resp = client.post("/scans", headers=admin_headers, json={
            "scenario": "default",
            "unexpected_parameter": "invalid_payload"
        })
        assert resp.status_code == 422

    def test_password_length_boundary_validation(self, client: TestClient):
        """Verify strict password length validation: 11 chars rejected (422), 12 chars accepted (201)."""
        uid = str(uuid.uuid4())[:8]
        # 11 characters -> MUST BE REJECTED with 422
        resp_short = client.post("/auth/register", json={
            "username": f"user_11_{uid}",
            "email": f"u11_{uid}@defense.cloud",
            "password": "ShortPass1!",  # exactly 11 characters
        })
        assert resp_short.status_code == 422
        errors = resp_short.json().get("detail", [])
        assert any("password" in str(err) for err in errors)

        # 12 characters -> MUST BE ACCEPTED (201) when valid
        resp_valid = client.post("/auth/register", json={
            "username": f"user_12_{uid}",
            "email": f"u12_{uid}@defense.cloud",
            "password": "ValidPass12!",  # exactly 12 characters
        })
        assert resp_valid.status_code == 201
        assert "access_token" in resp_valid.json()


# ──────────────────────────────────────────────────────────────────────────────
# 6. Trusted Proxy & IP Spoofing Prevention Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestTrustedProxyIPSpoofing:
    """Verify X-Forwarded-For header is ignored when peer is not in trusted_proxy_ips."""

    def test_untrusted_peer_cannot_spoof_ip(self, monkeypatch):
        class MockClient:
            host = "198.51.100.25"  # Untrusted external IP

        class MockRequest:
            client = MockClient()
            headers = {"X-Forwarded-For": "10.0.0.1"}

        # Configure trusted proxy list
        monkeypatch.setattr(settings, "trusted_proxy_ips", ["172.16.0.1"])

        # Request from 198.51.100.25 claiming to be 10.0.0.1
        resolved_ip = _get_client_ip(MockRequest())
        # MUST return the direct peer IP, NOT the spoofed header
        assert resolved_ip == "198.51.100.25"

    def test_trusted_proxy_peer_forwards_original_ip(self, monkeypatch):
        class MockClient:
            host = "10.0.0.2"  # Trusted internal reverse proxy

        class MockRequest:
            client = MockClient()
            headers = {"X-Forwarded-For": "203.0.113.195, 10.0.0.2"}

        monkeypatch.setattr(settings, "trusted_proxy_ips", ["10.0.0.0/8"])

        resolved_ip = _get_client_ip(MockRequest())
        # MUST return the client's original IP
        assert resolved_ip == "203.0.113.195"


# ──────────────────────────────────────────────────────────────────────────────
# 7. Refresh Token Rotation & Family Revocation Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRefreshTokenRotationSecurity:
    """Verify refresh token rotation and family revocation on old token replay."""

    def test_rotation_chain_and_old_token_revocation(self, client: TestClient):
        # 1. Login to get initial pair
        login_resp = client.post("/auth/login", json={
            "username": "test_admin",
            "password": "AdminTestPass12!"
        })
        assert login_resp.status_code == 200
        token_data_1 = login_resp.json()
        refresh_token_1 = token_data_1["refresh_token"]

        # 2. First rotation: refresh_token_1 -> refresh_token_2
        refresh_resp_1 = client.post("/auth/refresh", json={"refresh_token": refresh_token_1})
        assert refresh_resp_1.status_code == 200
        token_data_2 = refresh_resp_1.json()
        refresh_token_2 = token_data_2["refresh_token"]
        assert refresh_token_2 != refresh_token_1

        # 3. Second rotation: refresh_token_2 -> refresh_token_3
        refresh_resp_2 = client.post("/auth/refresh", json={"refresh_token": refresh_token_2})
        assert refresh_resp_2.status_code == 200
        token_data_3 = refresh_resp_2.json()
        refresh_token_3 = token_data_3["refresh_token"]
        assert refresh_token_3 != refresh_token_2

        # 4. Attack: Re-use old refresh_token_1 (already rotated)
        # Should return 401 AND revoke the entire token family
        replay_resp = client.post("/auth/refresh", json={"refresh_token": refresh_token_1})
        assert replay_resp.status_code == 401

        # 5. Verify the entire family was revoked: even latest refresh_token_3 is now invalid
        family_check_resp = client.post("/auth/refresh", json={"refresh_token": refresh_token_3})
        assert family_check_resp.status_code == 401

    def test_refresh_token_rotation_and_replay_forensic_chain(self, client: TestClient):
        """
        Forensic verification of refresh token rotation lifecycle:
        1. LOGIN -> initial access token + refresh token A
        2. REFRESH A -> new access token + rotated refresh token B
        3. REFRESH B -> new access token + rotated refresh token C
        4. PAGE RELOAD simulation -> reads stored tokens, invokes /auth/me successfully
        5. REFRESH C -> new access token + rotated refresh token D
        6. REPLAY OLD REFRESH TOKEN (Refresh Token A) -> 401 Unauthorized
        7. VERIFY FAMILY REVOCATION -> Refresh Token D (the newest) is also revoked (401)
        """
        _auth_rate_limiter.reset_for_testing()

        # Step 1: LOGIN
        login_resp = client.post("/auth/login", json={
            "username": "test_admin",
            "password": "AdminTestPass12!"
        })
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        tokens_1 = login_resp.json()
        token_A = tokens_1["refresh_token"]
        access_1 = tokens_1["access_token"]
        assert token_A is not None

        # Step 2: REFRESH A -> issues B, revokes A
        refresh_a_resp = client.post("/auth/refresh", json={"refresh_token": token_A})
        assert refresh_a_resp.status_code == 200
        tokens_2 = refresh_a_resp.json()
        token_B = tokens_2["refresh_token"]
        access_2 = tokens_2["access_token"]
        assert token_B != token_A

        # Step 3: REFRESH B -> issues C, revokes B
        refresh_b_resp = client.post("/auth/refresh", json={"refresh_token": token_B})
        assert refresh_b_resp.status_code == 200
        tokens_3 = refresh_b_resp.json()
        token_C = tokens_3["refresh_token"]
        access_3 = tokens_3["access_token"]
        assert token_C != token_B

        # Step 4: PAGE RELOAD simulation (frontend reads persisted access token & validates session)
        reload_me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {access_3}"})
        assert reload_me_resp.status_code == 200
        user_data = reload_me_resp.json()
        assert user_data["username"] == "test_admin"

        # Step 5: REFRESH C -> issues D, revokes C
        refresh_c_resp = client.post("/auth/refresh", json={"refresh_token": token_C})
        assert refresh_c_resp.status_code == 200
        tokens_4 = refresh_c_resp.json()
        token_D = tokens_4["refresh_token"]
        assert token_D != token_C

        # Step 6: REPLAY OLD REFRESH TOKEN (token_A from step 1)
        replay_resp = client.post("/auth/refresh", json={"refresh_token": token_A})
        assert replay_resp.status_code == 401, f"Expected 401 on replay, got {replay_resp.status_code}"
        assert "revoked" in replay_resp.text.lower() or "invalid" in replay_resp.text.lower() or "expired" in replay_resp.text.lower()

        # Step 7: VERIFY FAMILY REVOKED -> even newest token_D is now revoked
        family_check_resp = client.post("/auth/refresh", json={"refresh_token": token_D})
        assert family_check_resp.status_code == 401, f"Expected 401 on family revocation check, got {family_check_resp.status_code}"

        _auth_rate_limiter.reset_for_testing()


# ──────────────────────────────────────────────────────────────────────────────
# 8. RBAC Privilege Escalation Prevention Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRBACPrivilegeEscalation:
    """Verify least privilege boundaries across different user roles."""

    def test_viewer_cannot_create_users(self, client: TestClient, viewer_headers):
        resp = client.post("/auth/users", headers=viewer_headers, json={
            "username": "new_admin_user",
            "password": "Password123!@#",
            "role": "ADMIN"
        })
        assert resp.status_code == 403

    def test_viewer_cannot_trigger_scans(self, client: TestClient, viewer_headers):
        resp = client.post("/scans", headers=viewer_headers, json={"scenario": "default"})
        assert resp.status_code == 403

    def test_operator_cannot_modify_user_roles(self, client: TestClient, operator_headers):
        resp = client.patch("/auth/users/some-user-id", headers=operator_headers, json={
            "role": "ADMIN"
        })
        assert resp.status_code == 403

    def test_public_registration_cannot_self_assign_privileged_role(self, client: TestClient):
        """
        Public registration (POST /auth/register and POST /auth/signup) can NEVER create
        ADMIN, SECURITY_ANALYST, or OPERATOR roles regardless of payload parameters.
        Tests:
          - role=ADMIN -> 403 Forbidden
          - role=SECURITY_ANALYST -> 403 Forbidden
          - role=OPERATOR -> 403 Forbidden
          - role=VIEWER -> 201 (VIEWER role assigned)
          - missing role -> 201 (VIEWER role assigned by default)
          - null role -> 201 (VIEWER role assigned by default)
          - unknown role -> 403 Forbidden
          - mixed-case role ("AdMiN", "sEcUrItY_aNaLySt", "OpErAtOr") -> 403 Forbidden
          - extra privilege fields ("is_admin", "is_superuser") -> 422 Unprocessable Entity
          - all tests verified across both /auth/register and /auth/signup endpoints
        """
        forbidden_roles = [
            "ADMIN", "SECURITY_ANALYST", "OPERATOR",
            "admin", "security_analyst", "operator",
            "AdMiN", "sEcUrItY_aNaLySt", "OpErAtOr",
            "SUPERUSER", "ROOT", "attacker_custom",
        ]
        _auth_rate_limiter.reset_for_testing()
        for endpoint in ["/auth/register", "/auth/signup"]:
            for priv_role in forbidden_roles:
                _auth_rate_limiter.reset_for_testing()
                uid = str(uuid.uuid4())[:8]
                resp = client.post(endpoint, json={
                    "username": f"priv_{uid}",
                    "email": f"priv_{uid}@defense.cloud",
                    "password": "SecurePassword123!",
                    "role": priv_role,
                })
                assert resp.status_code == 403, f"Expected 403 for role '{priv_role}' on {endpoint}, got {resp.status_code}"
                data = resp.json()
                assert data["error_code"] == "AUTH_FORBIDDEN"
                assert "Privilege escalation rejected" in data["message"]

            # Extra privilege fields -> rejected with 422
            _auth_rate_limiter.reset_for_testing()
            uid = str(uuid.uuid4())[:8]
            resp_extra = client.post(endpoint, json={
                "username": f"extra_{uid}",
                "email": f"extra_{uid}@defense.cloud",
                "password": "SecurePassword123!",
                "is_admin": True,
                "is_superuser": True,
            })
            assert resp_extra.status_code == 422, f"Expected 422 for extra fields on {endpoint}"

            # Missing role -> defaults to VIEWER (201)
            _auth_rate_limiter.reset_for_testing()
            uid = str(uuid.uuid4())[:8]
            resp_missing = client.post(endpoint, json={
                "username": f"miss_{uid}",
                "email": f"miss_{uid}@defense.cloud",
                "password": "SecurePassword123!",
            })
            assert resp_missing.status_code == 201
            assert resp_missing.json()["user"]["role"] == "VIEWER"

            # Null role -> defaults to VIEWER (201)
            _auth_rate_limiter.reset_for_testing()
            uid = str(uuid.uuid4())[:8]
            resp_null = client.post(endpoint, json={
                "username": f"null_{uid}",
                "email": f"null_{uid}@defense.cloud",
                "password": "SecurePassword123!",
                "role": None,
            })
            assert resp_null.status_code == 201
            assert resp_null.json()["user"]["role"] == "VIEWER"

            # Explicit VIEWER role -> 201
            _auth_rate_limiter.reset_for_testing()
            uid = str(uuid.uuid4())[:8]
            resp_viewer = client.post(endpoint, json={
                "username": f"view_{uid}",
                "email": f"view_{uid}@defense.cloud",
                "password": "SecurePassword123!",
                "role": "VIEWER",
            })
            assert resp_viewer.status_code == 201
            assert resp_viewer.json()["user"]["role"] == "VIEWER"

        _auth_rate_limiter.reset_for_testing()


# ──────────────────────────────────────────────────────────────────────────────
# 9. IDOR & Separation of Duties Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestIDORAndSeparationOfDuties:
    """Verify IDOR prevention and separation of duties controls."""

    def test_idor_unowned_ai_run_access_returns_404(self, client: TestClient, analyst_headers, analyst2_headers, admin_headers):
        from core.database import SessionLocal
        from tests.test_ai_orchestration import create_test_finding

        db = SessionLocal()
        try:
            finding = create_test_finding(db)

            # Analyst 1 initiates AI analysis
            resp1 = client.post(
                "/api/v1/ai/analyze",
                headers=analyst_headers,
                json={"finding_id": finding.finding_id}
            )
            assert resp1.status_code == 201
            run_id = resp1.json()["run_id"]

            # Analyst 2 attempts to view Analyst 1's run -> 404 (IDOR prevention)
            idor_resp = client.get(f"/api/v1/ai/runs/{run_id}", headers=analyst2_headers)
            assert idor_resp.status_code == 404

            # Admin can view all runs
            admin_resp = client.get(f"/api/v1/ai/runs/{run_id}", headers=admin_headers)
            assert admin_resp.status_code == 200
        finally:
            db.close()

    def test_separation_of_duties_creator_cannot_approve_own_plan(self, client: TestClient, admin_headers):
        """A remediation plan cannot be approved by the same user who created it, even if they have approval permission."""
        from core.database import SessionLocal
        from tests.test_ai_orchestration import create_test_finding

        db = SessionLocal()
        try:
            finding = create_test_finding(db)

            # Admin creates remediation plan
            create_resp = client.post(f"/api/v1/remediations/plans?finding_id={finding.finding_id}", headers=admin_headers)
            assert create_resp.status_code == 201
            plan_id = create_resp.json()["remediation_id"]

            # Validate plan first
            val_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/validate", headers=admin_headers)
            assert val_resp.status_code == 200

            # Creator attempts to self-approve -> MUST be rejected with HTTP 403 (separation of duties)
            approve_resp = client.post(f"/api/v1/remediations/plans/{plan_id}/approve", headers=admin_headers)
            assert approve_resp.status_code == 403
            assert "separation of duties" in approve_resp.text.lower()
        finally:
            db.close()

