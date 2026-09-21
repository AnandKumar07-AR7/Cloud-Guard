"""
Unit and Integration tests for CloudGuard HTTPS Security Migration.

Verifies:
1. Dynamic HSTS (Strict-Transport-Security) header injection on HTTPS / X-Forwarded-Proto.
2. HSTS omission on plain HTTP development requests.
3. Strict CORS verification for HTTPS production origins.
4. Rejection of unauthorized origins and wildcard '*' origins.
5. Preservation of all defense-in-depth security headers (CSP, X-Frame-Options, etc.).
"""
import pytest
from fastapi.testclient import TestClient
from config.settings import Settings
from main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestHTTPSSecurityHeaders:
    """Verify HSTS behavior and security response headers."""

    def test_hsts_header_present_when_x_forwarded_proto_https(self, client):
        """When request is proxied via HTTPS, backend must return Strict-Transport-Security."""
        response = client.get("/health", headers={"x-forwarded-proto": "https"})
        assert response.status_code == 200
        assert "strict-transport-security" in response.headers
        hsts = response.headers["strict-transport-security"]
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    def test_hsts_header_absent_on_plain_http_dev_requests(self, client):
        """Plain HTTP requests without HTTPS proxy headers should not receive HSTS."""
        response = client.get("/health")
        assert response.status_code == 200
        assert "strict-transport-security" not in response.headers

    def test_all_defense_in_depth_headers_preserved_on_https(self, client):
        """Verify that all core security headers remain present on HTTPS responses."""
        response = client.get("/health", headers={"x-forwarded-proto": "https"})
        assert response.status_code == 200

        # Anti-sniffing
        assert response.headers.get("x-content-type-options") == "nosniff"

        # Frame protection / anti-clickjacking
        assert response.headers.get("x-frame-options") == "DENY"

        # Content Security Policy
        assert "content-security-policy" in response.headers
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

        # Referrer policy
        assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

        # Permissions policy
        assert "permissions-policy" in response.headers

        # Cross-Origin isolation
        assert response.headers.get("cross-origin-opener-policy") == "same-origin"
        assert response.headers.get("cross-origin-resource-policy") == "same-origin"

        # Cache control for API responses
        assert "no-store" in response.headers.get("cache-control", "")


class TestHTTPSCORS:
    """Verify CORS policy enforcement for HTTPS origins."""

    def test_cors_allows_configured_https_origin(self, client):
        """HTTPS origin in allowed list receives Access-Control-Allow-Origin."""
        response = client.options(
            "/health",
            headers={
                "Origin": "https://localhost",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("access-control-allow-origin") == "https://localhost"
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_cors_allows_https_3000_origin(self, client):
        """HTTPS port 3000 origin receives Access-Control-Allow-Origin."""
        response = client.options(
            "/health",
            headers={
                "Origin": "https://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("access-control-allow-origin") == "https://localhost:3000"

    def test_cors_allows_https_127_0_0_1_origin(self, client):
        """HTTPS 127.0.0.1 origin receives Access-Control-Allow-Origin."""
        response = client.options(
            "/health",
            headers={
                "Origin": "https://127.0.0.1",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("access-control-allow-origin") == "https://127.0.0.1"

    def test_cors_rejects_unauthorized_external_origin(self, client):
        """Untrusted origins must NOT receive Access-Control-Allow-Origin."""
        response = client.options(
            "/health",
            headers={
                "Origin": "https://attacker.evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in response.headers

    def test_cors_wildcard_prohibited_in_settings(self):
        """Settings validator must reject wildcard '*' in CORS_ORIGINS."""
        with pytest.raises(ValueError, match="Wildcard CORS origin"):
            Settings(cors_origins="*")

        with pytest.raises(ValueError, match="Wildcard CORS origin"):
            Settings(cors_origins="https://localhost,*")
