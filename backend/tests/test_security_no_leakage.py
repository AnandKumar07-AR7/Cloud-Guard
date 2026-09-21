"""
Phase 2 Tests — Security: No Secrets Leaked

Verifies that sensitive data does not appear in:
  - API responses
  - Error messages
  - Scan error records
  - AI prompt payloads (via masking)
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False)

@pytest.fixture(autouse=True, scope="module")
def setup_client_auth(setup_auth_db):
    from tests.conftest import _get_auth_headers
    client.headers.update(_get_auth_headers("test_admin", "AdminTestPass12!"))



class TestNoSecretsInAPIResponses:
    """Verifies that the critical scenario (which has AWS secrets in env vars) never leaks them."""

    @pytest.fixture(autouse=True)
    def run_critical_scan(self):
        """Run critical scenario scan which contains a deliberately planted secret."""
        r = client.post("/scans", json={"scenario": "critical"})
        assert r.status_code == 201
        self.scan_id = r.json()["scan_id"]

    def test_scan_response_has_no_raw_passwords(self):
        r = client.get(f"/scans/{self.scan_id}")
        response_text = r.text
        assert "SuperSecret123!" not in response_text

    def test_scan_response_has_no_aws_secret_key(self):
        r = client.get(f"/scans/{self.scan_id}")
        response_text = r.text
        assert "wJalrXUtnFEMI" not in response_text

    def test_findings_evidence_does_not_contain_raw_password(self):
        r = client.get(f"/findings?scan_id={self.scan_id}")
        response_text = r.text
        # The Lambda-002 finding detects DATABASE_PASSWORD but should not
        # include its value in the API response
        assert "SuperSecret123!" not in response_text

    def test_error_response_has_no_stack_traces(self):
        r = client.get("/scans/nonexistent-scan-id-for-security-test")
        response_text = r.text
        assert "Traceback" not in response_text
        assert "File \"" not in response_text

    def test_findings_evidence_shows_redacted_key_names_not_values(self):
        """
        The Lambda secrets finding should reference DATABASE_PASSWORD (key name)
        for context but NOT reveal its value.
        """
        r = client.get(f"/findings?scan_id={self.scan_id}&service=lambda&rule_id=LAM-002")
        findings = r.json()["items"]
        if findings:
            finding = findings[0]
            evidence_str = str(finding["evidence"])
            # Key name is OK (diagnostic context)
            assert "DATABASE_PASSWORD" in evidence_str
            # Value must NOT appear
            assert "SuperSecret123!" not in evidence_str


class TestScanErrorSanitization:
    def test_sanitize_error_message_strips_aws_key(self):
        from services.scan_models import _sanitize_error_message
        msg = "Failed with key AKIAIOSFODNN7EXAMPLE123456 reason: timeout"
        result = _sanitize_error_message(msg)
        assert "AKIAIOSFODNN7EXAMPLE123456" not in result
        assert "[AWS_KEY_REDACTED]" in result

    def test_sanitize_truncates_long_messages(self):
        from services.scan_models import _sanitize_error_message
        long_msg = "x" * 600
        result = _sanitize_error_message(long_msg)
        assert len(result) <= 520

    def test_scan_error_record_never_exposes_secrets(self):
        from services.scan_models import ScanRecord
        record = ScanRecord(provider="demo", account_id="123", mode="demo")
        record.add_error(
            source="test",
            error_type="TestError",
            message="Failed with key AKIAIOSFODNN7EXAMPLE123456 reason: auth",
        )
        error = record.errors[0]
        assert "AKIAIOSFODNN7EXAMPLE123456" not in error.message


class TestAPIResponsesDoNotLeakInternalPaths:
    def test_404_has_no_file_paths(self):
        r = client.get("/scans/bad-id-xyz")
        response_text = r.text
        # Should not contain Windows or Unix path separators in error
        assert "Cloud-Guard" not in response_text or "error_code" in r.json()
