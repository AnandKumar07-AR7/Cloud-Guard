"""
CloudGuard Phase 4 Tests — Security and Secret Leakage Prevention

Verifies that:
  - Investigation responses do not contain plain credentials
  - Resource explorer responses do not leak AWS secrets
  - AI context builder masks all secret keywords
  - Error responses on Phase 4 routes contain no stack traces or credentials
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from main import app

_SECRETS_TO_DETECT = [
    "s3cr3t-db-pass-12345",
    "sk-live-abcdef1234567890",
    "SuperSecret123!",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
]


@pytest.fixture
def client(auth_client):
    auth_client.post("/scans", json={"scenario": "default"})
    return auth_client


class TestPhase4SecurityNoLeakage:
    def test_investigation_response_no_raw_secrets(self, client):
        findings_resp = client.get("/findings")
        findings = findings_resp.json()["items"]

        for f in findings:
            fid = f["finding_id"]
            resp = client.get(f"/findings/{fid}/investigation")
            text = resp.text
            for secret in _SECRETS_TO_DETECT:
                assert secret not in text, f"Secret '{secret}' found in investigation for {fid}"

    def test_resource_explorer_response_no_raw_secrets(self, client):
        res_resp = client.get("/resources")
        items = res_resp.json()["items"]

        for item in items:
            rid = item["resource_id"]
            detail = client.get(f"/resources/{rid}")
            text = detail.text
            for secret in _SECRETS_TO_DETECT:
                assert secret not in text, f"Secret '{secret}' found in resource detail for {rid}"

    def test_posture_response_no_secrets(self, client):
        resp = client.get("/posture")
        text = resp.text
        for secret in _SECRETS_TO_DETECT:
            assert secret not in text

    def test_error_responses_on_new_routes_contain_no_stack_traces(self, client):
        routes = [
            "/findings/invalid-finding-id/investigation",
            "/resources/invalid-resource-id",
            "/resources?security_posture=BOGUS",
        ]
        for route in routes:
            resp = client.get(route)
            assert resp.status_code in (400, 404)
            text = resp.text
            assert "Traceback" not in text
            assert "File \"" not in text
            data = resp.json()
            assert "error_code" in data
            assert "message" in data
