"""
CloudGuard Phase 4 Tests — Finding Identity and Deduplication

Tests for:
  - Deterministic canonical_id generation
  - Stability across multiple scans
  - Invariance under different scan IDs
  - Distinctness when rule_id, resource_id, account_id, or field_path varies
"""
from __future__ import annotations

import pytest
from core.security.models import Evidence, Finding, Severity, _compute_canonical_id


def _make_finding(
    rule_id: str = "S3-001",
    resource_id: str = "my-bucket",
    account_id: str = "123456789012",
    field_path: str = "config.public_access_block.BlockPublicAcls",
    finding_id: str = None,
) -> Finding:
    ev = Evidence(
        rule_id=rule_id,
        observed_value=False,
        expected_value=True,
        field_path=field_path,
        source="bucket configuration",
    )
    kwargs = {
        "rule_id": rule_id,
        "resource_id": resource_id,
        "resource_type": "s3_bucket",
        "service": "s3",
        "account_id": account_id,
        "region": "us-east-1",
        "severity": Severity.HIGH,
        "title": "S3 Public Access Block Not Fully Configured",
        "description": "Test description",
        "evidence": ev,
    }
    if finding_id:
        kwargs["finding_id"] = finding_id
    return Finding(**kwargs)


class TestFindingIdentity:
    def test_canonical_id_is_deterministic(self):
        f1 = _make_finding()
        f2 = _make_finding()
        # Even with different random finding_id UUIDs, canonical_id must be identical
        assert f1.finding_id != f2.finding_id
        assert f1.canonical_id == f2.canonical_id

    def test_canonical_id_is_sha256_hex(self):
        f = _make_finding()
        assert len(f.canonical_id) == 32
        assert all(c in "0123456789abcdef" for c in f.canonical_id)

    def test_canonical_id_changes_with_rule_id(self):
        f1 = _make_finding(rule_id="S3-001")
        f2 = _make_finding(rule_id="S3-002")
        assert f1.canonical_id != f2.canonical_id

    def test_canonical_id_changes_with_resource_id(self):
        f1 = _make_finding(resource_id="bucket-a")
        f2 = _make_finding(resource_id="bucket-b")
        assert f1.canonical_id != f2.canonical_id

    def test_canonical_id_changes_with_account_id(self):
        f1 = _make_finding(account_id="111111111111")
        f2 = _make_finding(account_id="222222222222")
        assert f1.canonical_id != f2.canonical_id

    def test_canonical_id_changes_with_field_path(self):
        f1 = _make_finding(field_path="config.pab.BlockPublicAcls")
        f2 = _make_finding(field_path="config.pab.BlockPublicPolicy")
        assert f1.canonical_id != f2.canonical_id

    def test_canonical_id_helper_function(self):
        cid1 = _compute_canonical_id("IAM-001", "role-admin", "123456789012", "policies.statement.action")
        cid2 = _compute_canonical_id("IAM-001", "role-admin", "123456789012", "policies.statement.action")
        assert cid1 == cid2
        assert len(cid1) == 32

    def test_scan_id_does_not_affect_canonical_id(self):
        f1 = _make_finding()
        f1 = f1.model_copy(update={"scan_id": "scan-1111"})
        f2 = _make_finding()
        f2 = f2.model_copy(update={"scan_id": "scan-2222"})
        assert f1.canonical_id == f2.canonical_id
