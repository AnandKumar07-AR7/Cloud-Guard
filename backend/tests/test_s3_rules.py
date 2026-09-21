"""
Tests for S3 security rules.
Verifies that each rule fires (or does not fire) on specific fixtures.
"""
import pytest
from core.providers.demo.fixtures.s3_fixtures import (
    _public_data_lake, _website_assets, _audit_logs, _dev_scratch, _backup_store
)
from core.security.models import Severity
from core.security.rules.s3_rules import (
    S3PublicAccessBlockMissing,
    S3PublicACLGrant,
    S3WriteACLGrant,
    S3EncryptionMissing,
    S3VersioningDisabled,
    S3VersioningSuspended,
    S3MFADeleteDisabled,
)


class TestS3PublicAccessBlockMissing:
    rule = S3PublicAccessBlockMissing()

    def test_fires_on_empty_pab(self):
        resource = _public_data_lake()
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "S3-001"
        assert finding.severity == Severity.HIGH

    def test_no_fire_on_fully_enabled_pab(self):
        resource = _audit_logs()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_fires_on_partial_pab(self):
        resource = _website_assets()  # has BlockPublicAcls=False
        finding = self.rule.detect(resource)
        assert finding is not None  # partial PAB → fires
        assert "incomplete" in finding.title.lower() or "not fully" in finding.title.lower()


class TestS3PublicACLGrant:
    rule = S3PublicACLGrant()

    def test_fires_on_allusers_read_grant(self):
        resource = _website_assets()
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "S3-002"
        assert finding.severity == Severity.HIGH

    def test_no_fire_on_clean_bucket(self):
        resource = _audit_logs()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_on_empty_grants(self):
        resource = _public_data_lake()
        finding = self.rule.detect(resource)
        assert finding is None  # No ACL grants → no fire


class TestS3WriteACLGrant:
    rule = S3WriteACLGrant()

    def test_no_fire_on_read_only_grant(self):
        """A READ grant to AllUsers should NOT trigger the write rule."""
        resource = _website_assets()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_fires_on_write_grant(self):
        """A WRITE grant to AllUsers must fire."""
        from core.providers.base import CloudResource, ResourceType
        resource = CloudResource(
            resource_id="test-write-bucket",
            resource_type=ResourceType.S3_BUCKET,
            provider="test", service="s3",
            account_id="123", region="us-east-1",
            name="test-write",
            config={
                "acl": {
                    "grants": [
                        {
                            "grantee": {
                                "type": "Group",
                                "uri": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "permission": "WRITE",
                        }
                    ]
                }
            },
        )
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL


class TestS3EncryptionMissing:
    rule = S3EncryptionMissing()

    def test_fires_when_encryption_none(self):
        resource = _public_data_lake()
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "S3-004"
        assert finding.severity == Severity.MEDIUM

    def test_no_fire_when_encrypted(self):
        resource = _audit_logs()
        finding = self.rule.detect(resource)
        assert finding is None


class TestS3VersioningDisabled:
    rule = S3VersioningDisabled()

    def test_fires_when_disabled(self):
        resource = _dev_scratch()
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "S3-005"

    def test_no_fire_when_enabled(self):
        resource = _audit_logs()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_when_suspended(self):
        """Suspended versioning is handled by S3-006, not S3-005."""
        resource = _backup_store()  # status = Suspended
        finding = self.rule.detect(resource)
        # "Suspended" should not match "Disabled" check
        assert finding is None


class TestS3VersioningSuspended:
    rule = S3VersioningSuspended()

    def test_fires_when_suspended(self):
        resource = _backup_store()
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "S3-006"
        assert finding.severity == Severity.MEDIUM

    def test_no_fire_when_enabled(self):
        resource = _audit_logs()
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_when_disabled(self):
        resource = _dev_scratch()
        finding = self.rule.detect(resource)
        assert finding is None


class TestS3MFADeleteDisabled:
    rule = S3MFADeleteDisabled()

    def test_no_fire_when_mfa_delete_enabled(self):
        resource = _audit_logs()
        finding = self.rule.detect(resource)
        assert finding is None  # MFA delete = Enabled

    def test_fires_when_versioned_but_no_mfa_delete(self):
        resource = _website_assets()  # versioning=Enabled, mfa_delete=Disabled
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "S3-007"

    def test_no_fire_when_not_versioned(self):
        resource = _public_data_lake()  # versioning=Disabled
        finding = self.rule.detect(resource)
        assert finding is None  # Not versioned → different rule
