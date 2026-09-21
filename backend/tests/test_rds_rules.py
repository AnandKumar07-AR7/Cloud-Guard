"""
CloudGuard — RDS Security Rule Tests

Tests for:
  RDS-001  Publicly Accessible
  RDS-002  Storage Encryption Disabled
  RDS-003  Backup Retention Insufficient
  RDS-004  Deletion Protection Disabled
"""
from __future__ import annotations

import pytest
from core.providers.base import CloudResource, ResourceType
from core.security.rules.rds_rules import (
    RDSBackupRetentionInsufficient,
    RDSDeletionProtectionDisabled,
    RDSEncryptionDisabled,
    RDSPubliclyAccessible,
    RDS_RULES,
)

_ACCOUNT = "123456789012"
_REGION = "us-east-1"


def _rds(resource_id: str, config: dict) -> CloudResource:
    return CloudResource(
        resource_id=resource_id,
        resource_type=ResourceType.RDS_INSTANCE,
        provider="demo",
        service="rds",
        account_id=_ACCOUNT,
        region=_REGION,
        name=resource_id,
        config=config,
    )


# ──────────────────────────────────────────────────────────────────────────────
# RDS-001 — Publicly Accessible
# ──────────────────────────────────────────────────────────────────────────────

class TestRDSPubliclyAccessible:
    rule = RDSPubliclyAccessible()

    def test_fires_when_publicly_accessible(self):
        r = _rds("db-001", {"publicly_accessible": True, "engine": "mysql"})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "RDS-001"

    def test_no_finding_when_not_accessible(self):
        r = _rds("db-002", {"publicly_accessible": False})
        assert self.rule.detect(r) is None

    def test_no_finding_when_key_missing(self):
        r = _rds("db-003", {})
        assert self.rule.detect(r) is None

    def test_severity_is_critical(self):
        r = _rds("db-004", {"publicly_accessible": True})
        assert self.rule.detect(r).severity.value == "critical"

    def test_internet_exposure_and_data_risk(self):
        r = _rds("db-005", {"publicly_accessible": True})
        f = self.rule.detect(r)
        assert f.internet_exposed is True
        assert f.data_exposure_risk is True

    def test_evidence_includes_engine(self):
        r = _rds("db-006", {"publicly_accessible": True, "engine": "postgres"})
        f = self.rule.detect(r)
        assert f.evidence.details.get("engine") == "postgres"

    def test_category_is_network(self):
        assert self.rule.metadata.category == "network"

    def test_only_applies_to_rds_instances(self):
        r_ok = _rds("db-007", {"publicly_accessible": True})
        r_bad = CloudResource(
            resource_id="i-ec2", resource_type=ResourceType.EC2_INSTANCE,
            provider="demo", service="ec2", account_id=_ACCOUNT,
            region=_REGION, name="i-ec2", config={},
        )
        assert self.rule.applies_to(r_ok) is True
        assert self.rule.applies_to(r_bad) is False


# ──────────────────────────────────────────────────────────────────────────────
# RDS-002 — Storage Encryption Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestRDSEncryptionDisabled:
    rule = RDSEncryptionDisabled()

    def test_fires_when_not_encrypted(self):
        r = _rds("db-enc-001", {"storage_encrypted": False, "engine": "mysql"})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "RDS-002"

    def test_fires_when_encrypted_missing(self):
        r = _rds("db-enc-002", {})
        assert self.rule.detect(r) is not None

    def test_no_finding_when_encrypted(self):
        r = _rds("db-enc-003", {"storage_encrypted": True})
        assert self.rule.detect(r) is None

    def test_severity_is_high(self):
        r = _rds("db-enc-004", {"storage_encrypted": False})
        assert self.rule.detect(r).severity.value == "high"

    def test_data_exposure_risk_set(self):
        r = _rds("db-enc-005", {"storage_encrypted": False})
        assert self.rule.detect(r).data_exposure_risk is True

    def test_category_is_encryption(self):
        assert self.rule.metadata.category == "encryption"


# ──────────────────────────────────────────────────────────────────────────────
# RDS-003 — Backup Retention Insufficient
# ──────────────────────────────────────────────────────────────────────────────

class TestRDSBackupRetentionInsufficient:
    rule = RDSBackupRetentionInsufficient()

    def test_fires_when_retention_too_short(self):
        for days in [0, 1, 3, 6]:
            r = _rds(f"db-bkp-{days}", {"backup_retention_period": days})
            f = self.rule.detect(r)
            assert f is not None, f"Expected finding for retention={days}"
            assert f.rule_id == "RDS-003"

    def test_no_finding_when_retention_sufficient(self):
        for days in [7, 14, 30]:
            r = _rds(f"db-bkp-ok-{days}", {"backup_retention_period": days})
            assert self.rule.detect(r) is None

    def test_no_finding_when_retention_missing(self):
        """Cannot determine retention — don't flag without evidence."""
        r = _rds("db-bkp-none", {})
        assert self.rule.detect(r) is None

    def test_evidence_shows_actual_retention(self):
        r = _rds("db-bkp-ev", {"backup_retention_period": 3})
        f = self.rule.detect(r)
        assert f.evidence.observed_value == 3

    def test_severity_is_medium(self):
        r = _rds("db-bkp-sev", {"backup_retention_period": 1})
        assert self.rule.detect(r).severity.value == "medium"

    def test_category_is_configuration(self):
        assert self.rule.metadata.category == "configuration"


# ──────────────────────────────────────────────────────────────────────────────
# RDS-004 — Deletion Protection Disabled
# ──────────────────────────────────────────────────────────────────────────────

class TestRDSDeletionProtectionDisabled:
    rule = RDSDeletionProtectionDisabled()

    def test_fires_when_deletion_protection_disabled(self):
        r = _rds("db-del-001", {"deletion_protection": False})
        f = self.rule.detect(r)
        assert f is not None
        assert f.rule_id == "RDS-004"

    def test_fires_when_deletion_protection_missing(self):
        r = _rds("db-del-002", {})
        assert self.rule.detect(r) is not None

    def test_no_finding_when_deletion_protection_enabled(self):
        r = _rds("db-del-003", {"deletion_protection": True})
        assert self.rule.detect(r) is None

    def test_severity_is_medium(self):
        r = _rds("db-del-004", {"deletion_protection": False})
        assert self.rule.detect(r).severity.value == "medium"

    def test_category_is_configuration(self):
        assert self.rule.metadata.category == "configuration"


# ──────────────────────────────────────────────────────────────────────────────
# RDS_RULES registry
# ──────────────────────────────────────────────────────────────────────────────

class TestRDSRulesRegistry:
    def test_registry_has_4_rules(self):
        assert len(RDS_RULES) == 4

    def test_all_have_unique_rule_ids(self):
        ids = [r.rule_id for r in RDS_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_rds_resource_type(self):
        for rule in RDS_RULES:
            assert rule.metadata.resource_type == "rds_instance"

    def test_all_rules_have_category(self):
        for rule in RDS_RULES:
            assert rule.metadata.category

    def test_all_rules_have_version(self):
        for rule in RDS_RULES:
            assert rule.metadata.version

    def test_rules_start_with_rds_prefix(self):
        for rule in RDS_RULES:
            assert rule.rule_id.startswith("RDS-")
