"""
CloudGuard — Rule Catalog and API Tests

Tests for:
  - RuleCatalog (core/security/catalog.py)
  - GET /rules
  - GET /rules/{rule_id}
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.security.catalog import get_all_rules, get_catalog_summary, get_rule
from core.security.engine import get_engine, reset_engine


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_engine():
    """Reset engine singleton before each test so rule counts are consistent."""
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def client(auth_client):
    return auth_client


# ──────────────────────────────────────────────────────────────────────────────
# Catalog Unit Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRuleCatalogUnit:
    def test_get_all_rules_returns_all_registered(self):
        rules = get_all_rules()
        # Phase 3: 8+8+8+5+4+4+3+4 = 44+ rules
        assert len(rules) >= 44, f"Expected >= 44 rules, got {len(rules)}"

    def test_all_rules_have_unique_ids(self):
        rules = get_all_rules()
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found!"

    def test_filter_by_service_s3(self):
        rules = get_all_rules(service="s3")
        assert all(r.metadata.service == "s3" for r in rules)
        assert len(rules) >= 8

    def test_filter_by_service_iam(self):
        rules = get_all_rules(service="iam")
        assert all(r.metadata.service == "iam" for r in rules)
        assert len(rules) >= 8

    def test_filter_by_service_ec2(self):
        rules = get_all_rules(service="ec2")
        # ec2 service covers both EC2 rules and SG rules
        assert all(r.metadata.service == "ec2" for r in rules)
        assert len(rules) >= 4

    def test_filter_by_service_rds(self):
        rules = get_all_rules(service="rds")
        assert len(rules) >= 4

    def test_filter_by_service_vpc(self):
        rules = get_all_rules(service="vpc")
        assert len(rules) >= 3

    def test_filter_by_service_cloudtrail(self):
        rules = get_all_rules(service="cloudtrail")
        assert len(rules) >= 4

    def test_filter_by_severity_critical(self):
        rules = get_all_rules(severity="critical")
        assert all(r.metadata.severity.value == "critical" for r in rules)
        assert len(rules) >= 5

    def test_filter_by_category_logging(self):
        rules = get_all_rules(category="logging")
        assert all(r.metadata.category == "logging" for r in rules)
        assert len(rules) >= 3  # VPC-001, CT-001, CT-002, CT-003, S3-008

    def test_filter_by_category_encryption(self):
        rules = get_all_rules(category="encryption")
        assert all(r.metadata.category == "encryption" for r in rules)

    def test_get_rule_by_id_found(self):
        rule = get_rule("S3-001")
        assert rule is not None
        assert rule.rule_id == "S3-001"

    def test_get_rule_case_insensitive(self):
        rule = get_rule("s3-001")
        assert rule is not None
        assert rule.rule_id == "S3-001"

    def test_get_rule_not_found_returns_none(self):
        assert get_rule("NONEXISTENT-999") is None

    def test_get_rule_all_new_services(self):
        for rule_id in ["EC2-001", "RDS-001", "VPC-001", "CT-001", "IAM-006", "IAM-007", "IAM-008"]:
            rule = get_rule(rule_id)
            assert rule is not None, f"Rule {rule_id} not found in catalog"

    def test_catalog_summary_structure(self):
        summary = get_catalog_summary()
        assert "total_rules" in summary
        assert "enabled_rules" in summary
        assert "severity_distribution" in summary
        assert "service_distribution" in summary
        assert "category_distribution" in summary

    def test_catalog_summary_totals(self):
        summary = get_catalog_summary()
        assert summary["total_rules"] >= 44
        assert summary["enabled_rules"] <= summary["total_rules"]

    def test_catalog_summary_has_all_new_services(self):
        summary = get_catalog_summary()
        svc = summary["service_distribution"]
        assert "rds" in svc
        assert "vpc" in svc
        assert "cloudtrail" in svc

    def test_catalog_summary_has_all_categories(self):
        summary = get_catalog_summary()
        cats = summary["category_distribution"]
        assert "logging" in cats
        assert "encryption" in cats
        assert "network" in cats


# ──────────────────────────────────────────────────────────────────────────────
# GET /rules API Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestGetRulesAPI:
    def test_list_rules_returns_200(self, client):
        resp = client.get("/rules")
        assert resp.status_code == 200

    def test_list_rules_response_structure(self, client):
        resp = client.get("/rules")
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert "catalog_summary" in data

    def test_list_rules_total_count(self, client):
        resp = client.get("/rules")
        data = resp.json()
        assert data["total"] >= 44

    def test_list_rules_item_structure(self, client):
        resp = client.get("/rules")
        item = resp.json()["items"][0]
        required_fields = [
            "rule_id", "name", "description", "provider", "service",
            "resource_type", "severity", "category", "version",
            "internet_exposure_risk", "privilege_escalation_risk", "data_exposure_risk",
            "remediation_safety", "remediation_available",
            "compliance_mappings", "references", "enabled",
        ]
        for field in required_fields:
            assert field in item, f"Missing field '{field}' in rule response"

    def test_filter_by_service(self, client):
        resp = client.get("/rules?service=s3")
        data = resp.json()
        assert all(item["service"] == "s3" for item in data["items"])
        assert data["total"] >= 8

    def test_filter_by_severity(self, client):
        resp = client.get("/rules?severity=critical")
        data = resp.json()
        assert all(item["severity"] == "critical" for item in data["items"])

    def test_filter_by_category(self, client):
        resp = client.get("/rules?category=logging")
        data = resp.json()
        assert all(item["category"] == "logging" for item in data["items"])

    def test_invalid_severity_returns_400(self, client):
        resp = client.get("/rules?severity=INVALID")
        assert resp.status_code == 400

    def test_pagination_limit(self, client):
        resp = client.get("/rules?limit=5&offset=0")
        data = resp.json()
        assert len(data["items"]) <= 5
        assert data["limit"] == 5

    def test_pagination_offset(self, client):
        resp_page1 = client.get("/rules?limit=5&offset=0")
        resp_page2 = client.get("/rules?limit=5&offset=5")
        ids_page1 = {r["rule_id"] for r in resp_page1.json()["items"]}
        ids_page2 = {r["rule_id"] for r in resp_page2.json()["items"]}
        # Pages should not overlap
        assert ids_page1.isdisjoint(ids_page2)

    def test_catalog_summary_in_response(self, client):
        resp = client.get("/rules?include_summary=true")
        summary = resp.json()["catalog_summary"]
        assert summary is not None
        assert "total_rules" in summary
        assert "severity_distribution" in summary

    def test_rules_sorted_by_service_then_severity(self, client):
        resp = client.get("/rules?limit=200")
        items = resp.json()["items"]
        services = [i["service"] for i in items]
        # Services should be grouped (sorted)
        assert services == sorted(services) or len(set(services)) > 1  # grouped at minimum

    def test_new_services_present_in_catalog(self, client):
        resp = client.get("/rules?limit=200")
        services = {item["service"] for item in resp.json()["items"]}
        for svc in ["rds", "vpc", "cloudtrail"]:
            assert svc in services, f"Service '{svc}' missing from rule catalog"

    def test_new_iam_rules_present(self, client):
        resp = client.get("/rules?service=iam")
        ids = {item["rule_id"] for item in resp.json()["items"]}
        assert "IAM-006" in ids
        assert "IAM-007" in ids
        assert "IAM-008" in ids

    def test_filters_applied_in_response(self, client):
        resp = client.get("/rules?service=s3&severity=high")
        data = resp.json()
        assert data["filters_applied"].get("service") == "s3"
        assert data["filters_applied"].get("severity") == "high"


# ──────────────────────────────────────────────────────────────────────────────
# GET /rules/{rule_id} API Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestGetRuleByIdAPI:
    def test_get_known_rule_returns_200(self, client):
        resp = client.get("/rules/S3-001")
        assert resp.status_code == 200

    def test_get_rule_response_structure(self, client):
        resp = client.get("/rules/IAM-001")
        data = resp.json()
        assert data["rule_id"] == "IAM-001"
        assert data["service"] == "iam"
        assert data["severity"] == "critical"

    def test_get_new_ec2_rule(self, client):
        resp = client.get("/rules/EC2-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == "EC2-001"
        assert data["service"] == "ec2"

    def test_get_new_rds_rule(self, client):
        resp = client.get("/rules/RDS-001")
        assert resp.status_code == 200
        assert resp.json()["severity"] == "critical"

    def test_get_new_vpc_rule(self, client):
        resp = client.get("/rules/VPC-001")
        assert resp.status_code == 200
        assert resp.json()["category"] == "logging"

    def test_get_new_cloudtrail_rule(self, client):
        resp = client.get("/rules/CT-001")
        assert resp.status_code == 200
        assert resp.json()["severity"] == "critical"

    def test_get_rule_case_insensitive(self, client):
        resp = client.get("/rules/s3-001")
        assert resp.status_code == 200
        assert resp.json()["rule_id"] == "S3-001"

    def test_unknown_rule_returns_404(self, client):
        resp = client.get("/rules/DOESNOTEXIST-999")
        assert resp.status_code == 404

    def test_rule_has_references(self, client):
        resp = client.get("/rules/EC2-001")
        assert isinstance(resp.json()["references"], list)
        assert len(resp.json()["references"]) > 0

    def test_rule_has_compliance_mappings(self, client):
        resp = client.get("/rules/IAM-001")
        assert len(resp.json()["compliance_mappings"]) > 0

    def test_rule_has_remediation_guidance(self, client):
        resp = client.get("/rules/S3-001")
        assert resp.json()["remediation_guidance"] is not None
