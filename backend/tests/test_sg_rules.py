"""
Tests for Security Group security rules.
"""
import pytest
from core.providers.demo.fixtures.sg_fixtures import (
    _web_servers_sg, _database_sg, _bastion_sg, _redis_sg
)
from core.security.models import Severity
from core.security.rules.sg_rules import (
    SGSSHOpenToInternet, SGRDPOpenToInternet,
    SGAllTrafficOpenToInternet, SGMySQLOpenToInternet,
    SGPostgresOpenToInternet, SGRedisOpenToInternet,
)


class TestSGSSHOpenToInternet:
    rule = SGSSHOpenToInternet()

    def test_fires_when_ssh_open(self):
        resource = _web_servers_sg()  # SSH to 0.0.0.0/0
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "SG-001"
        assert finding.severity == Severity.HIGH

    def test_no_fire_when_ssh_restricted(self):
        resource = _bastion_sg()  # SSH to 10.0.0.0/8
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_no_ssh_rule(self):
        resource = _database_sg()  # No SSH rule
        finding = self.rule.detect(resource)
        assert finding is None


class TestSGRDPOpenToInternet:
    rule = SGRDPOpenToInternet()

    def test_fires_when_rdp_open(self):
        resource = _redis_sg()  # has RDP to 0.0.0.0/0
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "SG-002"
        assert finding.severity == Severity.HIGH

    def test_no_fire_when_no_rdp(self):
        resource = _database_sg()
        finding = self.rule.detect(resource)
        assert finding is None


class TestSGAllTrafficOpenToInternet:
    rule = SGAllTrafficOpenToInternet()

    def test_fires_on_all_traffic_rule(self):
        from core.providers.base import CloudResource, ResourceType
        resource = CloudResource(
            resource_id="sg-all-open",
            resource_type=ResourceType.SECURITY_GROUP,
            provider="test", service="ec2",
            account_id="123", region="us-east-1",
            name="all-open",
            config={
                "inbound_rules": [
                    {"protocol": "-1", "from_port": 0, "to_port": 65535, "cidr": "0.0.0.0/0"}
                ]
            },
        )
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_no_fire_on_specific_rules(self):
        resource = _web_servers_sg()  # Specific ports, not -1
        finding = self.rule.detect(resource)
        assert finding is None


class TestSGMySQLOpenToInternet:
    rule = SGMySQLOpenToInternet()

    def test_fires_when_mysql_exposed(self):
        resource = _database_sg()  # MySQL 3306 open to 0.0.0.0/0
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "SG-004"
        assert finding.severity == Severity.CRITICAL

    def test_no_fire_when_mysql_not_exposed(self):
        resource = _bastion_sg()
        finding = self.rule.detect(resource)
        assert finding is None


class TestSGRedisOpenToInternet:
    rule = SGRedisOpenToInternet()

    def test_fires_when_redis_exposed(self):
        resource = _redis_sg()  # Redis 6379 open
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "SG-006"
        assert finding.severity == Severity.HIGH

    def test_no_fire_when_redis_not_exposed(self):
        resource = _bastion_sg()
        finding = self.rule.detect(resource)
        assert finding is None
