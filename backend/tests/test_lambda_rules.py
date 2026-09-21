"""
Tests for Lambda security rules.
"""
import pytest
from core.providers.demo.fixtures.lambda_fixtures import (
    _api_handler, _data_processor, _scheduler
)
from core.security.models import Severity
from core.security.rules.lambda_rules import (
    LambdaPublicResourcePolicy, LambdaSecretsInEnvironment,
    LambdaDeprecatedRuntime, LambdaAdminExecutionRole, LambdaTracingDisabled,
)


class TestLambdaPublicResourcePolicy:
    rule = LambdaPublicResourcePolicy()

    def test_fires_on_public_resource_policy(self):
        resource = _data_processor()  # Principal: "*"
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "LAM-001"
        assert finding.severity == Severity.CRITICAL

    def test_no_fire_when_no_resource_policy(self):
        resource = _api_handler()  # resource_policy = None
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_on_clean_function(self):
        resource = _scheduler()
        finding = self.rule.detect(resource)
        assert finding is None


class TestLambdaSecretsInEnvironment:
    rule = LambdaSecretsInEnvironment()

    def test_fires_on_password_and_api_key_vars(self):
        resource = _api_handler()  # has DATABASE_PASSWORD and API_KEY
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "LAM-002"
        assert finding.severity == Severity.HIGH
        assert "DATABASE_PASSWORD" in str(finding.evidence.observed_value)

    def test_no_fire_on_safe_env_vars(self):
        resource = _scheduler()  # only LOG_LEVEL, TARGET_BUCKET
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_on_empty_env(self):
        from core.providers.base import CloudResource, ResourceType
        resource = CloudResource(
            resource_id="test-fn",
            resource_type=ResourceType.LAMBDA_FUNCTION,
            provider="test", service="lambda",
            account_id="123", region="us-east-1",
            name="test-fn",
            config={"environment_variables": {}},
        )
        finding = self.rule.detect(resource)
        assert finding is None


class TestLambdaDeprecatedRuntime:
    rule = LambdaDeprecatedRuntime()

    def test_fires_on_python38(self):
        resource = _api_handler()  # python3.8
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "LAM-003"
        assert finding.severity == Severity.HIGH
        assert "python3.8" in finding.title

    def test_no_fire_on_supported_runtime(self):
        resource = _data_processor()  # python3.12
        finding = self.rule.detect(resource)
        assert finding is None

    def test_fires_on_nodejs12x(self):
        from core.providers.base import CloudResource, ResourceType
        resource = CloudResource(
            resource_id="old-node",
            resource_type=ResourceType.LAMBDA_FUNCTION,
            provider="test", service="lambda",
            account_id="123", region="us-east-1",
            name="old-node",
            config={"runtime": "nodejs12.x"},
        )
        finding = self.rule.detect(resource)
        assert finding is not None


class TestLambdaAdminExecutionRole:
    rule = LambdaAdminExecutionRole()

    def test_fires_on_admin_role(self):
        resource = _data_processor()  # AdministratorAccess policy
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "LAM-004"
        assert finding.severity == Severity.CRITICAL

    def test_no_fire_on_readonly_role(self):
        resource = _scheduler()  # ReadOnlyAccess policy
        finding = self.rule.detect(resource)
        assert finding is None


class TestLambdaTracingDisabled:
    rule = LambdaTracingDisabled()

    def test_fires_when_passthrough(self):
        resource = _api_handler()  # tracing_mode = PassThrough
        finding = self.rule.detect(resource)
        assert finding is not None
        assert finding.rule_id == "LAM-005"

    def test_no_fire_when_active(self):
        resource = _data_processor()  # tracing_mode = Active
        finding = self.rule.detect(resource)
        assert finding is None

    def test_no_fire_on_clean_function(self):
        resource = _scheduler()  # tracing_mode = Active
        finding = self.rule.detect(resource)
        assert finding is None
