"""
CloudGuard Backend — Application Settings

Driven by environment variables (via .env file or system env).
Uses Pydantic Settings for validation and type coercion.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default allowed origins for development and HTTPS deployment. Override via CORS_ORIGINS env var in production.
_DEFAULT_CORS_ORIGINS = [
    "https://localhost",
    "https://localhost:3000",
    "https://localhost:5173",
    "https://localhost:8443",
    "https://127.0.0.1",
    "https://127.0.0.1:3000",
    "https://127.0.0.1:5173",
    "https://127.0.0.1:8443",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
]


class CloudGuardMode(str, Enum):
    """Operating mode for CloudGuard."""
    DEMO = "demo"
    AWS = "aws"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """
    CloudGuard application settings.

    All values can be set via environment variables or .env file.
    Environment variable names are uppercased versions of field names.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Mode ──────────────────────────────────────────────────────────────────
    cloudguard_mode: CloudGuardMode = Field(
        default=CloudGuardMode.DEMO,
        description="Operating mode: 'demo' (no AWS needed) or 'aws' (real AWS).",
    )

    # ── API ───────────────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_debug: bool = Field(default=False)
    secret_key: str = Field(default="CHANGE-ME-IN-PRODUCTION")

    # ── Auth / JWT (Phase 6) ──────────────────────────────────────────────────
    # JWT_SECRET_KEY must be set to a strong random secret in production.
    # The value "CHANGE-ME-BEFORE-PRODUCTION" is detected at runtime and will
    # cause startup to fail unless PYTEST_CURRENT_TEST is set (i.e., only during
    # automated test runs). Never hardcode a real secret here.
    jwt_secret_key: Optional[str] = Field(
        default="CHANGE-ME-BEFORE-PRODUCTION",
        description="JWT signing secret. MUST be set via JWT_SECRET_KEY env var in production.",
    )
    jwt_algorithm: str = Field(default="HS256")
    jwt_issuer: str = Field(
        default="cloudguard",
        description="JWT 'iss' claim. Set to unique service identifier.",
    )
    jwt_audience: str = Field(
        default="cloudguard-api",
        description="JWT 'aud' claim. Must be validated on every decode.",
    )
    access_token_expire_minutes: int = Field(default=30)
    refresh_token_expire_days: int = Field(default=7)

    # ── Demo Admin (Phase 6) ──────────────────────────────────────────────────
    # These are only used when CLOUDGUARD_MODE=demo.
    # Never auto-seed in AWS/production mode.
    # Never hardcode real credentials here; configure via .env for development.
    demo_admin_username: str = Field(default="admin")
    demo_admin_password: Optional[str] = Field(
        default=None,
        description="Demo admin password. Only used in CLOUDGUARD_MODE=demo.",
    )

    # ── AWS ───────────────────────────────────────────────────────────────────
    aws_access_key_id: Optional[str] = Field(default=None)
    aws_secret_access_key: Optional[str] = Field(default=None)
    aws_default_region: str = Field(default="us-east-1")
    aws_scan_regions: str = Field(
        default="",
        description="Comma-separated list of AWS regions to scan. Empty = default region only.",
    )
    aws_profile: Optional[str] = Field(default=None)

    # ── AI (Phase 8) ──────────────────────────────────────────────────────────
    ai_provider: str = Field(default="demo", description="AI provider: 'demo' or 'anthropic'")
    anthropic_api_key: Optional[str] = Field(default=None)
    anthropic_model: str = Field(default="claude-sonnet-4-20250514")
    anthropic_max_tokens: int = Field(default=2048)

    # Server-side limits
    max_ai_context_bytes: int = Field(default=32768, description="Max prompt context size in bytes")
    max_ai_tool_output_bytes: int = Field(default=8192, description="Max tool output size in bytes")
    max_ai_recommendation_length: int = Field(default=4096, description="Max length of recommendation text")
    max_ai_tool_calls: int = Field(default=5, description="Max tool calls per AI run")
    max_ai_analysis_duration_seconds: int = Field(default=15, description="Max analysis duration in seconds")
    max_ai_runs_per_request: int = Field(default=1, description="Max runs created per request")

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: str) -> str:
        val = (v or "").strip().lower()
        if val not in ("demo", "anthropic"):
            raise ValueError(f"Invalid AI provider '{v}'. Only 'demo' and 'anthropic' are allowed.")
        return val

    # ── CORS (configurable per environment) ─────────────────────────────────
    cors_origins: Union[List[str], str] = Field(
        default=_DEFAULT_CORS_ORIGINS,
        description="Allowed CORS origins. Set CORS_ORIGINS as comma-separated list in env.",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v) -> List[str]:
        """Accept comma-separated string from env var or a list directly. Prohibits wildcard '*'."""
        if isinstance(v, str):
            origins = [o.strip() for o in v.split(",") if o.strip()]
        elif isinstance(v, list):
            origins = [str(o).strip() for o in v if str(o).strip()]
        else:
            return v
        if "*" in origins:
            raise ValueError("Wildcard CORS origin '*' is strictly prohibited for authenticated API security.")
        return origins

    # ── Trusted Proxies (IP spoofing prevention) ──────────────────────────────
    trusted_proxy_ips: Union[List[str], str] = Field(
        default=[],
        description=(
            "IP addresses/CIDRs of trusted reverse proxies. "
            "X-Forwarded-For is only trusted from these IPs. "
            "Set as comma-separated list: TRUSTED_PROXY_IPS=10.0.0.1,172.16.0.0/12"
        ),
    )

    @field_validator("trusted_proxy_ips", mode="before")
    @classmethod
    def parse_trusted_proxy_ips(cls, v) -> List[str]:
        if isinstance(v, str):
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        return v

    # ── Request Security ──────────────────────────────────────────────────────
    max_request_body_bytes: int = Field(
        default=1_048_576,  # 1 MB
        description="Maximum allowed request body size in bytes. Requests exceeding this return 413.",
    )
    auth_rate_limit_per_minute: int = Field(
        default=10,
        description="Maximum login/register/refresh attempts per IP per minute.",
    )

    # ── Database (Phase 5) ────────────────────────────────────────────────────
    database_url: Optional[str] = Field(default=None)

    # ── Database Connection Pool ─────────────────────────────────────────────
    db_pool_size: int = Field(default=10, description="SQLAlchemy connection pool size.")
    db_max_overflow: int = Field(default=20, description="Max connections above pool_size.")
    db_pool_timeout: int = Field(default=30, description="Seconds to wait for a connection.")
    db_pool_recycle: int = Field(default=1800, description="Recycle connections after N seconds.")
    db_statement_timeout_ms: int = Field(
        default=30_000,
        description="PostgreSQL statement timeout in milliseconds. 0=disabled.",
    )
    db_idle_in_transaction_timeout_ms: int = Field(
        default=60_000,
        description="PostgreSQL idle-in-transaction timeout in milliseconds.",
    )
    db_lock_timeout_ms: int = Field(
        default=10_000,
        description="PostgreSQL lock acquisition timeout in milliseconds.",
    )

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_format: str = Field(default="json")

    # ── Derived properties ────────────────────────────────────────────────────
    @property
    def is_demo_mode(self) -> bool:
        """True when running in demo mode (no real AWS)."""
        return self.cloudguard_mode == CloudGuardMode.DEMO

    @property
    def is_aws_mode(self) -> bool:
        """True when running against real AWS."""
        return self.cloudguard_mode == CloudGuardMode.AWS

    @property
    def scan_regions(self) -> List[str]:
        """Parsed list of AWS regions to scan."""
        if not self.aws_scan_regions:
            return [self.aws_default_region]
        return [r.strip() for r in self.aws_scan_regions.split(",") if r.strip()]

    @property
    def has_anthropic_key(self) -> bool:
        """True when an Anthropic API key is configured."""
        return bool(self.anthropic_api_key)

    @property
    def has_aws_credentials(self) -> bool:
        """True when explicit AWS access key credentials are configured."""
        return bool(self.aws_access_key_id and self.aws_secret_access_key)

    def mode_banner(self) -> str:
        """Human-readable mode banner for startup logs."""
        if self.is_demo_mode:
            return "[DEMO] DEMO MODE - No AWS credentials required. Using mock cloud data."
        return f"[AWS]  AWS LIVE MODE - Scanning real AWS (region: {self.aws_default_region})"


# Singleton settings instance
settings = Settings()
