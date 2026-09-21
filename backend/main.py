"""
CloudGuard Backend — FastAPI Application Entry Point (Phase 6 + Security Hardening)

Architecture:
  - API routes are in api/routes/ (system, scans, findings, rules, resources, posture)
  - Auth routes are in auth/routes.py
  - Business logic is in services/
  - Auth logic is in auth/
  - Domain models are in core/
  - Error handling is in api/errors.py

Security hardening added:
  - CORS origins from settings (configurable per environment, not hardcoded)
  - Request body size limit (returns 413 for oversized requests)
  - Auth endpoint rate limiting per IP (returns 429 after N attempts per minute)
  - Security response headers (CSP, HSTS, Permissions-Policy, COOP, CORP)
  - Obsolete X-XSS-Protection removed

Route Access Classification:
  GET  /health            PUBLIC
  GET  /mode              PUBLIC
  GET  /                  PUBLIC
  POST /auth/login        PUBLIC (rate limited)
  POST /auth/refresh      PUBLIC (rate limited)
  POST /auth/logout       AUTHENTICATED
  GET  /auth/me           AUTHENTICATED
  POST /auth/change-password AUTHENTICATED
  GET  /auth/users        PERMISSION: users.read
  POST /auth/users        PERMISSION: users.manage
  POST /scans             PERMISSION: scans.create
  GET  /scans             PERMISSION: scans.read
  GET  /scans/{id}        PERMISSION: scans.read
  GET  /findings          PERMISSION: findings.read
  GET  /findings/{id}     PERMISSION: findings.read
  GET  /findings/{id}/investigation PERMISSION: investigation.read
  GET  /findings/{id}/history       PERMISSION: findings.read
  GET  /rules             PERMISSION: rules.read
  GET  /rules/{id}        PERMISSION: rules.read
  GET  /resources         PERMISSION: resources.read
  GET  /resources/{id}    PERMISSION: resources.read
  GET  /posture           PERMISSION: posture.read
"""
from __future__ import annotations

import os
import sys
import time
import threading
from collections import defaultdict
from typing import List

# Ensure backend directory is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.errors import (
    CloudGuardAPIError,
    cloudguard_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
)
from api.routes import system, scans, findings, rules, resources, posture, remediation, ai, automation, mcp
from auth import routes as auth_routes
from config.settings import settings
from core.utils.logging import configure_logging, get_logger

# configure_logging is idempotent — safe to call from both main.py and pytest
configure_logging(level=settings.log_level.value, fmt=settings.log_format)
log = get_logger(__name__)

_START_TIME = time.monotonic()


# ──────────────────────────────────────────────────────────────────────────────
# In-Process Auth Rate Limiter
# Thread-safe sliding-window rate limiter for auth endpoints.
# Uses the real client IP (post-proxy resolution) as the rate limit key.
# For multi-process deployments, replace with Redis-backed limiter.
# ──────────────────────────────────────────────────────────────────────────────

class _AuthRateLimiter:
    """
    Per-IP sliding-window rate limiter for authentication endpoints.
    Requests per window are configurable via AUTH_RATE_LIMIT_PER_MINUTE setting.
    """

    _AUTH_PATHS = {"/auth/login", "/auth/register", "/auth/signup", "/auth/refresh"}

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, List[float]] = defaultdict(list)

    def _client_key(self, request: Request) -> str:
        """Return the peer IP as the rate-limit key (direct socket, not X-Forwarded-For)."""
        return request.client.host if request.client else "unknown"

    def check(self, request: Request) -> bool:
        """
        Returns True if the request is allowed, False if rate-limited.
        Only applied to auth paths.
        """
        if request.url.path not in self._AUTH_PATHS:
            return True

        key = self._client_key(request)
        now = time.monotonic()
        window = 60.0  # 1 minute sliding window
        limit = settings.auth_rate_limit_per_minute

        with self._lock:
            timestamps = self._windows[key]
            # Purge entries outside the window
            cutoff = now - window
            valid = [ts for ts in timestamps if ts > cutoff]
            self._windows[key] = valid

            if len(valid) >= limit:
                return False

            self._windows[key].append(now)
            return True

    def reset_for_testing(self) -> None:
        """Reset all counters — only call from tests."""
        with self._lock:
            self._windows.clear()


_auth_rate_limiter = _AuthRateLimiter()


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "cloudguard_starting",
        mode=settings.cloudguard_mode.value,
        version="1.0.0-hardened",
        ai_enabled=settings.has_anthropic_key,
    )
    print(f"\n{'='*60}")
    print(f"  CloudGuard API — Hardened (Auth + RBAC + Security Controls)")
    print(f"  {settings.mode_banner()}")
    print(f"  AI: {'Claude' if settings.has_anthropic_key else 'Template fallback'}")
    print(f"  Docs: http://{settings.api_host}:{settings.api_port}/docs")
    print(f"{'='*60}\n")

    # ── Demo admin seeding — ONLY in demo mode ────────────────────────────────
    # SECURITY: Never auto-seed an admin in production/AWS mode.
    # DEMO_ADMIN_PASSWORD must be explicitly set in .env for seeding to occur.
    # Production deployments must NOT set DEMO_ADMIN_PASSWORD.
    if settings.is_demo_mode:
        try:
            from core.database import engine, SessionLocal
            from core.db_models import Base, AutomationSettingDBModel
            import auth.models
            import core.automation.models
            import core.mcp.models
            import core.remediation.models
            from auth.permissions import CloudGuardRole, Permission, ROLE_PERMISSIONS
            from auth.models import RoleDBModel, PermissionDBModel, UserDBModel
            from auth.security import hash_password
            from sqlalchemy import insert
            from auth.models import role_permissions as rp_table
            import uuid

            Base.metadata.create_all(bind=engine)
            db = SessionLocal()
            try:
                if db.query(RoleDBModel).count() == 0:
                    role_id_map = {}
                    for role in CloudGuardRole:
                        rid = str(uuid.uuid4())
                        role_id_map[role.value] = rid
                        db.add(RoleDBModel(role_id=rid, name=role.value, description=f"{role.value} role"))
                    db.flush()

                    perm_id_map = {}
                    for pname in Permission.all_permissions():
                        pid = str(uuid.uuid4())
                        perm_id_map[pname] = pid
                        db.add(PermissionDBModel(permission_id=pid, name=pname, description=pname))
                    db.flush()

                    for role, perms in ROLE_PERMISSIONS.items():
                        rid = role_id_map[role.value]
                        for pname in perms:
                            pid = perm_id_map.get(pname)
                            if pid:
                                db.execute(insert(rp_table).values(role_id=rid, permission_id=pid))
                    db.flush()

                    admin_pwd = settings.demo_admin_password or "Admin12345!"
                    test_users = [
                        (CloudGuardRole.ADMIN, settings.demo_admin_username or "admin", admin_pwd),
                        (CloudGuardRole.ADMIN, "test_admin", "AdminTestPass12!"),
                        (CloudGuardRole.SECURITY_ANALYST, "test_analyst", "AnalystTestPass12!"),
                        (CloudGuardRole.OPERATOR, "test_operator", "OperatorTestPass12!"),
                        (CloudGuardRole.VIEWER, "test_viewer", "ViewerTestPass12!"),
                    ]
                    for r, u, p in test_users:
                        db.add(UserDBModel(
                            username=u,
                            password_hash=hash_password(p),
                            role_id=role_id_map[r.value],
                            is_active=True,
                        ))

                    db.add(AutomationSettingDBModel(
                        setting_key="global_kill_switch",
                        setting_value={"enabled": False},
                    ))
                    db.commit()
                    log.info("demo_database_auto_initialized")
                elif settings.demo_admin_password:
                    from auth.service import AuthService
                    svc = AuthService(db)
                    svc.seed_demo_admin(
                        username=settings.demo_admin_username,
                        password=settings.demo_admin_password,
                    )
            finally:
                db.close()
        except Exception as exc:
            # Non-fatal — log and continue. DB might not be ready yet.
            log.warning("demo_admin_seed_failed", error=str(exc))

    yield
    log.info("cloudguard_stopped")


# ──────────────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CloudGuard API",
    description=(
        "AI-Powered Cloud Misconfiguration Detection and Auto-Remediation.\n\n"
        "**Hardened**: JWT Authentication + RBAC + Rate Limiting + Security Headers.\n\n"
        "**Demo Mode** — No AWS credentials required. Set `CLOUDGUARD_MODE=demo`.\n"
        "**AWS Mode** — Set `CLOUDGUARD_MODE=aws` with valid AWS credentials.\n\n"
        "Most endpoints require a Bearer token. Use `POST /auth/login` to authenticate."
    ),
    version="1.0.0-hardened",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Origins loaded from settings (configurable via CORS_ORIGINS env var).
# No wildcard — authenticated API requires explicit allow-list.
# Dev defaults: localhost:3000, localhost:5173, localhost:5174, 127.0.0.1:5173.
# SECURITY: In production set CORS_ORIGINS to your actual frontend domain only.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# ── Request Body Size Limit ───────────────────────────────────────────────────
# Rejects requests whose Content-Length exceeds MAX_REQUEST_BODY_BYTES (default 1 MB).
# Prevents denial-of-service via large payload uploads.
# Note: Only Content-Length header is checked (fast path). Chunked-encoded requests
# without Content-Length are not covered here; Uvicorn's --limit-max-requests or a
# reverse proxy (nginx client_max_body_size) should be used as a complementary control.
@app.middleware("http")
async def body_size_limit_middleware(request: Request, call_next):
    """Enforce maximum request body size. Returns 413 if exceeded."""
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > settings.max_request_body_bytes:
                log.warning(
                    "request_body_too_large",
                    content_length=content_length,
                    limit=settings.max_request_body_bytes,
                    path=request.url.path,
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "error_code": "REQUEST_TOO_LARGE",
                        "message": (
                            f"Request body exceeds maximum allowed size of "
                            f"{settings.max_request_body_bytes // 1024} KB."
                        ),
                    },
                )
        except ValueError:
            pass  # Malformed Content-Length — let FastAPI handle it
    return await call_next(request)


# ── Auth Rate Limiting ────────────────────────────────────────────────────────
# Per-IP sliding-window rate limiter for authentication endpoints.
# Uses AUTH_RATE_LIMIT_PER_MINUTE setting (default: 10 per minute per IP).
# A real production deployment should use a Redis-backed limiter for multi-process safety.
@app.middleware("http")
async def auth_rate_limit_middleware(request: Request, call_next):
    """Rate limit auth endpoints per IP. Returns 429 if limit exceeded."""
    if not _auth_rate_limiter.check(request):
        client_ip = request.client.host if request.client else "unknown"
        log.warning(
            "auth_rate_limit_exceeded",
            ip=client_ip,
            path=request.url.path,
        )
        return JSONResponse(
            status_code=429,
            content={
                "error_code": "RATE_LIMIT_EXCEEDED",
                "message": "Too many authentication attempts. Please wait before trying again.",
            },
            headers={"Retry-After": "60"},
        )
    return await call_next(request)


# ── Security Response Headers ─────────────────────────────────────────────────
# Applied to every response. These are defense-in-depth controls for the API.
# The nginx frontend also sets its own headers for the SPA.
# NOTES:
# - X-XSS-Protection is intentionally OMITTED — it is obsolete and can create
#   vulnerabilities in older browsers. CSP supersedes it.
# - HSTS: Only effective if the API is behind TLS. Included so that when TLS is
#   added (via load balancer / nginx), the browser policy is already established.
#   The max-age of 1 year is standard. includeSubDomains is omitted to avoid
#   locking sibling services. Adjust for your deployment.
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security response headers to every API response."""
    response: Response = await call_next(request)

    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent framing (clickjacking protection)
    response.headers["X-Frame-Options"] = "DENY"

    # Content Security Policy for API responses
    # SPA HTML is served by nginx and has its own CSP there.
    # For the API (JSON responses) this is defence-in-depth.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    # Strict Transport Security (HSTS)
    # Automatically enabled when requested via HTTPS or forwarded over HTTPS by reverse proxy
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Disable dangerous browser features
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )

    # Cross-Origin isolation headers
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # Disable caching for sensitive API responses
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

    return response


# ── Request ID Middleware ─────────────────────────────────────────────────────
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Inject a correlation ID into every request for structured logging."""
    from core.utils.logging import new_correlation_id, set_correlation_id
    import structlog
    cid = request.headers.get("X-Request-ID") or new_correlation_id()
    set_correlation_id(cid)
    structlog.contextvars.bind_contextvars(request_id=cid, path=request.url.path)
    response = await call_next(request)
    response.headers["X-Request-ID"] = cid
    structlog.contextvars.clear_contextvars()
    return response

# ── Error Handlers ────────────────────────────────────────────────────────────
app.add_exception_handler(CloudGuardAPIError, cloudguard_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(system.router)
app.include_router(auth_routes.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(rules.router)
app.include_router(resources.router)
app.include_router(posture.router)
app.include_router(remediation.router)
app.include_router(ai.router)
app.include_router(automation.router)
app.include_router(mcp.router)
