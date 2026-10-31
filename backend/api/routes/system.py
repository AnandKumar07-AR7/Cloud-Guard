"""
CloudGuard — System Routes

GET /health
GET /mode
GET /
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from api.schemas import HealthResponse, ModeResponse
from config.settings import settings
from core.providers.demo.provider import DemoProvider
from core.database import get_db

router = APIRouter(tags=["System"])

# Record startup time for uptime calculation
_START_TIME = time.monotonic()


@router.get("/", include_in_schema=False)
async def root():
    return {
        "service": "CloudGuard API",
        "version": "1.0.0-phase2",
        "mode": settings.cloudguard_mode.value,
        "docs": "/docs",
        "health": "/health",
    }


@router.get("/health", response_model=HealthResponse)
async def health_check(db=Depends(get_db)):
    """
    Application health check.

    Returns the operating status, mode, and AI availability.
    Also verifies database connectivity.
    """
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db_status = "available"
        app_status = "healthy"
    except Exception as exc:
        db_status = "unavailable"
        app_status = "degraded"

    ai_enabled = settings.has_anthropic_key or settings.has_gemini_key

    return HealthResponse(
        status=app_status,
        mode=settings.cloudguard_mode.value,
        version="1.0.0-phase2",
        timestamp=datetime.now(timezone.utc).isoformat(),
        ai_enabled=ai_enabled,
        uptime_seconds=round(time.monotonic() - _START_TIME, 1),
        database_status=db_status,
    )


@router.get("/mode", response_model=ModeResponse)
async def get_mode():
    """
    Get the current operating mode and capability summary.

    Accurately reflects runtime configuration.
    Never reports AWS Connected when running in Demo mode.
    """
    if settings.has_gemini_key:
        ai_source = "gemini"
    elif settings.has_anthropic_key:
        ai_source = "claude"
    else:
        ai_source = "template"

    ai_enabled = settings.has_anthropic_key or settings.has_gemini_key

    return ModeResponse(
        mode=settings.cloudguard_mode.value,
        is_demo=settings.is_demo_mode,
        is_aws=settings.is_aws_mode,
        ai_enabled=ai_enabled,
        ai_source=ai_source,
        aws_region=settings.aws_default_region if settings.is_aws_mode else None,
        available_scenarios=DemoProvider.available_scenarios() if settings.is_demo_mode else None,
        message=settings.mode_banner(),
    )


@router.get("/system/providers")
async def get_providers():
    """
    Get registered multi-cloud provider architectures and capability matrices.
    """
    from core.providers.registry import get_supported_providers
    return {"providers": [p.model_dump() for p in get_supported_providers()]}
