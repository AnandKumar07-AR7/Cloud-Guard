"""
CloudGuard — AI Agent Orchestrator (Phase 8)

Coordinates bounded AI security analysis runs for findings.
Enforces the fundamental execution boundary:
The AI is strictly advisory and NEVER has direct execution capabilities.
Enforces step limits, timeouts, duplicate call prevention, strict Pydantic output validation,
strategy allowlist verification, and transaction safety.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import select
from pydantic import ValidationError

from core.ai.context import SYSTEM_PROMPT, PromptContextBuilder
from core.ai.schemas import AIRecommendationOutputSchema
from core.ai.tools.dispatcher import ServerToolDispatcher
from core.ai.tools.registry import READ_ONLY_TOOL_REGISTRY
from core.db_models import (
    AIAgentRunDBModel,
    AIRecommendationDBModel,
    FindingDBModel,
)
from core.providers.ai.base import AIProvider, AIProviderError
from core.providers.ai import get_ai_provider
from core.remediation.strategy import get_strategy
from config.settings import settings
from core.utils.logging import get_logger

log = get_logger(__name__)


class AIAgentOrchestrator:
    """
    Server-side orchestrator for an AI security analysis run.
    """

    def __init__(self, session: Session, provider: Optional[AIProvider] = None):
        self.session = session
        self.provider = provider or get_ai_provider()

    def run_analysis(
        self,
        finding_id: str,
        user_id: str,
    ) -> Tuple[AIAgentRunDBModel, Optional[AIRecommendationDBModel]]:
        """
        Executes a bounded, server-controlled AI analysis run for a finding.
        Returns the persistent run model and the validated recommendation (if successful).
        """
        # 1. Validate Finding Exists
        finding = self.session.scalar(
            select(FindingDBModel).where(FindingDBModel.finding_id == finding_id)
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found.")

        # 2. Initialize Run Record in PENDING state
        run_id = str(uuid.uuid4())
        start_time = time.monotonic()

        run = AIAgentRunDBModel(
            run_id=run_id,
            finding_id=finding_id,
            initiating_user_id=user_id,
            provider_type=self.provider.provider_type,
            model_name=self.provider.model_name,
            status="PENDING",
            tool_call_count=0,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(run)
        self.session.commit()

        # Transition to RUNNING
        run.status = "RUNNING"
        self.session.commit()

        dispatcher = ServerToolDispatcher(self.session, run_id=run_id)

        # 3. Assemble Initial Context
        user_prompt = PromptContextBuilder.build_initial_user_message(finding)
        messages: List[Dict[str, Any]] = [
            {"role": "user", "content": user_prompt}
        ]

        # Prepare tool descriptions for provider
        available_tools = [tool.to_dict() for tool in READ_ONLY_TOOL_REGISTRY.values()]

        recommendation_payload: Optional[Dict[str, Any]] = None
        executed_tool_calls: set[Tuple[str, str]] = set()

        max_calls = settings.max_ai_tool_calls
        max_duration = settings.max_ai_analysis_duration_seconds

        try:
            # 4. Multi-Step Server-Controlled Execution Loop
            while run.tool_call_count <= max_calls:
                # Check execution timeout
                elapsed = time.monotonic() - start_time
                if elapsed > max_duration:
                    log.warning("ai_analysis_timed_out", run_id=run_id, elapsed=elapsed)
                    run.status = "TIMED_OUT"
                    run.error_category = "analysis_timeout"
                    run.duration_ms = int(elapsed * 1000)
                    run.completed_at = datetime.now(timezone.utc)
                    self.session.commit()
                    return run, None

                # Call AI Provider
                response = self.provider.generate_response(
                    system_prompt=SYSTEM_PROMPT,
                    messages=messages,
                    available_tools=available_tools,
                )

                # Case A: Provider emitted tool request(s)
                if response.tool_requests:
                    for t_req in response.tool_requests:
                        if run.tool_call_count >= max_calls:
                            log.warning("max_tool_calls_exceeded", run_id=run_id, count=run.tool_call_count)
                            run.status = "FAILED"
                            run.error_category = "context_limit_exceeded"
                            run.duration_ms = int((time.monotonic() - start_time) * 1000)
                            run.completed_at = datetime.now(timezone.utc)
                            self.session.commit()
                            return run, None

                        # Check for duplicate call
                        serialized_args = json.dumps(t_req.arguments, sort_keys=True)
                        call_key = (t_req.tool_name, serialized_args)
                        if call_key in executed_tool_calls:
                            log.warning("duplicate_tool_call_detected", tool_name=t_req.tool_name, run_id=run_id)
                            # Record blocked duplicate event
                            dispatcher._record_event(
                                event_id=str(uuid.uuid4()),
                                tool_name=t_req.tool_name,
                                status="BLOCKED",
                                input_summary={"arguments": t_req.arguments},
                                output_summary={"error": "Duplicate tool invocation detected."},
                                error_category="tool_execution_failed",
                                duration_ms=0,
                            )
                            # Return duplicate error to AI context
                            messages.append({
                                "role": "tool",
                                "name": t_req.tool_name,
                                "content": json.dumps({"error": "Duplicate tool invocation detected. Do not repeat identical calls."}),
                            })
                            run.tool_call_count += 1
                            continue

                        executed_tool_calls.add(call_key)
                        run.tool_call_count += 1

                        success, tool_result, _ = dispatcher.execute_tool(t_req.tool_name, t_req.arguments)
                        messages.append({
                            "role": "tool",
                            "name": t_req.tool_name,
                            "content": json.dumps(tool_result),
                        })

                    # Next step in loop to let provider evaluate tool results
                    continue

                # Case B: Provider emitted recommendation
                if response.recommendation:
                    recommendation_payload = response.recommendation
                    break

                # If provider returned text without tool or recommendation
                if response.raw_text:
                    messages.append({"role": "assistant", "content": response.raw_text})
                    # Prompt provider once to emit structured output
                    messages.append({
                        "role": "user",
                        "content": "Please produce your final structured recommendation in valid JSON format matching the required schema.",
                    })
                    continue

                # No output produced
                break

            # 5. Output Validation
            if not recommendation_payload:
                log.warning("no_recommendation_emitted", run_id=run_id)
                run.status = "FAILED"
                run.error_category = "invalid_ai_output"
                run.duration_ms = int((time.monotonic() - start_time) * 1000)
                run.completed_at = datetime.now(timezone.utc)
                self.session.commit()
                return run, None

            # Validate via Pydantic schema (extra='forbid')
            try:
                validated_rec = AIRecommendationOutputSchema(**recommendation_payload)
            except ValidationError as val_err:
                log.warning("recommendation_schema_validation_failed", run_id=run_id, error=str(val_err))
                run.status = "FAILED"
                run.error_category = "invalid_ai_output"
                run.duration_ms = int((time.monotonic() - start_time) * 1000)
                run.completed_at = datetime.now(timezone.utc)
                self.session.commit()
                return run, None

            # 6. Re-validate Strategy Allowlist against Phase 7
            strat_id = validated_rec.recommended_strategy_id
            if strat_id:
                allowed_strategy = get_strategy(strat_id)
                if not allowed_strategy:
                    log.warning("unallowlisted_strategy_in_recommendation", strategy_id=strat_id, run_id=run_id)
                    run.status = "FAILED"
                    run.error_category = "invalid_ai_output"
                    run.duration_ms = int((time.monotonic() - start_time) * 1000)
                    run.completed_at = datetime.now(timezone.utc)
                    self.session.commit()
                    return run, None

            # 7. Persist Validated Recommendation
            rec_db = AIRecommendationDBModel(
                recommendation_id=str(uuid.uuid4()),
                run_id=run_id,
                finding_id=finding_id,
                recommended_strategy_id=validated_rec.recommended_strategy_id,
                analysis_summary=validated_rec.analysis_summary,
                risk_summary=validated_rec.risk_summary,
                recommendation_rationale=validated_rec.recommendation_rationale,
                expected_impact=validated_rec.expected_impact,
                confidence=validated_rec.confidence,
                requires_approval=True,  # Always requires human approval!
                created_at=datetime.now(timezone.utc),
            )
            self.session.add(rec_db)

            # 8. Mark Run Completed
            run.status = "COMPLETED"
            run.duration_ms = int((time.monotonic() - start_time) * 1000)
            run.completed_at = datetime.now(timezone.utc)
            self.session.commit()

            return run, rec_db

        except AIProviderError as p_err:
            log.warning("ai_provider_failure", error=str(p_err), category=p_err.error_category)
            run.status = "FAILED"
            run.error_category = p_err.error_category
            run.duration_ms = int((time.monotonic() - start_time) * 1000)
            run.completed_at = datetime.now(timezone.utc)
            self.session.commit()
            return run, None

        except Exception as exc:
            log.error("unexpected_orchestrator_failure", error=type(exc).__name__)
            self.session.rollback()
            # Safely record failed run in new transaction
            try:
                failed_run = self.session.scalar(
                    select(AIAgentRunDBModel).where(AIAgentRunDBModel.run_id == run_id)
                )
                if failed_run:
                    failed_run.status = "FAILED"
                    failed_run.error_category = "provider_error"
                    failed_run.completed_at = datetime.now(timezone.utc)
                    self.session.commit()
                    return failed_run, None
            except Exception:
                pass
            raise
