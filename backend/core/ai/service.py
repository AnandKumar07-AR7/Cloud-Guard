"""
CloudGuard — AI Service Abstraction (Phase 4)

Wraps the Anthropic Claude API (preserved from legacy) behind a clean
AIService interface. Falls back to template-based explanations when
no API key is configured.

AI is used for:
  - Explaining findings to developers
  - Summarizing findings for management
  - Providing remediation recommendations

AI is NOT used for:
  - Security detection (rules do that)
  - Risk scoring (the risk engine does that)
  - Inventing cloud state
  - Bypassing authorization

Response transparency:
  - ai_source = "claude" when Claude was used
  - ai_source = "template" when falling back to template
  The caller always knows which path was taken.

Phase 4 additions:
  - SecurityAnalystContextBuilder — structured context assembly with masking
  - AIService.analyze_finding() — returns structured AIAnalysis object
  - AIAnalysis distinguishes observed facts from AI inferences
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.ai.masking import mask_finding_evidence_for_ai, mask_env_vars
from core.security.models import AIAnalysis, Finding, RiskContext, SecurityContext, Severity
from core.utils.logging import get_logger

log = get_logger(__name__)

# Legacy AI explanation result schema (backward compat)
# Keys: developer_explanation, manager_summary, remediation_steps, ai_source
AIExplanation = Dict[str, str]


# ==============================================================================
# Security Analyst Context Builder
# ==============================================================================

class SecurityAnalystContextBuilder:
    """
    Assembles a structured, masked context payload for the AI Security Analyst.

    CRITICAL: This builder applies masking BEFORE any data is assembled
    for transmission to Claude. Sensitive values are never sent to the AI.

    The context includes:
      - Rule metadata
      - Finding summary
      - Evidence (masked)
      - Risk context
      - Security context
      - Related findings summary (if any)
    """

    def build(
        self,
        finding: Finding,
        related_findings: Optional[List[Finding]] = None,
        resource_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build the structured analyst context.

        Args:
            finding: The primary finding to analyze.
            related_findings: Other findings on the same/related resources.
            resource_config: Optional resource config (will be masked).

        Returns:
            Structured dict safe for transmission to Claude.
        """
        context = {
            "finding": self._build_finding_context(finding),
            "evidence": self._build_evidence_context(finding),
            "risk": self._build_risk_context(finding),
            "security": self._build_security_context(finding),
        }

        if related_findings:
            context["related_findings"] = self._build_related_context(related_findings)

        if resource_config:
            context["resource_config_sample"] = self._mask_config(resource_config)

        return context

    def _build_finding_context(self, finding: Finding) -> Dict[str, Any]:
        return {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value.upper(),
            "category": finding.category,
            "service": finding.service,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,  # Not sensitive — it's a resource name
            "region": finding.region,
            "status": finding.status.value,
        }

    def _build_evidence_context(self, finding: Finding) -> Dict[str, Any]:
        return {
            "field_path": finding.evidence.field_path,
            "observed_value": mask_finding_evidence_for_ai(finding.evidence.observed_value),
            "expected_value": mask_finding_evidence_for_ai(finding.evidence.expected_value),
            "source": finding.evidence.source,
            "summary": finding.evidence.to_summary(),
        }

    def _build_risk_context(self, finding: Finding) -> Dict[str, Any]:
        base = {
            "risk_score": finding.risk_score,
            "internet_exposed": finding.internet_exposed,
            "privilege_escalation_risk": finding.privilege_escalation_risk,
            "data_exposure_risk": finding.data_exposure_risk,
        }
        if finding.risk_context:
            base["rationale"] = finding.risk_context.rationale
            base["base_score"] = finding.risk_context.base_score
        return base

    def _build_security_context(self, finding: Finding) -> Dict[str, Any]:
        if finding.security_context:
            return finding.security_context.model_dump()
        return {}

    def _build_related_context(self, related: List[Finding]) -> List[Dict[str, Any]]:
        # Only include non-sensitive summary info from related findings
        return [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "resource_id": f.resource_id,
                "service": f.service,
            }
            for f in related[:10]  # Cap at 10 to prevent prompt bloat
        ]

    def _mask_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Mask any potentially sensitive config values before including."""
        masked = {}
        sensitive_keys = {
            "password", "secret", "key", "token", "credential",
            "auth", "private", "cert", "pass",
        }
        for k, v in config.items():
            if any(s in k.lower() for s in sensitive_keys):
                masked[k] = "[MASKED]"
            elif isinstance(v, dict):
                masked[k] = self._mask_config(v)
            else:
                masked[k] = v
        return masked


# ==============================================================================
# AI Service
# ==============================================================================

class AIService:
    """
    Service for AI-powered security analysis using Claude.

    Always falls back to template-based explanations when:
      - No Anthropic API key is configured.
      - The API call fails.
      - The response is malformed.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514") -> None:
        self._api_key = api_key
        self._model = model
        self._client = None
        self._context_builder = SecurityAnalystContextBuilder()

        if api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
                log.info("ai_service_initialized", model=model, mode="claude")
            except ImportError:
                log.warning("anthropic_sdk_not_installed", fallback="templates")
            except Exception as exc:
                log.warning("ai_service_init_failed", error=str(exc), fallback="templates")
        else:
            log.info("ai_service_initialized", mode="templates", reason="no_api_key")

    @property
    def is_ai_enabled(self) -> bool:
        return self._client is not None

    def explain_finding(self, finding: Finding, resource_config: Optional[Dict[str, Any]] = None) -> AIExplanation:
        """
        Generate a human-readable explanation for a security finding.
        Legacy method — preserved for backward compatibility.

        Args:
            finding: The finding to explain.
            resource_config: Optional additional config context (will be masked before sending).

        Returns:
            Dict with keys: developer_explanation, manager_summary, remediation_steps, ai_source.
        """
        if not self.is_ai_enabled:
            return self._template_explanation(finding)

        try:
            return self._claude_explanation(finding, resource_config)
        except Exception as exc:
            log.warning(
                "ai_explanation_failed",
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                error=str(exc),
                fallback="templates",
            )
            return self._template_explanation(finding)

    def analyze_finding(
        self,
        finding: Finding,
        related_findings: Optional[List[Finding]] = None,
        resource_config: Optional[Dict[str, Any]] = None,
    ) -> AIAnalysis:
        """
        Generate a structured AIAnalysis for a finding.

        Phase 4: This is the primary AI analyst method.
        Returns a fully structured AIAnalysis with observed_facts and ai_inferences
        clearly distinguished.

        Args:
            finding: The finding to analyze.
            related_findings: Related findings for context.
            resource_config: Optional resource config (will be masked).

        Returns:
            AIAnalysis object. Never raises — falls back to template.
        """
        if not self.is_ai_enabled:
            return self._template_analysis(finding, related_findings)

        try:
            return self._claude_analysis(finding, related_findings, resource_config)
        except Exception as exc:
            log.warning(
                "ai_analysis_failed",
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                error=str(exc),
                fallback="templates",
            )
            return self._template_analysis(finding, related_findings)

    def _claude_analysis(
        self,
        finding: Finding,
        related_findings: Optional[List[Finding]] = None,
        resource_config: Optional[Dict[str, Any]] = None,
    ) -> AIAnalysis:
        """Call Claude API and return structured AIAnalysis."""
        context = self._context_builder.build(finding, related_findings, resource_config)

        prompt = f"""You are a Cloud Security Analyst reviewing AWS security findings.

Analyze the following security finding and provide a structured assessment.

IMPORTANT: Clearly distinguish between:
1. "Observed facts" — what was actually measured in the configuration
2. "AI inferences" — your interpretation or extrapolation

FINDING CONTEXT:
{json.dumps(context, indent=2, default=str)}

Respond in this exact JSON format:
{{
  "executive_summary": "1-2 sentence business risk summary without technical jargon.",
  "technical_analysis": "Technical explanation: what the misconfiguration is, why it's a security concern.",
  "business_impact": "Business risk and potential consequences if exploited.",
  "attack_relevance": "What attack scenarios this enables. Only reference attack paths supported by the evidence above.",
  "recommended_action": "Step-by-step remediation instructions (numbered list).",
  "confidence": "high|medium|low — your confidence in this assessment given available evidence.",
  "limitations": "Any gaps in the analysis due to incomplete evidence.",
  "observed_facts": ["fact 1 from evidence", "fact 2 from evidence"],
  "ai_inferences": ["inference 1", "inference 2"]
}}"""

        message = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text
        log.debug(
            "claude_analysis_received",
            finding_id=finding.finding_id,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )

        # Parse JSON from response
        if "```json" in response_text:
            start = response_text.find("```json") + 7
            end = response_text.find("```", start)
            json_text = response_text[start:end].strip()
        elif "{" in response_text:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            json_text = response_text[start:end]
        else:
            json_text = response_text

        data = json.loads(json_text)

        return AIAnalysis(
            ai_source="claude",
            executive_summary=data.get("executive_summary", ""),
            technical_analysis=data.get("technical_analysis", ""),
            business_impact=data.get("business_impact", ""),
            attack_relevance=data.get("attack_relevance", ""),
            recommended_action=data.get("recommended_action", ""),
            confidence=data.get("confidence", "medium"),
            limitations=data.get("limitations", ""),
            observed_facts=data.get("observed_facts", []),
            ai_inferences=data.get("ai_inferences", []),
            generated_at=datetime.now(timezone.utc),
        )

    def _claude_explanation(
        self,
        finding: Finding,
        resource_config: Optional[Dict[str, Any]] = None,
    ) -> AIExplanation:
        """Call Claude API to generate explanation. Preserves legacy behavior."""
        # Mask sensitive values before sending to Claude
        safe_evidence = {
            "rule_id": finding.evidence.rule_id,
            "observed_value": mask_finding_evidence_for_ai(finding.evidence.observed_value),
            "expected_value": mask_finding_evidence_for_ai(finding.evidence.expected_value),
            "field_path": finding.evidence.field_path,
        }

        prompt = f"""You are a cloud security expert analyzing AWS misconfigurations.

Analyze this security finding and provide a comprehensive explanation:

**Finding Details:**
- Rule ID: {finding.rule_id}
- Title: {finding.title}
- Severity: {finding.severity.value.upper()}
- Resource Type: {finding.resource_type}
- Service: {finding.service}
- Region: {finding.region}

**Evidence:**
- Field: {finding.evidence.field_path}
- Observed: {safe_evidence['observed_value']}
- Expected: {safe_evidence['expected_value']}

**Risk Factors:**
- Internet Exposed: {finding.internet_exposed}
- Privilege Escalation Risk: {finding.privilege_escalation_risk}
- Data Exposure Risk: {finding.data_exposure_risk}
- Risk Score: {finding.risk_score}/100

Respond in this exact JSON format:
{{
  "developer_explanation": "Technical explanation (2-3 sentences). What the issue is, why it's a security concern, and potential attack vectors.",
  "manager_summary": "Executive summary (1-2 sentences). Business risk and impact without technical jargon.",
  "remediation_steps": "Step-by-step numbered instructions to fix this issue in the AWS console or via CLI."
}}"""

        message = self._client.messages.create(
            model=self._model,
            max_tokens=2048,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )

        response_text = message.content[0].text
        log.debug(
            "claude_response_received",
            finding_id=finding.finding_id,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )

        # Parse JSON from response
        if "```json" in response_text:
            start = response_text.find("```json") + 7
            end = response_text.find("```", start)
            json_text = response_text[start:end].strip()
        elif "{" in response_text:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            json_text = response_text[start:end]
        else:
            json_text = response_text

        explanation = json.loads(json_text)

        required = ["developer_explanation", "manager_summary", "remediation_steps"]
        if not all(k in explanation for k in required):
            raise ValueError(f"Claude response missing keys: {[k for k in required if k not in explanation]}")

        explanation["ai_source"] = "claude"
        return explanation

    def _template_explanation(self, finding: Finding) -> AIExplanation:
        """
        Generate a template-based explanation without AI.
        Preserved from legacy cloudguard-copilot-main behavior.
        """
        severity_str = finding.severity.value.upper()
        resource_type_display = finding.resource_type.replace("_", " ").title()

        developer_explanation = (
            f"The {resource_type_display} '{finding.resource_id}' has a {severity_str} "
            f"security misconfiguration: {finding.title}. "
            f"{finding.description}"
        )

        impact_phrases = {
            Severity.CRITICAL.value: "poses an immediate critical risk to the organization's security posture",
            Severity.HIGH.value: "poses a significant security risk that requires urgent attention",
            Severity.MEDIUM.value: "represents a security gap that should be addressed in the near term",
            Severity.LOW.value: "represents a minor security improvement opportunity",
        }
        impact = impact_phrases.get(finding.severity.value, "poses a security risk")

        manager_summary = (
            f"A {severity_str} severity issue was detected in {resource_type_display}. "
            f"This {impact} and should be reviewed by the security team."
        )

        remediation = finding.remediation_guidance or (
            f"Review the {resource_type_display} configuration and apply security best practices. "
            "Consult the AWS documentation for the specific service."
        )

        return {
            "developer_explanation": developer_explanation,
            "manager_summary": manager_summary,
            "remediation_steps": remediation,
            "ai_source": "template",
        }

    def _template_analysis(
        self,
        finding: Finding,
        related_findings: Optional[List[Finding]] = None,
    ) -> AIAnalysis:
        """
        Generate a structured AIAnalysis from templates without calling Claude.

        Uses actual finding data — evidence, severity, risk factors, resource info.
        Never generates generic placeholder text.
        """
        severity_str = finding.severity.value.upper()
        resource_type_display = finding.resource_type.replace("_", " ").title()

        # Observed facts come from evidence — not AI inference
        observed_facts = [
            f"Field '{finding.evidence.field_path}' observed value: {finding.evidence.observed_value!r}",
            f"Expected value: {finding.evidence.expected_value!r}",
            f"Rule '{finding.rule_id}' triggered on resource '{finding.resource_id}'",
        ]
        if finding.internet_exposed:
            observed_facts.append("Resource is reachable from the Internet based on security group configuration")
        if finding.privilege_escalation_risk:
            observed_facts.append("Finding involves privilege escalation risk based on IAM policy analysis")
        if finding.data_exposure_risk:
            observed_facts.append("Finding may expose data based on resource classification")

        # AI inferences (clearly labeled as interpretations)
        ai_inferences = [
            f"This is a {severity_str.lower()}-severity misconfiguration in {resource_type_display}",
            f"Risk score of {finding.risk_score}/100 indicates {'immediate action required' if finding.risk_score >= 80 else 'attention needed'}",
        ]
        if related_findings:
            svc_names = {f.service for f in related_findings}
            ai_inferences.append(
                f"Found {len(related_findings)} related finding(s) across services: {', '.join(sorted(svc_names))}"
            )

        # Build executive summary from actual finding data
        executive_summary = (
            f"A {severity_str} severity security issue was detected: {finding.title} "
            f"on {resource_type_display} '{finding.resource_id}' in region {finding.region}."
        )

        # Technical analysis from description + evidence
        technical_analysis = (
            f"{finding.description}\n\n"
            f"Evidence: {finding.evidence.to_summary()}"
        )

        # Business impact based on severity and risk factors
        impact_map = {
            "critical": "This is an immediate security threat that could lead to data breach, account compromise, or service disruption.",
            "high": "This security gap poses a significant risk that could be exploited by an attacker with moderate access.",
            "medium": "This misconfiguration creates a security weakness that should be addressed to reduce attack surface.",
            "low": "This is a security improvement opportunity that reduces operational risk when addressed.",
        }
        business_impact = impact_map.get(finding.severity.value, "This finding requires security review.")

        if finding.internet_exposed:
            business_impact += " The resource's internet exposure significantly increases exploitation risk."
        if finding.data_exposure_risk:
            business_impact += " Data handled by this resource may be at risk."

        # Attack relevance — only from evidence
        attack_parts = []
        if finding.internet_exposed:
            attack_parts.append("Internet-exposed resource increases attack surface for external threat actors")
        if finding.privilege_escalation_risk:
            attack_parts.append("Privilege escalation path could allow attacker to gain elevated permissions")
        if finding.data_exposure_risk:
            attack_parts.append("Data exposure risk could lead to unauthorized data access or exfiltration")
        attack_relevance = ". ".join(attack_parts) or "No specific attack path identified from available evidence."

        remediation = finding.remediation_guidance or (
            f"Review and update the {resource_type_display} '{finding.resource_id}' configuration. "
            f"The field '{finding.evidence.field_path}' should be set to '{finding.evidence.expected_value}'. "
            "Consult the AWS documentation for the specific service for step-by-step instructions."
        )

        # Confidence is high for template (the evidence is deterministic)
        confidence = "high"

        limitations = (
            "This analysis is template-generated based on deterministic rule evidence. "
            "AI-powered contextual analysis is available when Claude API is configured."
        )

        return AIAnalysis(
            ai_source="template",
            executive_summary=executive_summary,
            technical_analysis=technical_analysis,
            business_impact=business_impact,
            attack_relevance=attack_relevance,
            recommended_action=remediation,
            confidence=confidence,
            limitations=limitations,
            observed_facts=observed_facts,
            ai_inferences=ai_inferences,
            generated_at=datetime.now(timezone.utc),
        )
