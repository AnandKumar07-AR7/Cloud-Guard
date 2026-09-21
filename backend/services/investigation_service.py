"""
CloudGuard — Finding Investigation Service

Assembles comprehensive, evidence-grounded investigation context
for a specific security finding.

The Investigation Service connects:
  - The Finding itself (with deterministic canonical ID)
  - The Rule definition and metadata
  - The affected CloudResource configuration
  - The structured Evidence
  - The RiskContext (explainable breakdown)
  - The SecurityContext
  - Related CloudResources (discovered via configuration relationships)
  - Related Findings (on the same or related resources)
  - AI Analysis (structured AIAnalysis from Claude or template fallback)
  - Remediation Guidance & Criteria
  - Compliance References

Used by:
  - GET /findings/{finding_id}/investigation API endpoint
  - Obsidian Command Center Finding Detail view
  - AI Security Analyst
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.ai.service import AIService
from core.providers.base import CloudResource
from core.security.catalog import get_rule
from core.security.models import (
    AIAnalysis,
    ComplianceContext,
    Finding,
    RemediationContext,
    RiskContext,
    SecurityContext,
)
from core.utils.logging import get_logger
from services.repositories import FindingRepository, ResourceRepository, RelationshipRepository
from services.scan_models import ScanRecord
from services.scan_store import ScanStore, get_scan_store

log = get_logger(__name__)


class InvestigationContext(BaseModel):
    """
    Complete investigation package for a security finding.
    """
    finding: Finding
    rule_metadata: Optional[Dict[str, Any]] = None
    resource: Optional[Dict[str, Any]] = None
    evidence: Dict[str, Any]
    risk_context: Optional[RiskContext] = None
    security_context: Optional[SecurityContext] = None
    related_resources: List[Dict[str, Any]] = Field(default_factory=list)
    related_findings: List[Finding] = Field(default_factory=list)
    ai_analysis: Optional[AIAnalysis] = None
    remediation_context: Optional[RemediationContext] = None
    compliance_context: Optional[ComplianceContext] = None


class InvestigationService:
    """
    Coordinates gathering all context required to investigate a finding.
    """

    def __init__(
        self,
        db: Optional[Session] = None,
        scan_store: Optional[ScanStore] = None,
        ai_service: Optional[AIService] = None,
    ) -> None:
        self.db = db
        if self.db:
            self.finding_repo = FindingRepository(self.db)
            self.resource_repo = ResourceRepository(self.db)
            self.relationship_repo = RelationshipRepository(self.db)
            self._scan_store = None
        else:
            self._scan_store = scan_store or get_scan_store()
            
        self._ai_service = ai_service or AIService()

    def investigate(
        self,
        finding_id: str,
        scan_id: Optional[str] = None,
        enrich_with_ai: bool = False,
    ) -> Optional[InvestigationContext]:
        """
        Assemble investigation context for a finding by finding_id or canonical_id.
        """
        # Locate the finding
        finding = None
        if self.db:
            finding = self.finding_repo.get(finding_id)
        else:
            record, finding = self._find_finding_legacy(finding_id, scan_id)
            if finding:
                scan_id = record.scan_id

        if not finding:
            return None

        # Resolve scan_id if not explicitly provided
        effective_scan_id = scan_id or finding.scan_id

        # 1. Rule Metadata
        rule = get_rule(finding.rule_id)
        rule_meta = None
        if rule:
            meta = rule.metadata
            rule_meta = {
                "rule_id": meta.rule_id,
                "name": meta.name,
                "description": meta.description,
                "provider": meta.provider,
                "service": meta.service,
                "resource_type": meta.resource_type,
                "severity": meta.severity.value,
                "category": meta.category,
                "version": meta.version,
                "internet_exposure_risk": meta.internet_exposure_risk,
                "privilege_escalation_risk": meta.privilege_escalation_risk,
                "data_exposure_risk": meta.data_exposure_risk,
                "remediation_safety": meta.remediation_safety.value if hasattr(meta.remediation_safety, "value") else str(meta.remediation_safety),
                "remediation_available": meta.remediation_available,
                "remediation_guidance": meta.remediation_template,
                "remediation_template": meta.remediation_template,
                "compliance_mappings": meta.compliance_mappings,
                "references": meta.references,
                "enabled": meta.enabled,
            }

        # 2. Affected Resource
        resource_obj = None
        if self.db:
            resource_obj = self.resource_repo.get(finding.resource_id, scan_id=effective_scan_id)
        else:
            resource_obj = self._find_resource_legacy(record, finding.resource_id)

        resource_dict = None
        if resource_obj:
            from core.ai.masking import mask_config
            resource_dict = resource_obj.model_dump()
            resource_dict["config"] = mask_config(resource_obj.config)

        # 3. Evidence
        evidence_dict = finding.evidence.model_dump()

        # 4. Risk & Security Contexts
        risk_ctx = finding.risk_context
        sec_ctx = finding.security_context or finding.derive_security_context()

        # 5. Related Resources
        related_resources = []
        if self.db:
            rels = self.relationship_repo.get_for_resource(effective_scan_id, finding.resource_id)
            target_ids = {r.target_resource_id for r in rels}
            target_ids.update(finding.resource_relationships)
            for r_id in target_ids:
                r_obj = self.resource_repo.get(r_id, effective_scan_id)
                if r_obj:
                    related_resources.append({
                        "resource_id": r_obj.resource_id,
                        "resource_type": r_obj.resource_type,
                        "service": r_obj.service,
                        "region": r_obj.region,
                        "name": r_obj.name,
                        "tags": r_obj.tags,
                    })
        else:
            related_resources = self._resolve_related_resources_legacy(record, finding)

        # 6. Related Findings
        related_findings = []
        if self.db:
            scan_findings = self.finding_repo.get_for_scan(effective_scan_id)
            target_ids = {finding.resource_id}
            target_ids.update({r.target_resource_id for r in finding.relationships})
            target_ids.update(finding.resource_relationships)
            
            for f in scan_findings:
                if f.finding_id == finding.finding_id:
                    continue
                if f.resource_id in target_ids or any(rel.target_resource_id == finding.resource_id for rel in f.relationships):
                    related_findings.append(f)
        else:
            related_findings = self._find_related_findings_legacy(record, finding)

        # 7. AI Analysis
        ai_analysis = finding.ai_analysis
        if ai_analysis is None or enrich_with_ai:
            res_cfg = resource_obj.config if resource_obj else None
            ai_analysis = self._ai_service.analyze_finding(
                finding=finding,
                related_findings=related_findings,
                resource_config=res_cfg,
            )

        # 8. Remediation & Compliance
        rem_ctx = finding.remediation_context or RemediationContext(
            available=bool(finding.remediation_guidance),
            safety=finding.remediation_safety,
            recommended_action=finding.remediation_guidance or (rule.metadata.remediation_template if rule else ""),
            affected_fields=[finding.evidence.field_path] if finding.evidence.field_path else [],
            estimated_impact=f"Resolves {finding.severity.value} misconfiguration on {finding.resource_id}",
            verification_criteria=f"Verify {finding.evidence.field_path} equals {finding.evidence.expected_value}",
        )
        comp_ctx = finding.compliance_context or ComplianceContext.from_mappings(
            finding.compliance_mappings or (rule.metadata.compliance_mappings if rule else [])
        )

        return InvestigationContext(
            finding=finding,
            rule_metadata=rule_meta,
            resource=resource_dict,
            evidence=evidence_dict,
            risk_context=risk_ctx,
            security_context=sec_ctx,
            related_resources=related_resources,
            related_findings=related_findings,
            ai_analysis=ai_analysis,
            remediation_context=rem_ctx,
            compliance_context=comp_ctx,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Legacy in-memory helpers for backward compatibility
    # ──────────────────────────────────────────────────────────────────────────

    def _find_finding_legacy(self, finding_id: str, scan_id: Optional[str] = None):
        if scan_id:
            record = self._scan_store.get(scan_id)
            if record:
                for f in record.findings:
                    if str(f.finding_id) == str(finding_id) or str(f.canonical_id) == str(finding_id):
                        return record, f
            return None, None
        scans = self._scan_store.list(limit=50)
        for record in scans:
            for f in record.findings:
                if str(f.finding_id) == str(finding_id) or str(f.canonical_id) == str(finding_id):
                    return record, f
        return None, None

    def _find_resource_legacy(self, record: ScanRecord, resource_id: str) -> Optional[CloudResource]:
        for r in record.resources:
            if r.resource_id == resource_id:
                return r
        return None

    def _resolve_related_resources_legacy(self, record: ScanRecord, finding: Finding) -> List[Dict[str, Any]]:
        related_ids = set()
        for rel in finding.relationships:
            related_ids.add(rel.target_resource_id)
        for r_id in finding.resource_relationships:
            related_ids.add(r_id)

        results = []
        for r in record.resources:
            if r.resource_id in related_ids:
                results.append({
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type.value,
                    "service": r.service,
                    "region": r.region,
                    "name": r.display_name,
                    "tags": r.tags,
                })
        return results

    def _find_related_findings_legacy(self, record: ScanRecord, finding: Finding) -> List[Finding]:
        target_ids = {finding.resource_id}
        for rel in finding.relationships:
            target_ids.add(rel.target_resource_id)
        for r_id in finding.resource_relationships:
            target_ids.add(r_id)

        related = []
        for f in record.findings:
            if f.finding_id == finding.finding_id:
                continue
            if f.resource_id in target_ids or any(rel.target_resource_id == finding.resource_id for rel in f.relationships):
                related.append(f)
        return related


def get_investigation_service(db: Optional[Session] = None) -> InvestigationService:
    """Return InvestigationService, optionally injected with a DB session."""
    return InvestigationService(db=db)

