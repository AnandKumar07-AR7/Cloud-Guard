"""
CloudGuard — SQLAlchemy Repositories

Provides data access abstraction over SQLAlchemy models, mapping them to and from
domain Pydantic models.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.db_models import (
    AIAnalysisDBModel,
    FindingDBModel,
    RelationshipDBModel,
    ResourceDBModel,
    ResourceSnapshotDBModel,
    ScanDBModel,
)
from core.providers.base import CloudResource
from core.security.models import (
    AIAnalysis,
    ComplianceContext,
    Finding,
    FindingStatus,
    RemediationContext,
    ResourceRelationship,
    RiskContext,
    SecurityContext,
    Severity,
)
from services.scan_models import RiskSummary, ScanError, ScanRecord, ScanStatus

log = logging.getLogger(__name__)


class ScanRepository:
    """Repository for Scan lifecycle data."""

    def __init__(self, db: Session):
        self.db = db

    def save(self, record: ScanRecord) -> ScanRecord:
        """
        Persists a complete ScanRecord including its resources and findings.
        This behaves like a bounded context save.
        """
        # 1. UPSERT Scan
        scan_model = self.db.execute(
            select(ScanDBModel).where(ScanDBModel.scan_id == record.scan_id)
        ).scalar_one_or_none()

        if not scan_model:
            scan_model = ScanDBModel(scan_id=record.scan_id)
            self.db.add(scan_model)

        scan_model.correlation_id = record.correlation_id
        scan_model.provider = record.provider
        scan_model.account_id = record.account_id
        scan_model.mode = record.mode
        scan_model.scenario = record.scenario
        scan_model.regions = record.regions
        scan_model.status = record.status.value
        scan_model.started_at = record.started_at
        scan_model.completed_at = record.completed_at
        scan_model.resource_count = record.resource_count
        scan_model.finding_count = record.finding_count

        if record.risk_summary:
            rs = record.risk_summary
            scan_model.posture_score = rs.posture_score
            scan_model.risk_level = rs.risk_level
            scan_model.critical_count = rs.severity_counts.get(Severity.CRITICAL.value, 0)
            scan_model.high_count = rs.severity_counts.get(Severity.HIGH.value, 0)
            scan_model.medium_count = rs.severity_counts.get(Severity.MEDIUM.value, 0)
            scan_model.low_count = rs.severity_counts.get(Severity.LOW.value, 0)
            scan_model.info_count = rs.severity_counts.get(Severity.INFORMATIONAL.value, 0)
            scan_model.risk_summary = rs.model_dump()
        
        scan_model.errors = [e.model_dump() for e in record.errors]
        scan_model.error_message = record.error_message

        # We rely on flush for IDs but for simplicity we can commit at the service boundary.
        return record

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        scan_model = self.db.execute(
            select(ScanDBModel).where(ScanDBModel.scan_id == scan_id)
        ).scalar_one_or_none()
        if not scan_model:
            return None
        return self._to_domain(scan_model)

    def list(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[ScanStatus] = None,
        mode: Optional[str] = None,
    ) -> List[ScanRecord]:
        stmt = select(ScanDBModel).order_by(ScanDBModel.started_at.desc())
        if status:
            stmt = stmt.where(ScanDBModel.status == status.value)
        if mode:
            stmt = stmt.where(ScanDBModel.mode == mode)
        
        stmt = stmt.offset(offset).limit(limit)
        models = self.db.execute(stmt).scalars().all()
        return [self._to_domain(m) for m in models]

    def count(self, status: Optional[ScanStatus] = None) -> int:
        stmt = select(func.count(ScanDBModel.scan_id))
        if status:
            stmt = stmt.where(ScanDBModel.status == status.value)
        return self.db.execute(stmt).scalar_one()

    def delete(self, scan_id: str) -> bool:
        scan_model = self.db.execute(
            select(ScanDBModel).where(ScanDBModel.scan_id == scan_id)
        ).scalar_one_or_none()
        if scan_model:
            self.db.delete(scan_model)
            return True
        return False

    def _to_domain(self, model: ScanDBModel) -> ScanRecord:
        record = ScanRecord(
            scan_id=model.scan_id,
            correlation_id=model.correlation_id,
            provider=model.provider,
            account_id=model.account_id,
            mode=model.mode,
            scenario=model.scenario,
            regions=model.regions or [],
            status=ScanStatus(model.status.upper()) if model.status else ScanStatus.COMPLETED,
            started_at=model.started_at,
            completed_at=model.completed_at,
            resource_count=model.resource_count or 0,
            error_message=model.error_message,
        )
        if model.risk_summary:
            record.risk_summary = RiskSummary.model_validate(model.risk_summary)
        if model.errors:
            record.errors = [ScanError.model_validate(e) for e in model.errors]
        
        # Load findings and resources using the relationships is possible but we might want to lazy load
        # or load them using the other repositories to avoid complex mapping here.
        # However, ScanRecord assumes they are populated.
        finding_repo = FindingRepository(self.db)
        record.findings = finding_repo.get_for_scan(model.scan_id)
        
        resource_repo = ResourceRepository(self.db)
        record.resources = resource_repo.get_for_scan(model.scan_id)
        
        return record


class ResourceRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_snapshot(self, scan_id: str, resource: CloudResource) -> None:
        """
        Upserts the persistent ResourceDBModel and inserts a ResourceSnapshotDBModel.
        """
        # Persistent Resource
        r_model = self.db.execute(
            select(ResourceDBModel).where(ResourceDBModel.resource_id == resource.resource_id)
        ).scalar_one_or_none()
        
        if not r_model:
            r_model = ResourceDBModel(resource_id=resource.resource_id)
            self.db.add(r_model)
        
        r_model.provider = resource.provider
        r_model.account_id = resource.account_id
        r_model.region = resource.region
        r_model.service = resource.service
        r_model.resource_type = resource.resource_type
        r_model.name = resource.name
        r_model.tags = resource.tags
        
        # Snapshot for this scan
        snap = ResourceSnapshotDBModel(
            scan_id=scan_id,
            resource_id=resource.resource_id,
            configuration=resource.config
        )
        self.db.add(snap)

    def get_for_scan(self, scan_id: str) -> List[CloudResource]:
        stmt = select(ResourceDBModel, ResourceSnapshotDBModel).join(
            ResourceSnapshotDBModel, ResourceDBModel.resource_id == ResourceSnapshotDBModel.resource_id
        ).where(ResourceSnapshotDBModel.scan_id == scan_id)
        
        results = self.db.execute(stmt).all()
        resources = []
        for r_model, snap_model in results:
            resources.append(CloudResource(
                resource_id=r_model.resource_id,
                provider=r_model.provider,
                account_id=r_model.account_id,
                region=r_model.region,
                service=r_model.service,
                resource_type=r_model.resource_type,
                name=r_model.name,
                tags=r_model.tags,
                config=snap_model.configuration,
            ))
        return resources

    def get(self, resource_id: str, scan_id: Optional[str] = None) -> Optional[CloudResource]:
        """
        Get a resource. If scan_id is provided, gets that specific snapshot config,
        otherwise gets the latest snapshot config.
        """
        r_model = self.db.execute(
            select(ResourceDBModel).where(ResourceDBModel.resource_id == resource_id)
        ).scalar_one_or_none()
        if not r_model:
            return None
        
        stmt = select(ResourceSnapshotDBModel).where(ResourceSnapshotDBModel.resource_id == resource_id)
        if scan_id:
            stmt = stmt.where(ResourceSnapshotDBModel.scan_id == scan_id)
        stmt = stmt.order_by(ResourceSnapshotDBModel.observed_at.desc()).limit(1)
        
        snap_model = self.db.execute(stmt).scalar_one_or_none()
        config = snap_model.configuration if snap_model else {}
        
        return CloudResource(
            resource_id=r_model.resource_id,
            provider=r_model.provider,
            account_id=r_model.account_id,
            region=r_model.region,
            service=r_model.service,
            resource_type=r_model.resource_type,
            name=r_model.name,
            tags=r_model.tags,
            config=config,
        )


class FindingRepository:
    def __init__(self, db: Session):
        self.db = db

    def save(self, scan_id: str, finding: Finding) -> Finding:
        """
        Persists a finding, handling finding history via canonical_id.
        """
        # Find if this canonical_id exists from previous scans
        existing = self.db.execute(
            select(FindingDBModel)
            .where(FindingDBModel.canonical_id == finding.canonical_id)
            .order_by(FindingDBModel.last_detected_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        
        if existing:
            finding.first_detected_at = existing.first_detected_at
        
        f_model = FindingDBModel(
            finding_id=finding.finding_id,
            canonical_id=finding.canonical_id,
            scan_id=scan_id,
            resource_id=finding.resource_id,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            resource_type=finding.resource_type,
            service=finding.service,
            account_id=finding.account_id,
            region=finding.region,
            severity=finding.severity.value,
            risk_score=finding.risk_score,
            category=finding.category,
            status=finding.status.value,
            title=finding.title,
            description=finding.description,
            internet_exposed=finding.risk_context.internet_exposure_applied if finding.risk_context else False,
            evidence=finding.evidence.model_dump(),
            first_detected_at=finding.first_detected_at,
            last_detected_at=finding.last_detected_at,
        )
        if finding.security_context:
            f_model.security_context = finding.security_context.model_dump()
        if finding.risk_context:
            f_model.risk_context = finding.risk_context.model_dump()
        if finding.remediation_context:
            f_model.remediation_context = finding.remediation_context.model_dump()
        if finding.compliance_context:
            f_model.compliance_context = finding.compliance_context.model_dump()
            
        self.db.add(f_model)
        
        if finding.ai_analysis:
            ai_model = AIAnalysisDBModel(
                finding_id=finding.finding_id,
                ai_source=finding.ai_analysis.ai_source,
                executive_summary=finding.ai_analysis.executive_summary,
                technical_analysis=finding.ai_analysis.technical_analysis,
                business_impact=finding.ai_analysis.business_impact,
                attack_relevance=finding.ai_analysis.attack_relevance,
                recommended_action=finding.ai_analysis.recommended_action,
                confidence=finding.ai_analysis.confidence,
                limitations=finding.ai_analysis.limitations,
                observed_facts=finding.ai_analysis.observed_facts,
                ai_inferences=finding.ai_analysis.ai_inferences,
            )
            self.db.add(ai_model)
            
        return finding

    def get_for_scan(self, scan_id: str) -> List[Finding]:
        models = self.db.execute(
            select(FindingDBModel).where(FindingDBModel.scan_id == scan_id)
        ).scalars().all()
        return [self._to_domain(m) for m in models]

    def get(self, finding_id: str) -> Optional[Finding]:
        model = self.db.execute(
            select(FindingDBModel).where(
                (FindingDBModel.finding_id == finding_id) | 
                (FindingDBModel.canonical_id == finding_id)
            ).order_by(FindingDBModel.last_detected_at.desc()).limit(1)
        ).scalar_one_or_none()
        if not model:
            return None
        return self._to_domain(model)

    def list(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        service: Optional[str] = None,
        resource_type: Optional[str] = None,
        region: Optional[str] = None,
        rule_id: Optional[str] = None,
        internet_exposed: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Finding]:
        stmt = select(FindingDBModel)
        
        if scan_id:
            stmt = stmt.where(FindingDBModel.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingDBModel.severity == severity)
        if status:
            stmt = stmt.where(FindingDBModel.status == status)
        if service:
            stmt = stmt.where(FindingDBModel.service == service)
        if resource_type:
            stmt = stmt.where(FindingDBModel.resource_type == resource_type)
        if region:
            stmt = stmt.where(FindingDBModel.region == region)
        if rule_id:
            stmt = stmt.where(FindingDBModel.rule_id == rule_id)
        if internet_exposed is not None:
            stmt = stmt.where(FindingDBModel.internet_exposed == internet_exposed)
            
        stmt = stmt.order_by(FindingDBModel.risk_score.desc(), FindingDBModel.finding_id.asc())
        stmt = stmt.offset(offset).limit(limit)
        
        models = self.db.execute(stmt).scalars().all()
        return [self._to_domain(m) for m in models]

    def count(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        service: Optional[str] = None,
        resource_type: Optional[str] = None,
        region: Optional[str] = None,
        rule_id: Optional[str] = None,
        internet_exposed: Optional[bool] = None,
    ) -> int:
        from sqlalchemy import func
        stmt = select(func.count()).select_from(FindingDBModel)
        
        if scan_id:
            stmt = stmt.where(FindingDBModel.scan_id == scan_id)
        if severity:
            stmt = stmt.where(FindingDBModel.severity == severity)
        if status:
            stmt = stmt.where(FindingDBModel.status == status)
        if service:
            stmt = stmt.where(FindingDBModel.service == service)
        if resource_type:
            stmt = stmt.where(FindingDBModel.resource_type == resource_type)
        if region:
            stmt = stmt.where(FindingDBModel.region == region)
        if rule_id:
            stmt = stmt.where(FindingDBModel.rule_id == rule_id)
        if internet_exposed is not None:
            stmt = stmt.where(FindingDBModel.internet_exposed == internet_exposed)
            
        return self.db.execute(stmt).scalar() or 0
        
    def get_history(self, canonical_id: str) -> List[Finding]:
        models = self.db.execute(
            select(FindingDBModel)
            .where(FindingDBModel.canonical_id == canonical_id)
            .order_by(FindingDBModel.first_detected_at.desc())
        ).scalars().all()
        return [self._to_domain(m) for m in models]

    def _to_domain(self, model: FindingDBModel) -> Finding:
        ev = model.evidence or {}
        if not isinstance(ev, dict) or "rule_id" not in ev or "observed_value" not in ev:
            ev = {
                "rule_id": model.rule_id,
                "observed_value": ev.get("observed_value", "detected") if isinstance(ev, dict) else "detected",
                "expected_value": ev.get("expected_value", "secure") if isinstance(ev, dict) else "secure",
                "field_path": ev.get("field_path", "configuration") if isinstance(ev, dict) else "configuration",
            }
        finding = Finding(
            finding_id=model.finding_id,
            canonical_id=model.canonical_id,
            scan_id=model.scan_id,
            resource_id=model.resource_id,
            rule_id=model.rule_id,
            rule_version=model.rule_version or "1.0.0",
            resource_type=model.resource_type,
            service=model.service,
            account_id=model.account_id,
            region=model.region,
            severity=Severity(model.severity.lower()),
            risk_score=model.risk_score,
            category=model.category,
            status=FindingStatus(model.status),
            title=model.title,
            description=model.description,
            internet_exposed=model.internet_exposed,
            evidence=ev,
            first_detected_at=model.first_detected_at,
            last_detected_at=model.last_detected_at,
        )
        if model.security_context:
            finding.security_context = SecurityContext.model_validate(model.security_context)
        if model.risk_context:
            finding.risk_context = RiskContext.model_validate(model.risk_context)
        if model.remediation_context:
            finding.remediation_context = RemediationContext.model_validate(model.remediation_context)
        if model.compliance_context:
            finding.compliance_context = ComplianceContext.model_validate(model.compliance_context)
            
        # Optional AI Analysis
        if model.ai_analysis:
            aim = model.ai_analysis
            finding.ai_analysis = AIAnalysis(
                ai_source=aim.ai_source,
                executive_summary=aim.executive_summary,
                technical_analysis=aim.technical_analysis,
                business_impact=aim.business_impact,
                attack_relevance=aim.attack_relevance,
                recommended_action=aim.recommended_action,
                confidence=aim.confidence,
                limitations=aim.limitations,
                observed_facts=aim.observed_facts,
                ai_inferences=aim.ai_inferences,
            )
            
        return finding


class RelationshipRepository:
    def __init__(self, db: Session):
        self.db = db

    def save(self, scan_id: str, relationship: ResourceRelationship) -> None:
        model = RelationshipDBModel(
            scan_id=scan_id,
            source_resource_id=relationship.source_resource_id,
            target_resource_id=relationship.target_resource_id,
            target_resource_type=relationship.target_resource_type,
            target_service=relationship.target_service,
            relationship_type=relationship.relationship_type.value,
            evidence=relationship.evidence_source,
        )
        self.db.add(model)

    def get_for_scan(self, scan_id: str) -> List[ResourceRelationship]:
        models = self.db.execute(
            select(RelationshipDBModel).where(RelationshipDBModel.scan_id == scan_id)
        ).scalars().all()
        return [
            ResourceRelationship(
                source_resource_id=m.source_resource_id,
                target_resource_id=m.target_resource_id,
                target_resource_type=m.target_resource_type,
                target_service=m.target_service,
                relationship_type=m.relationship_type,
                evidence_source=str(m.evidence) if m.evidence else "",
            )
            for m in models
        ]

    def get_for_resource(self, scan_id: str, resource_id: str) -> List[ResourceRelationship]:
        models = self.db.execute(
            select(RelationshipDBModel)
            .where(RelationshipDBModel.scan_id == scan_id)
            .where(
                (RelationshipDBModel.source_resource_id == resource_id) |
                (RelationshipDBModel.target_resource_id == resource_id)
            )
        ).scalars().all()
        return [
            ResourceRelationship(
                source_resource_id=m.source_resource_id,
                target_resource_id=m.target_resource_id,
                target_resource_type=m.target_resource_type,
                target_service=m.target_service,
                relationship_type=m.relationship_type,
                evidence_source=str(m.evidence) if m.evidence else "",
            )
            for m in models
        ]
