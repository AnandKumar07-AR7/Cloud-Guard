import sqlite3
import uuid
from core.database import SessionLocal
from services.remediation_service import RemediationService
from core.db_models import RemediationPlanDBModel, RemediationActionDBModel, RemediationAuditEventDBModel, RemediationExecutionDBModel

def setup_demo_remediations():
    db = SessionLocal()
    service = RemediationService()
    try:
        user_id = 'c6a458b8-5773-480c-b6d6-8f739a2137f9'
        
        # 1. Clean up old orphaned plans
        old_ids = ['168808b0-1fea-4251-be14-7d16f840ebb7', '2d596ec7-d8a4-4efd-ab9c-6ba61250d0f4']
        for oid in old_ids:
            db.query(RemediationAuditEventDBModel).filter(RemediationAuditEventDBModel.remediation_id == oid).delete()
            db.query(RemediationExecutionDBModel).filter(RemediationExecutionDBModel.remediation_id == oid).delete()
            db.query(RemediationActionDBModel).filter(RemediationActionDBModel.remediation_id == oid).delete()
            db.query(RemediationPlanDBModel).filter(RemediationPlanDBModel.remediation_id == oid).delete()
        db.commit()
        print("Cleaned up orphaned plans.")

        # 2. Reset SG-001 plan to DRAFT
        sg_plan = db.query(RemediationPlanDBModel).filter(RemediationPlanDBModel.remediation_id == 'aa903d1b-730a-4eb9-9339-8a9b4c91e7cb').first()
        if sg_plan:
            sg_plan.state = 'DRAFT'
            sg_plan.validation_result = None
            sg_plan.error_message = None
            db.commit()
            print("Reset SG-001 plan to DRAFT.")

        # 3. Create or Reset IAM-003 plan
        iam_finding_id = 'c408f125-600d-4c85-90e4-2b03d3e444fb'
        iam_plan = db.query(RemediationPlanDBModel).filter(RemediationPlanDBModel.finding_id == iam_finding_id).first()
        if not iam_plan:
            print("Creating remediation plan for IAM-003...")
            iam_plan_obj = service.create_plan(db, iam_finding_id, user_id)
            print("Created IAM-003 plan:", iam_plan_obj.remediation_id)
        else:
            iam_plan.state = 'DRAFT'
            iam_plan.validation_result = None
            iam_plan.error_message = None
            db.commit()
            print("Reset IAM-003 plan to DRAFT:", iam_plan.remediation_id)

        print("\nCURRENT PLANS IN DB:")
        for p in db.query(RemediationPlanDBModel).all():
            print(f"- Plan {p.remediation_id} | Rule: {p.rule_id} | Resource: {p.resource_id} | State: {p.state}")

    finally:
        db.close()

if __name__ == '__main__':
    setup_demo_remediations()

