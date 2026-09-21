export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational' | string
export type FindingStatus = 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'STILL_VULNERABLE' | string

export interface Evidence {
  rule_id: string
  field_path?: string
  observed_value?: unknown
  expected_value?: unknown
  summary: string
  details?: Record<string, unknown>
  [key: string]: unknown
}

export interface SecurityContext {
  internet_exposed?: boolean
  publicly_accessible?: boolean
  network_exposure?: boolean
  privilege_escalation_risk?: boolean
  data_exposure_risk?: boolean
  credentials_detected?: boolean
  [key: string]: unknown
}

export interface RiskContext {
  base_score?: number
  severity_factor?: string
  internet_exposure_applied?: boolean
  internet_exposure_factor?: number
  final_score?: number
  rationale?: string
  [key: string]: unknown
}

export interface RemediationContext {
  available?: boolean
  safety?: string
  recommended_action?: string
  affected_fields?: string[]
  strategy_id?: string
  [key: string]: unknown
}

export interface ComplianceReference {
  framework: string
  control_id: string
  title?: string
}

export interface ComplianceContext {
  references?: ComplianceReference[]
  [key: string]: unknown
}

export interface AIAnalysisData {
  ai_source?: string
  executive_summary?: string
  technical_analysis?: string
  business_impact?: string
  attack_relevance?: string
  recommended_action?: string
  confidence?: string
  observed_facts?: string[]
  ai_inferences?: string[]
}

export interface Finding {
  finding_id: string
  canonical_id: string
  rule_id: string
  rule_version?: string
  scan_id: string
  resource_id: string
  resource_type: string
  resource_name?: string
  resource_arn?: string
  service: string
  account_id: string
  region: string
  provider: string
  severity: SeverityLevel
  risk_score: number
  status: FindingStatus
  title: string
  description: string
  remediation_guidance?: string
  category: string
  remediation_safety?: string
  evidence: Evidence
  compliance_mappings?: string[]
  internet_exposed: boolean
  is_internet_exposed?: boolean
  privilege_escalation_risk?: boolean
  data_exposure_risk?: boolean
  security_context?: SecurityContext
  risk_context?: RiskContext
  remediation_context?: RemediationContext
  compliance_context?: ComplianceContext
  ai_analysis?: AIAnalysisData
  ai_explanation?: string
  ai_manager_summary?: string
  ai_source?: string
  detected_at: string
  updated_at: string
}

export interface FindingListResponse {
  items: Finding[]
  findings?: Finding[]
  total: number
  limit: number
  offset: number
}

export interface FindingHistoryItem {
  finding_id: string
  scan_id: string
  status: string
  severity: string
  last_detected_at?: string
}

export interface FindingHistoryResponse {
  canonical_id: string
  occurrences: number
  history: FindingHistoryItem[]
}

export interface RelatedResource {
  resource_id: string
  resource_type: string
  service: string
  relationship_type?: string
}

export interface InvestigationResponse {
  finding: Finding
  rule?: {
    rule_id: string
    name: string
    description?: string
    severity: string
    service?: string
    category?: string
    rationale?: string
    remediation?: string
  }
  resource?: {
    resource_id: string
    resource_type?: string
    service?: string
    region?: string
    account_id?: string
    config?: Record<string, unknown>
    tags?: Record<string, string>
  }
  evidence: Evidence
  related_resources?: RelatedResource[]
  related_findings?: Finding[]
  ai_analysis?: AIAnalysisData
  remediation_context?: RemediationContext
  compliance_context?: ComplianceContext
}
