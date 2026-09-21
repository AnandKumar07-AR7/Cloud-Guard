export interface SeveritySummary {
  critical: number
  high: number
  medium: number
  low: number
  informational: number
}

export interface RiskSummary {
  posture_score: number
  risk_level: string
  severity_counts: SeveritySummary
  top_risk_score: number
  average_risk_score: number
  open_finding_count: number
  total_finding_count: number
}

export interface ScanSummary {
  scan_id: string
  correlation_id: string
  provider: string
  account_id: string
  mode: string
  scenario?: string
  status: 'CREATED' | 'QUEUED' | 'DISCOVERING' | 'ANALYZING' | 'RISK_SCORING' | 'COMPLETED' | 'FAILED' | string
  regions: string[]
  resource_count: number
  resources_scanned?: number
  finding_count: number
  findings_count?: number
  severity_summary?: SeveritySummary
  risk_summary?: RiskSummary
  started_at: string
  completed_at?: string
  duration_seconds?: number
  error_count: number
  error_message?: string
}

export interface ScanListResponse {
  items: ScanSummary[]
  scans?: ScanSummary[]
  total: number
  limit: number
  offset: number
}

export interface ScanRequest {
  scenario?: 'default' | 'healthy' | 'critical' | string
  enrich_with_ai?: boolean
  ai_enrichment?: boolean
}
