export interface ServicePosture {
  posture_score: number
  risk_level: string
  total_resources: number
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  top_risk_score?: number
}

export interface PostureResponse {
  posture_score: number
  risk_level: string
  total_resources: number
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  service_posture: Record<string, ServicePosture>
  resource_posture_summary: {
    SECURE: number
    AT_RISK: number
    HIGH_RISK: number
    CRITICAL: number
  }
  last_scanned_at?: string
  scan_id?: string
}
