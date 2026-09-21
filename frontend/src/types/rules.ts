export interface SecurityRule {
  rule_id: string
  name: string
  description: string
  provider: string
  service: string
  resource_type: string
  severity: string
  category: string
  rationale?: string
  remediation?: string
  enabled: boolean
}

export interface RuleCatalogSummary {
  total_rules: number
  enabled_rules: number
  severity_distribution: Record<string, number>
  service_distribution: Record<string, number>
  category_distribution: Record<string, number>
}

export interface RuleListResponse {
  items: SecurityRule[]
  total: number
  limit: number
  offset: number
  catalog_summary?: RuleCatalogSummary
}
