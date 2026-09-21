export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unavailable' | string
  mode: 'demo' | 'aws' | string
  version: string
  timestamp: string
  ai_enabled: boolean
  uptime_seconds: number
  db_status?: 'available' | 'unavailable' | string
}

export interface ModeResponse {
  mode: 'demo' | 'aws' | string
  description: string
  available_scenarios?: string[]
}
