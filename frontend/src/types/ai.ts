export interface AIAgentRun {
  run_id: string
  finding_id: string
  initiating_user_id: string
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | string
  agent_version: string
  agent_name?: string
  model_name?: string
  tokens_consumed?: number
  reasoning_text?: string
  prompt_tokens?: number
  completion_tokens?: number
  error_message?: string
  error_category?: string
  created_at: string
  started_at?: string
  completed_at?: string
  duration_seconds?: number
  duration_ms?: number
  summary?: string
  executive_summary?: string
  observed_facts?: string[]
  ai_inferences?: string[]
}

export interface AIRecommendation {
  recommendation_id: string
  run_id: string
  finding_id: string
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | number | string
  recommended_action: string
  title?: string
  action_summary?: string
  description?: string
  rationale: string
  executive_summary?: string
  technical_analysis?: string
  business_impact?: string
  attack_relevance?: string
  recommended_strategy_id?: string
  strategy_name?: string
  safety_class?: string
  requires_human_approval: boolean
  is_immutable: boolean
  created_at: string
}

export interface AIToolEvent {
  event_id: string
  run_id: string
  tool_name: string
  tool_input?: Record<string, unknown>
  tool_output?: Record<string, unknown>
  status: 'SUCCESS' | 'FAILED' | string
  duration_ms?: number
  created_at: string
  timestamp?: string
}
