export type Role = 'ADMIN' | 'SECURITY_ANALYST' | 'OPERATOR' | 'VIEWER' | string

export type Permission =
  | '*'
  | 'scans.read'
  | 'scans.create'
  | 'findings.read'
  | 'rules.read'
  | 'resources.read'
  | 'posture.read'
  | 'investigation.read'
  | 'remediations.read'
  | 'remediations.create'
  | 'remediations.validate'
  | 'remediations.approve'
  | 'remediations.execute'
  | 'remediations.cancel'
  | 'remediations.audit.read'
  | 'ai.read'
  | 'ai.analyze'
  | 'ai.audit.read'
  | 'automation.read'
  | 'automation.manage'
  | 'automation.evaluate'
  | 'automation.killswitch'
  | 'automation.audit.read'
  | 'mcp.read'
  | 'mcp.execute'
  | 'mcp.manage'
  | 'mcp.audit_read'
  | 'users.read'
  | 'users.manage'
  | string

export interface User {
  user_id: string
  username: string
  email: string
  role: Role
  is_active: boolean
  is_verified: boolean
  permissions?: string[]
  created_at: string
  updated_at?: string
  last_login_at?: string
  aws_account_id?: string
}

export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: User
}

export interface AccessTokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}
