import { api } from './client'

export interface ConnectedAccount {
  account_id: string
  account_name: string
  role_arn: string
  external_id: string
  region: string
  default_region?: string
  status: 'CONNECTED' | 'PENDING_VERIFICATION' | 'ERROR' | string
  last_verified_at: string
  created_at: string
  is_primary?: boolean
}

export interface GenerateExternalIdResponse {
  external_id: string
  host_account_id: string
  trust_policy: Record<string, any>
  permissions_policy: Record<string, any>
  cloudformation_template: string
  quick_launch_url: string
}

export type ExternalIdResponse = GenerateExternalIdResponse

export interface ConnectAccountRequest {
  account_id: string
  account_name: string
  role_arn: string
  external_id: string
  region?: string
  default_region?: string
}

export const accountsApi = {
  listAccounts: async (): Promise<ConnectedAccount[]> => {
    return api.get<ConnectedAccount[]>('/api/v1/accounts')
  },

  generateExternalId: async (targetAccountId?: string): Promise<GenerateExternalIdResponse> => {
    return api.post<GenerateExternalIdResponse>('/api/v1/accounts/generate-external-id', {
      account_id: targetAccountId,
    })
  },

  connectAccount: async (data: ConnectAccountRequest): Promise<{ account: ConnectedAccount }> => {
    const res = await api.post<ConnectedAccount>('/api/v1/accounts/connect', {
      ...data,
      region: data.region || data.default_region || 'us-east-1',
    })
    return { account: res }
  },

  disconnectAccount: async (accountId: string): Promise<void> => {
    return api.delete(`/api/v1/accounts/${accountId}`)
  },
}
