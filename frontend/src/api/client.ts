export class ApiError extends Error {
  status: number
  errorCode?: string
  details?: unknown

  constructor(status: number, message: string, errorCode?: string, details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.errorCode = errorCode
    this.details = details
  }
}

interface RequestOptions extends RequestInit {
  params?: Record<string, string | number | boolean | undefined | null>
}

class ApiClient {
  private baseUrl = ''
  private isRefreshing = false
  private refreshSubscribers: ((token: string) => void)[] = []

  private subscribeTokenRefresh(cb: (token: string) => void) {
    this.refreshSubscribers.push(cb)
  }

  private onTokenRefreshed(token: string) {
    this.refreshSubscribers.forEach((cb) => cb(token))
    this.refreshSubscribers = []
  }

  async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { params, headers: customHeaders, ...customOptions } = options

    let url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`

    if (params) {
      const searchParams = new URLSearchParams()
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          searchParams.append(key, String(value))
        }
      })
      const queryString = searchParams.toString()
      if (queryString) {
        url += (url.includes('?') ? '&' : '?') + queryString
      }
    }

    const headers = new Headers(customHeaders)
    if (!headers.has('Content-Type') && !(customOptions.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json')
    }

    const isTestEnv =
      (typeof window !== 'undefined' && ((window as any).__VITEST__ || typeof (window as any).vi !== 'undefined')) ||
      import.meta.env?.MODE === 'test'
    const isTabActive = sessionStorage.getItem('cloudguard_tab_active') === 'true' || isTestEnv
    const token = isTabActive ? localStorage.getItem('cloudguard_access_token') : null
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    try {
      const response = await fetch(url, {
        ...customOptions,
        headers,
      })

      // Handle 401 Unauthorized (Refresh token flow)
      if (response.status === 401 && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/refresh')) {
        const refreshToken = localStorage.getItem('cloudguard_refresh_token')
        if (refreshToken) {
          if (!this.isRefreshing) {
            this.isRefreshing = true
            try {
              const refreshRes = await fetch('/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refreshToken }),
              })

              if (refreshRes.ok) {
                const data = await refreshRes.json()
                localStorage.setItem('cloudguard_access_token', data.access_token)
                // SECURITY: Must also persist the rotated refresh token.
                // The backend uses refresh token family rotation — every /auth/refresh
                // issues a new refresh token and revokes the old one. Failure to store
                // the new token here means the next auto-refresh sends the revoked
                // token, which triggers family-wide revocation and forces logout.
                if (data.refresh_token) {
                  localStorage.setItem('cloudguard_refresh_token', data.refresh_token)
                }
                this.isRefreshing = false
                this.onTokenRefreshed(data.access_token)
              } else {
                this.isRefreshing = false
                localStorage.removeItem('cloudguard_access_token')
                localStorage.removeItem('cloudguard_refresh_token')
                window.dispatchEvent(new CustomEvent('cloudguard_auth_expired'))
                throw new ApiError(401, 'Session expired. Please log in again.', 'AUTH_EXPIRED')
              }
            } catch (err) {
              this.isRefreshing = false
              localStorage.removeItem('cloudguard_access_token')
              localStorage.removeItem('cloudguard_refresh_token')
              window.dispatchEvent(new CustomEvent('cloudguard_auth_expired'))
              throw err
            }
          }

          // Wait for token refresh and retry
          return new Promise<T>((resolve) => {
            this.subscribeTokenRefresh(async (newToken: string) => {
              headers.set('Authorization', `Bearer ${newToken}`)
              const retryResponse = await fetch(url, { ...customOptions, headers })
              resolve(this.handleResponse<T>(retryResponse))
            })
          })
        }
      }

      return this.handleResponse<T>(response)
    } catch (err) {
      if (err instanceof ApiError) {
        throw err
      }
      throw new ApiError(0, err instanceof Error ? err.message : 'Network error occurred', 'NETWORK_ERROR')
    }
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const contentType = response.headers?.get ? response.headers.get('content-type') : null
    const isJson = contentType && contentType.includes('application/json')

    if (response.status === 204) {
      return {} as T
    }

    const data = isJson ? await response.json() : await response.text()

    if (!response.ok) {
      let errorMsg = 'Request failed'
      if (typeof data === 'object' && data !== null) {
        if (typeof data.message === 'string') {
          errorMsg = data.message
        } else if (typeof data.detail === 'string') {
          errorMsg = data.detail
        } else if (Array.isArray(data.detail)) {
          // Pydantic validation errors: [{msg, loc, ...}, ...]
          errorMsg = data.detail
            .map((e: { msg?: string; loc?: string[] }) => {
              const field = e.loc && e.loc.length > 1 ? e.loc[e.loc.length - 1] : undefined
              return field ? `${field}: ${e.msg}` : e.msg || 'Validation error'
            })
            .join('. ')
        } else if (typeof data.error === 'string') {
          errorMsg = data.error
        }
      } else if (typeof data === 'string') {
        errorMsg = data
      }
      const errorCode = typeof data === 'object' && data !== null ? data.error_code : undefined
      const errorDetails = typeof data === 'object' && data !== null ? data.details : undefined

      throw new ApiError(response.status, errorMsg, errorCode, errorDetails)
    }

    return data as T
  }

  get<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'GET' })
  }

  post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'POST',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  }

  patch<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, {
      ...options,
      method: 'PATCH',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  }

  delete<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: 'DELETE' })
  }
}

export const api = new ApiClient()

export const getAuthToken = () => localStorage.getItem('cloudguard_access_token')
export const setAuthToken = (token: string) => localStorage.setItem('cloudguard_access_token', token)
export const clearAuthToken = () => localStorage.removeItem('cloudguard_access_token')
