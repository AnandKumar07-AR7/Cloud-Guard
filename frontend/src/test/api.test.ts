import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api, setAuthToken, getAuthToken, clearAuthToken } from '../api/client'

describe('API Client Layer', () => {
  beforeEach(() => {
    localStorage.clear()
    clearAuthToken()
  })

  it('manages authorization token in memory and localStorage', () => {
    expect(getAuthToken()).toBeNull()

    setAuthToken('test-jwt-token-123')
    expect(getAuthToken()).toBe('test-jwt-token-123')
    expect(localStorage.getItem('cloudguard_access_token')).toBe('test-jwt-token-123')

    clearAuthToken()
    expect(getAuthToken()).toBeNull()
    expect(localStorage.getItem('cloudguard_access_token')).toBeNull()
  })
})
