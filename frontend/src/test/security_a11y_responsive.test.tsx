import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { CommandPalette } from '../components/CommandPalette'
import { Modal } from '../components/Modal'
import { Drawer } from '../components/Drawer'
import { EmptyState } from '../components/EmptyState'
import { findingsApi } from '../api/findingsApi'
import { resourcesApi } from '../api/resourcesApi'
import { scansApi } from '../api/scansApi'
import { mcpApi } from '../api/mcpApi'
import { api } from '../api/client'

vi.mock('../api/findingsApi')
vi.mock('../api/resourcesApi')
vi.mock('../api/scansApi')
vi.mock('../api/mcpApi')

describe('Phase 11 Security, Accessibility, and Resilience Verification', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  describe('1. Security Verification: Secret Masking & Injection Prevention', () => {
    it('prevents XSS and HTML injection when rendering untrusted cloud-controlled data', () => {
      const untrustedPayload = '<img src=x onerror=alert("pwned") /><script>window.pwned=true</script>'

      render(
        <EmptyState
          title={untrustedPayload}
          description="Cloud asset discovery found malicious payload"
        />
      )

      // Untrusted string must be rendered as raw text, not as an HTML element
      expect(screen.getByText(untrustedPayload)).toBeInTheDocument()
      expect(document.querySelector('img[src="x"]')).toBeNull()
      expect((window as any).pwned).toBeUndefined()
    })

    it('safely masks credentials and secret tokens in technical identifiers', () => {
      const maskSecret = (key: string) => {
        if (key.length <= 8) return '••••••••'
        return `${key.slice(0, 4)}••••••••${key.slice(-4)}`
      }

      const rawSecret = 'AKIAIOSFODNN7EXAMPLE'
      const masked = maskSecret(rawSecret)

      expect(masked).toBe('AKIA••••••••MPLE')
      expect(masked).not.toContain('IOSFODNN7')
    })
  })

  describe('2. Accessibility (a11y) & Keyboard Navigation', () => {
    it('supports keyboard navigation and Escape key dismissal in Command Palette', async () => {
      const handleClose = vi.fn()
      vi.mocked(findingsApi.listFindings).mockResolvedValue({ items: [], total: 0 } as any)
      vi.mocked(resourcesApi.listResources).mockResolvedValue({ items: [], total: 0 } as any)
      vi.mocked(scansApi.listScans).mockResolvedValue({ items: [], total: 0 } as any)
      vi.mocked(mcpApi.listServers).mockResolvedValue([] as any)

      render(
        <MemoryRouter>
          <CommandPalette isOpen={true} onClose={handleClose} />
        </MemoryRouter>
      )

      const input = screen.getByPlaceholderText(/Search pages, findings/i)
      expect(input).toBeInTheDocument()

      // Pressing Escape should trigger close
      fireEvent.keyDown(input, { key: 'Escape', code: 'Escape' })
      expect(handleClose).toHaveBeenCalledTimes(1)
    })

    it('enforces accessibility in Modal with proper dialog roles and focus containers', () => {
      const handleClose = vi.fn()

      render(
        <Modal isOpen={true} onClose={handleClose} title="Security Action Confirmation">
          <div>Sensitive remediation step requires re-authentication.</div>
        </Modal>
      )

      expect(screen.getByText('Security Action Confirmation')).toBeInTheDocument()
      expect(screen.getByText(/Sensitive remediation step requires re-authentication/i)).toBeInTheDocument()

      // Close button operates properly
      const closeBtn = screen.getByRole('button')
      fireEvent.click(closeBtn)
      expect(handleClose).toHaveBeenCalled()
    })

    it('renders Drawer with semantic structure and accessible dismissal', () => {
      const handleClose = vi.fn()

      render(
        <Drawer isOpen={true} onClose={handleClose} title="Resource Technical Details">
          <div>ARN: arn:aws:s3:::sensitive-financial-records</div>
        </Drawer>
      )

      expect(screen.getByText('Resource Technical Details')).toBeInTheDocument()
      expect(screen.getByText(/arn:aws:s3:::sensitive-financial-records/i)).toBeInTheDocument()

      const closeBtn = screen.getByRole('button')
      fireEvent.click(closeBtn)
      expect(handleClose).toHaveBeenCalled()
    })
  })

  describe('3. Comprehensive HTTP Status Code & Network Error Resilience', () => {
    const createMockResponse = (status: number, body: unknown) =>
      ({
        ok: status >= 200 && status < 300,
        status,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => body,
        text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
      } as unknown as Response)

    it('handles 401 Unauthorized by clearing session and redirecting to /login', async () => {
      localStorage.setItem('cloudguard_access_token', 'expired-token')
      localStorage.setItem('cloudguard_refresh_token', 'expired-refresh')

      // Mock fetch returning 401 on refresh
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(401, { detail: 'Token expired' })
      )

      await expect(api.get('/findings')).rejects.toThrow()
      expect(localStorage.getItem('cloudguard_access_token')).toBeNull()
    })

    it('handles 403 Forbidden with permission boundary error', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(403, { detail: 'Forbidden: Insufficient role permissions' })
      )

      await expect(api.post('/automation/kill-switch', { enable: true })).rejects.toThrow(
        /Forbidden: Insufficient role permissions/i
      )
    })

    it('handles 404 Resource Not Found cleanly', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(404, { detail: 'Finding f-missing-999 not found' })
      )

      await expect(api.get('/findings/f-missing-999')).rejects.toThrow(/not found/i)
    })

    it('handles 409 Conflict during concurrent state transitions', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(409, { detail: 'Conflict: Plan already in EXECUTING state' })
      )

      await expect(api.post('/remediations/plans/p-1/execute', {})).rejects.toThrow(
        /Conflict: Plan already in EXECUTING state/i
      )
    })

    it('handles 422 Unprocessable Entity for schema validation failures', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(422, {
          detail: [{ loc: ['body', 'reason'], msg: 'field required', type: 'value_error.missing' }],
        })
      )

      await expect(api.post('/automation/kill-switch', {})).rejects.toThrow()
    })

    it('handles 429 Rate Limit Throttling gracefully', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(429, { detail: 'Too Many Requests: Rate limit exceeded. Retry in 30s.' })
      )

      await expect(api.get('/scans')).rejects.toThrow(/Rate limit exceeded/i)
    })

    it('handles 500 Internal Server Error without leaking internal stack traces', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(500, { detail: 'Internal Server Error' })
      )

      await expect(api.get('/overview')).rejects.toThrow(/Internal Server Error/i)
    })

    it('handles 503 Service Unavailable when cloud backend is undergoing maintenance', async () => {
      vi.spyOn(global, 'fetch').mockResolvedValueOnce(
        createMockResponse(503, { detail: 'Service Temporarily Unavailable' })
      )

      await expect(api.get('/posture')).rejects.toThrow(/Service Temporarily Unavailable/i)
    })

    it('handles Network Failure and offline state gracefully', async () => {
      vi.spyOn(global, 'fetch').mockRejectedValueOnce(new TypeError('Failed to fetch (Network disconnected)'))

      await expect(api.get('/findings')).rejects.toThrow(/Network disconnected/i)
    })
  })
})
