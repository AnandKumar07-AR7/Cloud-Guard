import { api } from './client'
import type { ScanListResponse, ScanRequest, ScanSummary } from '../types/scans'

/**
 * Scan status values returned by the API.
 * AWS scans transition: QUEUED → DISCOVERING → ANALYZING → RISK_SCORING → COMPLETED
 * Demo scans return COMPLETED immediately.
 */
const TERMINAL_STATUSES = ['COMPLETED', 'FAILED']
const POLL_INTERVAL_MS = 3000  // Poll every 3 seconds
const MAX_POLL_ATTEMPTS = 120  // Max 6 minutes of polling

export const scansApi = {
  listScans: async (
    limitOrParams?: number | { limit?: number; offset?: number; status?: string },
    offset?: number
  ): Promise<ScanListResponse> => {
    let params: Record<string, string | number | boolean | null | undefined> = {}
    if (typeof limitOrParams === 'number') {
      params = { limit: limitOrParams, offset: offset || 0 }
    } else if (limitOrParams) {
      params = limitOrParams as Record<string, string | number | boolean | null | undefined>
    }
    const res = await api.get<ScanListResponse>('/scans', { params })
    return {
      ...res,
      items: res.items || res.scans || [],
      scans: res.scans || res.items || [],
    }
  },

  getScan: async (scanId: string): Promise<ScanSummary> => {
    return api.get<ScanSummary>(`/scans/${scanId}`)
  },

  /**
   * Initiate a scan. For AWS mode, this returns immediately with status QUEUED.
   * Use `runScanAndWait()` to automatically poll until completion.
   */
  runScan: async (req: ScanRequest = {}): Promise<ScanSummary> => {
    return api.post<ScanSummary>('/scans', req)
  },

  /**
   * Initiate a scan and poll until it reaches a terminal status (COMPLETED or FAILED).
   *
   * For demo mode scans, this returns immediately since the scan completes synchronously.
   * For AWS mode scans, this polls GET /scans/{id} every 3 seconds until the scan
   * finishes, providing real-time status updates via the optional onProgress callback.
   *
   * @param req - Scan request parameters
   * @param onProgress - Optional callback invoked on each poll with the current scan state
   * @returns The completed (or failed) scan summary
   */
  runScanAndWait: async (
    req: ScanRequest = {},
    onProgress?: (scan: ScanSummary) => void,
  ): Promise<ScanSummary> => {
    const scan = await api.post<ScanSummary>('/scans', req)

    // If already in a terminal state (demo mode), return immediately
    if (TERMINAL_STATUSES.includes(scan.status)) {
      onProgress?.(scan)
      return scan
    }

    // AWS mode: poll until completion
    let current = scan
    onProgress?.(current)

    for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
      await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS))

      current = await api.get<ScanSummary>(`/scans/${scan.scan_id}`)
      onProgress?.(current)

      if (TERMINAL_STATUSES.includes(current.status)) {
        return current
      }
    }

    // Timed out — return whatever state we have
    return current
  },

  createScan: async (req: ScanRequest = {}): Promise<ScanSummary> => {
    return api.post<ScanSummary>('/scans', req)
  },
}
