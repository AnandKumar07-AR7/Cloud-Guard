/// <reference types="vitest" />
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/auth': 'http://127.0.0.1:8000',
      '/scans': 'http://127.0.0.1:8000',
      '/findings': 'http://127.0.0.1:8000',
      '/resources': 'http://127.0.0.1:8000',
      '/rules': 'http://127.0.0.1:8000',
      '/posture': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/mode': 'http://127.0.0.1:8000',
      '/api': 'http://127.0.0.1:8000',
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
  },
})
