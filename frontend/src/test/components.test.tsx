import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import React from 'react'
import { SeverityBadge, StatusBadge, OpClassBadge, Badge } from '../components/Badge'
import { DiffViewer } from '../components/DiffViewer'
import { ScoreGauge } from '../components/ScoreGauge'
import { EmptyState } from '../components/EmptyState'

describe('Obsidian Command Center Component Library', () => {
  describe('SeverityBadge', () => {
    it('renders CRITICAL severity with correct text and uppercase styling', () => {
      render(<SeverityBadge severity="CRITICAL" />)
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })

    it('renders count when supplied', () => {
      render(<SeverityBadge severity="HIGH" count={5} />)
      expect(screen.getByText('HIGH')).toBeInTheDocument()
      expect(screen.getByText('(5)')).toBeInTheDocument()
    })

    it('handles lowercase severity strings gracefully', () => {
      render(<SeverityBadge severity="medium" />)
      expect(screen.getByText('medium')).toBeInTheDocument()
    })
  })

  describe('StatusBadge', () => {
    it('renders OPEN status correctly', () => {
      render(<StatusBadge status="OPEN" />)
      expect(screen.getByText('OPEN')).toBeInTheDocument()
    })

    it('renders VERIFIED_FIXED status correctly', () => {
      render(<StatusBadge status="VERIFIED_FIXED" />)
      expect(screen.getByText('VERIFIED_FIXED')).toBeInTheDocument()
    })
  })

  describe('OpClassBadge', () => {
    it('renders DESTRUCTIVE operation class correctly', () => {
      render(<OpClassBadge opClass="DESTRUCTIVE" />)
      expect(screen.getByText('DESTRUCTIVE')).toBeInTheDocument()
    })

    it('renders READ operation class correctly', () => {
      render(<OpClassBadge opClass="READ" />)
      expect(screen.getByText('READ')).toBeInTheDocument()
    })
  })

  describe('DiffViewer', () => {
    it('renders before and after configuration comparison', () => {
      const beforeState = { versioning: 'Disabled', publicAccess: true }
      const afterState = { versioning: 'Enabled', publicAccess: false }

      render(
        <DiffViewer
          before={beforeState}
          after={afterState}
          beforeTitle="Current Vulnerable State"
          afterTitle="Proposed Remediated State"
        />
      )

      expect(screen.getByText('Current Vulnerable State')).toBeInTheDocument()
      expect(screen.getByText('Proposed Remediated State')).toBeInTheDocument()
      expect(screen.getByText('VULNERABLE')).toBeInTheDocument()
      expect(screen.getByText('REMEDIATED')).toBeInTheDocument()
    })
  })

  describe('ScoreGauge', () => {
    it('renders SVG score gauge with numerical score', () => {
      render(<ScoreGauge score={85.5} size={140} />)
      expect(screen.getByText('86')).toBeInTheDocument()
    })
  })

  describe('EmptyState', () => {
    it('renders title and description', () => {
      render(
        <EmptyState
          title="No Active Threats"
          description="Environment is fully secure."
        />
      )
      expect(screen.getByText('No Active Threats')).toBeInTheDocument()
      expect(screen.getByText('Environment is fully secure.')).toBeInTheDocument()
    })
  })
})
