import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { ProtectedRoute } from '../auth/ProtectedRoute'
import { AppLayout } from '../layouts/AppLayout'

// Pages
import { LoginPage } from '../pages/LoginPage'
import { OverviewPage } from '../pages/overview/OverviewPage'
import { PosturePage } from '../pages/posture/PosturePage'
import { LiveActivityPage } from '../pages/activity/LiveActivityPage'

// Discover
import { AssetsPage } from '../pages/discover/AssetsPage'
import { AccountsPage } from '../pages/discover/AccountsPage'

// Security
import { FindingsPage } from '../pages/security/FindingsPage'
import { FindingDetailPage } from '../pages/security/FindingDetailPage'
import { FindingInvestigationPage } from '../pages/security/FindingInvestigationPage'
import { RulesPage } from '../pages/security/RulesPage'
import { RiskAnalysisPage } from '../pages/security/RiskAnalysisPage'
import { AttackPathsPage } from '../pages/security/AttackPathsPage'

// Intelligence
import { AIAnalystPage } from '../pages/intelligence/AIAnalystPage'
import { AgentOrchestratorPage } from '../pages/intelligence/AgentOrchestratorPage'
import { AgentRunsPage } from '../pages/intelligence/AgentRunsPage'
import { AgentActivityPage } from '../pages/intelligence/AgentActivityPage'

// Remediation
import { RemediationCenterPage } from '../pages/remediation/RemediationCenterPage'
import { ApprovalQueuePage } from '../pages/remediation/ApprovalQueuePage'
import { ExecutionsPage } from '../pages/remediation/ExecutionsPage'
import { VerificationPage } from '../pages/remediation/VerificationPage'

// Compliance & Operations
import { CompliancePage } from '../pages/compliance/CompliancePage'
import { ScansPage } from '../pages/operations/ScansPage'
import { ReportsPage } from '../pages/operations/ReportsPage'
import { AuditLogPage } from '../pages/operations/AuditLogPage'

// System
import { MCPServersPage } from '../pages/system/MCPServersPage'
import { PolicyAutomationPage } from '../pages/system/PolicyAutomationPage'
import { SettingsPage } from '../pages/system/SettingsPage'

export const AppRoutes: React.FC = () => {
  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/login" element={<LoginPage initialMode="login" />} />
      <Route path="/signup" element={<LoginPage initialMode="signup" />} />
      <Route path="/register" element={<LoginPage initialMode="signup" />} />

      {/* Protected Routes enclosed in AppLayout */}
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<OverviewPage />} />
        <Route path="overview" element={<OverviewPage />} />
        <Route path="posture" element={<PosturePage />} />
        <Route path="activity" element={<LiveActivityPage />} />

        {/* Discover */}
        <Route path="assets" element={<AssetsPage />} />
        <Route path="accounts" element={<AccountsPage />} />
        <Route path="resources" element={<AssetsPage />} />

        {/* Security */}
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
        <Route path="findings/:id/investigate" element={<FindingInvestigationPage />} />
        <Route path="findings/:id/investigation" element={<FindingInvestigationPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="risk" element={<RiskAnalysisPage />} />
        <Route path="attack-paths" element={<AttackPathsPage />} />

        {/* Intelligence */}
        <Route path="ai" element={<AIAnalystPage />} />
        <Route path="ai-analyst" element={<AIAnalystPage />} />
        <Route path="orchestrator" element={<AgentOrchestratorPage />} />
        <Route path="agent-orchestrator" element={<AgentOrchestratorPage />} />
        <Route path="runs" element={<AgentRunsPage />} />
        <Route path="agent-runs" element={<AgentRunsPage />} />
        <Route path="agent-activity" element={<AgentActivityPage />} />

        {/* Remediation */}
        <Route path="remediation" element={<RemediationCenterPage />} />
        <Route path="approvals" element={<ApprovalQueuePage />} />
        <Route path="executions" element={<ExecutionsPage />} />
        <Route path="verification" element={<VerificationPage />} />

        {/* Compliance & Operations */}
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="audit" element={<AuditLogPage />} />

        {/* System */}
        <Route path="mcp" element={<MCPServersPage />} />
        <Route path="automation" element={<PolicyAutomationPage />} />
        <Route path="policies" element={<PolicyAutomationPage />} />
        <Route path="settings" element={<SettingsPage />} />

        {/* 404 redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
