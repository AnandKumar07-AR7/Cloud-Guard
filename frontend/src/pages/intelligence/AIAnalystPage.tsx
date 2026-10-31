import React, { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Cpu,
  Sparkles,
  Wrench,
  Fingerprint,
  Send,
  MessageSquare,
  Bot,
  User,
  Trash2,
  Copy,
  Check,
  Terminal,
  ShieldAlert,
  ArrowRight,
  Layers,
} from 'lucide-react'
import { aiApi } from '../../api/aiApi'
import { findingsApi } from '../../api/findingsApi'
import { useAuth } from '../../auth/AuthContext'
import { LoadingSkeleton } from '../../components/LoadingSkeleton'
import { EmptyState } from '../../components/EmptyState'
import { PageHeader } from '../../components/ui/PageHeader'
import { Card, CardBody, CardHeader } from '../../components/ui/Card'
import { Button } from '../../components/ui/Button'

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
  suggestions?: string[]
}

const DEFAULT_MESSAGES: ChatMessage[] = [
  {
    id: 'welcome',
    role: 'assistant',
    content: `👋 Hello! I am your **Gemini Cloud Security Copilot**.

I have real-time visibility into your live cloud environment (**AWS AP-SOUTHEAST-2**, Account ID \`817760095153\`). You can chat with me about your detected misconfigurations (such as open Port 22 SSH Security Groups or IAM wildcard permissions), ask for security guidance, or request step-by-step remediation commands.

How can I help you secure your cloud infrastructure today?`,
    timestamp: 'Just now',
    suggestions: [
      'What are my top security risks right now?',
      'How do I fix the IAM wildcard role?',
      'What is an IAM permissions boundary?',
      'Show me CLI remediation commands',
      'How do I secure S3 buckets?',
    ],
  },
]

// Simple Code block with copy button
const CodeBlock: React.FC<{ code: string; language?: string }> = ({ code, language }) => {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      style={{
        margin: '10px 0',
        borderRadius: 8,
        overflow: 'hidden',
        border: '1px solid rgba(255, 255, 255, 0.12)',
        background: '#090d16',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '6px 12px',
          background: 'rgba(255, 255, 255, 0.04)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-muted)',
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Terminal size={12} className="text-cyan" />
          {language || 'bash'}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          style={{
            background: 'transparent',
            border: 'none',
            color: copied ? '#10b981' : 'var(--text-secondary)',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            fontSize: 11,
          }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre
        style={{
          margin: 0,
          padding: '12px 14px',
          overflowX: 'auto',
          fontSize: 12,
          fontFamily: 'var(--font-mono)',
          color: '#38bdf8',
          lineHeight: 1.5,
        }}
      >
        {code}
      </pre>
    </div>
  )
}

// Markdown formatter for Gemini messages
const FormattedMessage: React.FC<{ content: string }> = ({ content }) => {
  const parts = content.split(/(```[\s\S]*?```)/g)

  return (
    <div style={{ fontSize: 13, lineHeight: 1.6, color: '#e2e8f0' }}>
      {parts.map((part, index) => {
        if (part.startsWith('```') && part.endsWith('```')) {
          const lines = part.slice(3, -3).trim().split('\n')
          const firstLine = lines[0].trim()
          const isLang = /^[a-zA-Z0-9_-]+$/.test(firstLine)
          const language = isLang ? firstLine : 'bash'
          const code = (isLang ? lines.slice(1) : lines).join('\n')
          return <CodeBlock key={index} code={code} language={language} />
        }

        // Render plain text with line breaks, bold, and bullets
        const lines = part.split('\n')
        return (
          <React.Fragment key={index}>
            {lines.map((line, lIdx) => {
              if (line.startsWith('### ')) {
                return (
                  <h4
                    key={lIdx}
                    style={{
                      margin: '12px 0 6px 0',
                      fontSize: 14,
                      fontWeight: 700,
                      color: '#ffffff',
                    }}
                  >
                    {line.replace('### ', '')}
                  </h4>
                )
              }

              // Bold parser & inline code
              const renderSpans = (text: string) => {
                const chunks = text.split(/(\*\*.*?\*\*|`.*?`)/g)
                return chunks.map((chunk, cIdx) => {
                  if (chunk.startsWith('**') && chunk.endsWith('**')) {
                    return (
                      <strong key={cIdx} style={{ color: '#ffffff', fontWeight: 700 }}>
                        {chunk.slice(2, -2)}
                      </strong>
                    )
                  }
                  if (chunk.startsWith('`') && chunk.endsWith('`')) {
                    return (
                      <code
                        key={cIdx}
                        style={{
                          background: 'rgba(6, 182, 212, 0.14)',
                          color: '#38bdf8',
                          padding: '2px 5px',
                          borderRadius: 4,
                          fontSize: 12,
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        {chunk.slice(1, -1)}
                      </code>
                    )
                  }
                  return chunk
                })
              }

              if (line.startsWith('• ') || line.startsWith('- ')) {
                return (
                  <div
                    key={lIdx}
                    style={{
                      display: 'flex',
                      gap: 8,
                      margin: '4px 0',
                      paddingLeft: 4,
                    }}
                  >
                    <span style={{ color: '#06b6d4', flexShrink: 0 }}>•</span>
                    <div>{renderSpans(line.replace(/^[•-]\s*/, ''))}</div>
                  </div>
                )
              }

              return (
                <div key={lIdx} style={{ minHeight: line ? 'auto' : 8 }}>
                  {renderSpans(line)}
                </div>
              )
            })}
          </React.Fragment>
        )
      })}
    </div>
  )
}

export const AIAnalystPage: React.FC = () => {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { user } = useAuth()
  const currentAccountId = user?.aws_account_id || '371700247056'
  const [activeTab, setActiveTab] = useState<'chat' | 'runs'>('chat')
  const [selectedFindingId, setSelectedFindingId] = useState<string>('')
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null)

  // Chatbot State
  const [messages, setMessages] = useState<ChatMessage[]>(DEFAULT_MESSAGES)
  const [inputMessage, setInputMessage] = useState<string>('')
  const [isChatLoading, setIsChatLoading] = useState<boolean>(false)
  const chatBottomRef = useRef<HTMLDivElement>(null)

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (activeTab === 'chat') {
      chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, isChatLoading, activeTab])

  // Fetch recent runs
  const { data: runs, isLoading: loadingRuns } = useQuery({
    queryKey: ['ai', 'runs'],
    queryFn: () => aiApi.listRuns({ limit: 20 }),
  })

  // Fetch findings for analysis selector
  const { data: findingsData } = useQuery({
    queryKey: ['findings', 'open'],
    queryFn: () => findingsApi.listFindings({ status: 'OPEN', limit: 30 }),
  })

  // Selected run details
  const activeRunId = selectedRunId || (runs && runs.length > 0 ? runs[0].run_id : null)

  const { data: currentRun, isLoading: loadingRun } = useQuery({
    queryKey: ['ai', 'run', activeRunId],
    queryFn: () => aiApi.getRun(activeRunId!),
    enabled: Boolean(activeRunId),
  })

  const { data: recommendations } = useQuery({
    queryKey: ['ai', 'recommendations', activeRunId],
    queryFn: () => aiApi.getRunRecommendations(activeRunId!),
    enabled: Boolean(activeRunId),
  })

  const { data: auditEvents } = useQuery({
    queryKey: ['ai', 'audit', activeRunId],
    queryFn: () => aiApi.getRunAudit(activeRunId!),
    enabled: Boolean(activeRunId),
  })

  // Trigger analysis mutation
  const analyzeMutation = useMutation({
    mutationFn: (findingId: string) => aiApi.analyze(findingId),
    onSuccess: (newRun) => {
      queryClient.invalidateQueries({ queryKey: ['ai', 'runs'] })
      setSelectedRunId(newRun.run_id)
      setActiveTab('runs')
    },
  })

  const createPlanMutation = useMutation({
    mutationFn: (recId: string) => aiApi.createRemediationPlanFromRecommendation(recId),
    onSuccess: () => {
      navigate('/remediation')
    },
    onError: (error: any) => {
      const msg = error?.response?.data?.detail || error.message || 'Failed to create plan'
      if (msg.includes('already exists')) {
        navigate('/remediation')
      } else {
        alert(`Error creating plan: ${msg}`)
      }
    },
  })

  const findings = findingsData?.findings || []

  // Chat send handler
  const handleSendMessage = async (userText: string) => {
    const trimmed = userText.trim()
    if (!trimmed || isChatLoading) return

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      role: 'user',
      content: trimmed,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    setMessages((prev) => [...prev, userMsg])
    setInputMessage('')
    setIsChatLoading(true)

    try {
      const history = messages.slice(-6).map((m) => ({ role: m.role, content: m.content }))
      const res = await aiApi.chat(trimmed, history)

      const assistantMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: res.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        suggestions: res.suggested_actions,
      }

      setMessages((prev) => [...prev, assistantMsg])
    } catch {
      const errorMsg: ChatMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content:
          "⚠️ I'm currently unable to connect to the backend security engine. Please verify that the backend is active at `http://127.0.0.1:8000`.",
        timestamp: 'Just now',
      }
      setMessages((prev) => [...prev, errorMsg])
    } finally {
      setIsChatLoading(false)
    }
  }

  return (
    <div className="cg-page-container">
      {/* Header */}
      <PageHeader
        title="AI SECURITY ASSISTANT"
        subtitle="Gemini Security Copilot & Autonomous AI Cloud Misconfiguration Analysis"
        badge={
          <span
            style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '3px 10px',
              borderRadius: 999,
              background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.2) 0%, rgba(6, 182, 212, 0.2) 100%)',
              border: '1px solid rgba(168, 85, 247, 0.4)',
              color: '#c084fc',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Sparkles size={12} className="text-cyan" />
            GEMINI COPILOT ACTIVE
          </span>
        }
        actions={
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {/* View Switcher: Chat vs Runs */}
            <div
              style={{
                display: 'inline-flex',
                background: 'rgba(255, 255, 255, 0.05)',
                padding: 3,
                borderRadius: 10,
                border: '1px solid rgba(255, 255, 255, 0.1)',
              }}
            >
              <button
                type="button"
                onClick={() => setActiveTab('chat')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 14px',
                  borderRadius: 8,
                  border: 'none',
                  background: activeTab === 'chat' ? 'var(--accent-primary)' : 'transparent',
                  color: activeTab === 'chat' ? '#ffffff' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: 12,
                  fontWeight: 600,
                  transition: 'all 0.15s ease',
                }}
              >
                <MessageSquare size={14} />
                Gemini Chatbot
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('runs')}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 14px',
                  borderRadius: 8,
                  border: 'none',
                  background: activeTab === 'runs' ? 'var(--accent-primary)' : 'transparent',
                  color: activeTab === 'runs' ? '#ffffff' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: 12,
                  fontWeight: 600,
                  transition: 'all 0.15s ease',
                }}
              >
                <Cpu size={14} />
                Audit Reports ({runs?.length || 0})
              </button>
            </div>
          </div>
        }
      />

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* TAB 1: GEMINI CHATBOT VIEW */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'chat' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Quick Prompt Suggestion Pills */}
          <div
            style={{
              display: 'flex',
              gap: 8,
              overflowX: 'auto',
              paddingBottom: 4,
            }}
          >
            {[
              '🔍 What are my top security risks?',
              '🔑 How do I fix the IAM wildcard role?',
              '🛡️ What is an IAM permissions boundary?',
              '⚡ Give me CLI remediation commands',
              '🪣 How do I secure S3 buckets?',
            ].map((prompt, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handleSendMessage(prompt.replace(/^[^\w]+/, ''))}
                disabled={isChatLoading}
                style={{
                  padding: '6px 12px',
                  borderRadius: 999,
                  background: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  color: 'var(--text-secondary)',
                  fontSize: 12,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(6, 182, 212, 0.4)'
                  e.currentTarget.style.color = '#ffffff'
                  e.currentTarget.style.background = 'rgba(6, 182, 212, 0.1)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.1)'
                  e.currentTarget.style.color = 'var(--text-secondary)'
                  e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)'
                }}
              >
                {prompt}
              </button>
            ))}
          </div>

          {/* Chat Window Container */}
          <Card variant="elevated" style={{ height: '620px', display: 'flex', flexDirection: 'column' }}>
            {/* Chat Top Banner */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 18px',
                borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
                background: 'rgba(15, 23, 42, 0.6)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    background: 'linear-gradient(135deg, #a855f7 0%, #06b6d4 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#ffffff',
                    boxShadow: '0 0 12px rgba(6, 182, 212, 0.4)',
                  }}
                >
                  <Sparkles size={16} />
                </div>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: '#ffffff' }}>
                    Gemini Cloud Security Copilot
                  </div>
                  <div style={{ fontSize: 11, color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
                    ● AWS Live Telemetry (Account {currentAccountId})
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setMessages(DEFAULT_MESSAGES)}
                title="Reset Chat"
                style={{
                  background: 'transparent',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  color: 'var(--text-muted)',
                  borderRadius: 8,
                  padding: '5px 10px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: 11,
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = '#fb7185')}
                onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
              >
                <Trash2 size={13} />
                Clear Chat
              </button>
            </div>

            {/* Chat Messages Feed */}
            <CardBody
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '18px 20px',
                display: 'flex',
                flexDirection: 'column',
                gap: 16,
              }}
            >
              {messages.map((m) => (
                <div
                  key={m.id}
                  style={{
                    display: 'flex',
                    gap: 12,
                    alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                    maxWidth: m.role === 'user' ? '80%' : '88%',
                    flexDirection: m.role === 'user' ? 'row-reverse' : 'row',
                  }}
                >
                  {/* Avatar */}
                  <div
                    style={{
                      width: 30,
                      height: 30,
                      borderRadius: '50%',
                      flexShrink: 0,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      background:
                        m.role === 'user'
                          ? 'rgba(99, 102, 241, 0.25)'
                          : 'linear-gradient(135deg, rgba(168, 85, 247, 0.4) 0%, rgba(6, 182, 212, 0.4) 100%)',
                      border:
                        m.role === 'user'
                          ? '1px solid rgba(99, 102, 241, 0.5)'
                          : '1px solid rgba(6, 182, 212, 0.5)',
                      color: '#ffffff',
                    }}
                  >
                    {m.role === 'user' ? <User size={15} /> : <Sparkles size={15} />}
                  </div>

                  {/* Message Bubble */}
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    <div
                      style={{
                        padding: '12px 16px',
                        borderRadius: 14,
                        background:
                          m.role === 'user'
                            ? 'linear-gradient(135deg, rgba(99, 102, 241, 0.3) 0%, rgba(79, 70, 229, 0.35) 100%)'
                            : 'rgba(18, 25, 43, 0.85)',
                        border:
                          m.role === 'user'
                            ? '1px solid rgba(99, 102, 241, 0.4)'
                            : '1px solid rgba(255, 255, 255, 0.08)',
                        boxShadow: '0 4px 15px rgba(0, 0, 0, 0.2)',
                      }}
                    >
                      <FormattedMessage content={m.content} />
                    </div>

                    {/* Suggestions Buttons from Assistant */}
                    {m.suggestions && m.suggestions.length > 0 && (
                      <div
                        style={{
                          display: 'flex',
                          flexWrap: 'wrap',
                          gap: 6,
                          marginTop: 8,
                          paddingLeft: 4,
                        }}
                      >
                        {m.suggestions.map((s, idx) => (
                          <button
                            key={idx}
                            type="button"
                            onClick={() => handleSendMessage(s)}
                            disabled={isChatLoading}
                            style={{
                              padding: '4px 10px',
                              borderRadius: 6,
                              background: 'rgba(6, 182, 212, 0.1)',
                              border: '1px solid rgba(6, 182, 212, 0.25)',
                              color: '#38bdf8',
                              fontSize: 11,
                              cursor: 'pointer',
                              transition: 'all 0.12s ease',
                            }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.background = 'rgba(6, 182, 212, 0.2)'
                              e.currentTarget.style.borderColor = '#06b6d4'
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.background = 'rgba(6, 182, 212, 0.1)'
                              e.currentTarget.style.borderColor = 'rgba(6, 182, 212, 0.25)'
                            }}
                          >
                            ↳ {s}
                          </button>
                        ))}
                      </div>
                    )}

                    <span
                      style={{
                        fontSize: 10,
                        color: 'var(--text-muted)',
                        marginTop: 4,
                        paddingLeft: 4,
                        alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                      }}
                    >
                      {m.timestamp}
                    </span>
                  </div>
                </div>
              ))}

              {/* Thinking Indicator */}
              {isChatLoading && (
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                  <div
                    style={{
                      width: 30,
                      height: 30,
                      borderRadius: '50%',
                      background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.4) 0%, rgba(6, 182, 212, 0.4) 100%)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: '#ffffff',
                    }}
                  >
                    <Sparkles size={15} className="spin" />
                  </div>
                  <div
                    style={{
                      padding: '10px 16px',
                      borderRadius: 14,
                      background: 'rgba(18, 25, 43, 0.75)',
                      border: '1px solid rgba(255, 255, 255, 0.08)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      color: '#38bdf8',
                      fontSize: 12,
                    }}
                  >
                    <span>Gemini is analyzing your cloud posture...</span>
                  </div>
                </div>
              )}

              <div ref={chatBottomRef} />
            </CardBody>

            {/* Input Bar */}
            <div
              style={{
                padding: '12px 18px',
                borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                background: 'rgba(11, 15, 26, 0.85)',
              }}
            >
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  handleSendMessage(inputMessage)
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                }}
              >
                <input
                  type="text"
                  placeholder="Ask Gemini anything about your cloud security, AWS findings, or fixes..."
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  disabled={isChatLoading}
                  style={{
                    flex: 1,
                    padding: '12px 16px',
                    borderRadius: 12,
                    border: '1px solid rgba(255, 255, 255, 0.12)',
                    background: 'rgba(18, 25, 43, 0.9)',
                    color: '#ffffff',
                    fontSize: 13,
                    outline: 'none',
                    transition: 'border-color 0.15s ease',
                  }}
                  onFocus={(e) => (e.target.style.borderColor = 'rgba(6, 182, 212, 0.5)')}
                  onBlur={(e) => (e.target.style.borderColor = 'rgba(255, 255, 255, 0.12)')}
                />
                <button
                  type="submit"
                  disabled={!inputMessage.trim() || isChatLoading}
                  style={{
                    padding: '12px 18px',
                    borderRadius: 12,
                    border: 'none',
                    background:
                      !inputMessage.trim() || isChatLoading
                        ? 'rgba(255, 255, 255, 0.1)'
                        : 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
                    color: '#ffffff',
                    cursor: !inputMessage.trim() || isChatLoading ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    fontWeight: 700,
                    fontSize: 13,
                    boxShadow:
                      !inputMessage.trim() || isChatLoading
                        ? 'none'
                        : '0 0 15px rgba(6, 182, 212, 0.35)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <Send size={15} />
                  Send
                </button>
              </form>
            </div>
          </Card>
        </div>
      )}

      {/* ────────────────────────────────────────────────────────────────────────── */}
      {/* TAB 2: AUTONOMOUS AGENT RUNS & AUDIT LOGS */}
      {/* ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'runs' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Analyze Finding Launcher Bar */}
          <Card variant="default">
            <CardBody style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#ffffff' }}>
                  Trigger Autonomous Security Audit
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Launch a dedicated background agent run against any discovered open finding.
                </div>
              </div>

              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <select
                  value={selectedFindingId}
                  onChange={(e) => setSelectedFindingId(e.target.value)}
                  style={{
                    padding: '8px 12px',
                    background: 'rgba(18, 25, 43, 0.8)',
                    border: '1px solid rgba(255, 255, 255, 0.12)',
                    borderRadius: 8,
                    color: '#ffffff',
                    fontSize: 12,
                    minWidth: 300,
                    outline: 'none',
                  }}
                >
                  <option value="">Select an open finding to audit...</option>
                  {findings.map((f) => (
                    <option key={f.finding_id} value={f.finding_id}>
                      [{f.severity}] {f.title.slice(0, 45)}...
                    </option>
                  ))}
                </select>

                <Button
                  variant="primary"
                  size="sm"
                  disabled={!selectedFindingId || analyzeMutation.isPending}
                  onClick={() => selectedFindingId && analyzeMutation.mutate(selectedFindingId)}
                >
                  <Cpu size={14} className={analyzeMutation.isPending ? 'spin' : ''} />
                  {analyzeMutation.isPending ? 'Auditing...' : 'Run Audit'}
                </Button>
              </div>
            </CardBody>
          </Card>

          {/* Main 2-Column Analyst Workspace */}
          <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 'var(--space-4)', alignItems: 'start' }}>
            {/* Left Column: Historical Agent Runs */}
            <Card variant="elevated">
              <CardHeader
                title="Recorded Runs"
                action={<span className="font-mono text-cyan">{runs?.length || 0}</span>}
              />
              <CardBody style={{ padding: 0 }}>
                {loadingRuns ? (
                  <div style={{ padding: 'var(--space-3)' }}>
                    <LoadingSkeleton variant="card" count={4} height="56px" />
                  </div>
                ) : !runs || runs.length === 0 ? (
                  <div style={{ padding: 'var(--space-5)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                    No analyst runs recorded. Select a finding above to trigger an autonomous analysis.
                  </div>
                ) : (
                  <div style={{ maxHeight: '680px', overflowY: 'auto' }}>
                    {runs.map((r) => {
                      const isSelected = r.run_id === activeRunId
                      return (
                        <div
                          key={r.run_id}
                          onClick={() => setSelectedRunId(r.run_id)}
                          style={{
                            padding: 'var(--space-3)',
                            borderBottom: '1px solid var(--border-subtle)',
                            background: isSelected ? 'var(--status-info-bg)' : 'transparent',
                            borderLeft: isSelected ? '3px solid var(--accent-primary)' : '3px solid transparent',
                            cursor: 'pointer',
                            transition: 'background 0.1s ease',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span className="font-mono text-cyan" style={{ fontSize: '11px', fontWeight: 600 }}>
                              {r.run_id.slice(0, 8)}...
                            </span>
                            <span
                              style={{
                                fontSize: '10px',
                                fontWeight: 600,
                                padding: '1px 6px',
                                borderRadius: 'var(--radius-sm)',
                                background:
                                  r.status === 'COMPLETED'
                                    ? 'var(--status-success-bg)'
                                    : r.status === 'FAILED'
                                    ? 'var(--status-critical-bg)'
                                    : 'var(--status-warning-bg)',
                                color:
                                  r.status === 'COMPLETED'
                                    ? 'var(--text-success)'
                                    : r.status === 'FAILED'
                                    ? 'var(--text-critical)'
                                    : 'var(--text-warning)',
                              }}
                            >
                              {r.status}
                            </span>
                          </div>

                          <div style={{ fontSize: '12px', color: 'var(--text-high)', marginTop: '4px' }}>
                            Finding: <span className="font-mono">{r.finding_id ? r.finding_id.slice(0, 10) : 'N/A'}...</span>
                          </div>

                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                            <span className="font-mono">{r.agent_name || 'Security Analyst'}</span>
                            <span className="font-mono">{r.duration_ms ? `${r.duration_ms}ms` : 'Recorded'}</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardBody>
            </Card>

            {/* Right Column: Structured Analysis Inspector */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              {loadingRun ? (
                <LoadingSkeleton variant="card" count={3} height="120px" />
              ) : !currentRun ? (
                <Card variant="elevated">
                  <CardBody style={{ padding: 'var(--space-6)' }}>
                    <EmptyState
                      icon={Cpu}
                      title="No Analysis Selected"
                      description="Select a recorded run on the left or trigger an analysis above to inspect structured telemetry."
                    />
                  </CardBody>
                </Card>
              ) : (
                <>
                  {/* Run Metadata Card */}
                  <Card variant="elevated">
                    <CardHeader
                      title={`Run ${currentRun.run_id.slice(0, 12)}...`}
                      action={
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 600,
                            padding: '2px 8px',
                            borderRadius: 'var(--radius-sm)',
                            background:
                              currentRun.status === 'COMPLETED'
                                ? 'var(--status-success-bg)'
                                : 'var(--status-critical-bg)',
                            color:
                              currentRun.status === 'COMPLETED'
                                ? 'var(--text-success)'
                                : 'var(--text-critical)',
                          }}
                        >
                          {currentRun.status}
                        </span>
                      }
                    />
                    <CardBody>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 'var(--space-3)', marginBottom: 'var(--space-4)' }}>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Target Finding</div>
                          <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                            {currentRun.finding_id || 'N/A'}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Model Engine</div>
                          <div className="font-mono" style={{ fontSize: '12px', color: 'var(--text-high)' }}>
                            {currentRun.model_name || 'Anthropic Sonnet'}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Tokens Consumed</div>
                          <div className="font-mono text-cyan" style={{ fontSize: '12px' }}>
                            {currentRun.tokens_consumed ?? 0} tokens
                          </div>
                        </div>
                      </div>

                      {/* Reasoning Output */}
                      {currentRun.reasoning_text && (
                        <div>
                          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                            Analysis Reasoning
                          </div>
                          <div
                            style={{
                              padding: 'var(--space-3)',
                              borderRadius: 'var(--radius-sm)',
                              background: 'var(--surface-overlay)',
                              border: '1px solid var(--border-subtle)',
                              fontSize: '12px',
                              lineHeight: 1.5,
                              color: 'var(--text-high)',
                              whiteSpace: 'pre-wrap',
                            }}
                          >
                            {currentRun.reasoning_text}
                          </div>
                        </div>
                      )}
                    </CardBody>
                  </Card>

                  {/* Recommendations */}
                  <Card variant="elevated">
                    <CardHeader
                      title="AI Recommendations"
                      action={<span className="font-mono text-cyan">{recommendations?.length || 0} Generated</span>}
                    />
                    <CardBody style={{ padding: 0 }}>
                      {!recommendations || recommendations.length === 0 ? (
                        <div style={{ padding: 'var(--space-4)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                          No discrete recommendations attached to this run.
                        </div>
                      ) : (
                        recommendations.map((rec) => (
                          <div
                            key={rec.recommendation_id}
                            style={{
                              padding: 'var(--space-4)',
                              borderBottom: '1px solid var(--border-subtle)',
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              gap: 'var(--space-3)',
                            }}
                          >
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                                <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-high)' }}>
                                  {rec.title}
                                </span>
                                <span
                                  style={{
                                    fontSize: '10px',
                                    fontWeight: 600,
                                    padding: '1px 6px',
                                    borderRadius: 'var(--radius-sm)',
                                    background: 'var(--status-info-bg)',
                                    color: 'var(--accent-primary)',
                                    textTransform: 'uppercase',
                                  }}
                                >
                                  Confidence: {typeof rec.confidence === 'number' ? `${Math.round(rec.confidence * 100)}%` : String(rec.confidence)}
                                </span>
                              </div>
                              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                                {rec.description}
                              </div>
                            </div>

                            <Button
                              variant="primary"
                              size="sm"
                              disabled={createPlanMutation.isPending}
                              onClick={() => createPlanMutation.mutate(rec.recommendation_id)}
                            >
                              <Wrench size={13} />
                              Handoff to Fixes
                            </Button>
                          </div>
                        ))
                      )}
                    </CardBody>
                  </Card>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
export default AIAnalystPage
