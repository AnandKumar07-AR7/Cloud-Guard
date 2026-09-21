# CloudGuard — AI Security Analyst & Agent Orchestration

## 1. Overview & Operational Boundaries
CloudGuard features an AI Security Analyst designed to interpret complex security misconfigurations, synthesize blast radiuses, and recommend remediation steps. 

> [!IMPORTANT]
> **Strict Advisory Boundary**: AI is strictly advisory. AI agents **cannot directly invoke AWS APIs**, **cannot bypass the remediation allowlist**, and **cannot self-approve remediation actions**. Every remediation plan requires human approval or an explicit, policy-governed automation decision.

---

## 2. AI Agent Orchestration Flow

```mermaid
graph TD
    subgraph Trigger["Initiation"]
        Finding[Security Finding Selected]
        User[Security Analyst Request]
        Finding --> User
    end

    subgraph Guardrails["Security & Sanitization Boundary"]
        Sanitizer[Prompt Sanitizer & Secret Redactor]
        TokenLimiter[Token & Context Size Limiter<br/>32 KB Max Context]
        User --> Sanitizer --> TokenLimiter
    end

    subgraph AgentLoop["AIAgentOrchestrator Execution"]
        LLM[Claude Sonnet 4 / Mock AI Provider]
        ToolRouter[Governed Tool Router]
        MCPTools[(MCP Discovery / Security Tools)]

        TokenLimiter --> LLM
        LLM -->|Tool Request| ToolRouter
        ToolRouter -->|Execute Read Tool| MCPTools
        MCPTools -->|Structured Output| ToolRouter
        ToolRouter -->|Max 5 Tool Calls| LLM
    end

    subgraph OutputPipeline["Structured Synthesis & Validation"]
        Validator[Pydantic Schema Output Validator]
        TriPartite[Tri-Partite Investigation Formatter]
        LLM -->|Raw Completion| Validator --> TriPartite
    end

    subgraph HumanGate["Human-in-the-Loop Decision"]
        Facts[Observed Facts]
        Inferences[AI Inferences & Blast Radius]
        Recommendations[Remediation Strategy Guidance]
        DecisionGate{Security Analyst Decision}

        TriPartite --> Facts
        TriPartite --> Inferences
        TriPartite --> Recommendations
        Facts --> DecisionGate
        Inferences --> DecisionGate
        Recommendations --> DecisionGate
        DecisionGate -->|Create Governed Plan| RemediationCenter[Remediation Center Lifecycle]
    end
```

---

## 3. Defense Against Prompt Injection
1. **Untrusted Data Isolation**: All cloud resource tags, bucket names, and IAM policy documents are treated as untrusted strings. They are encapsulated within strictly formatted markdown/JSON tags in the prompt.
2. **Context Window Enforcement**: A hard ceiling of 32,768 bytes (`MAX_AI_CONTEXT_BYTES`) prevents buffer flooding and context manipulation attacks.
3. **Structured Pydantic Parsing**: AI output is forced into typed models (`AIAnalysisResponse`). Free-form arbitrary shell or script output is rejected.
4. **Tool-Call Capping**: Orchestrator terminates agent execution after at most 5 tool calls (`MAX_AI_TOOL_CALLS = 5`) or 15 seconds runtime limit.
