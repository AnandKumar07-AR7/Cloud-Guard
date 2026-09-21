# CloudGuard — Architecture Documentation

## 1. Executive Summary
CloudGuard is an AI-powered cloud misconfiguration detection, risk quantification, and policy-governed automated remediation system. It provides real-time visibility across multi-service AWS architectures, quantifies infrastructure risk through deterministic mathematical scoring, and delivers governed, tamper-evident remediation actions via human-in-the-loop and automated workflows.

---

## 2. System Architecture Overview

```mermaid
graph TB
    subgraph Client["Presentation Layer — Obsidian Command Center"]
        UI["React 18 + TypeScript + Vite SPA<br/>Obsidian Theme & Design System"]
        Router["React Router v6"]
        Query["TanStack React Query (State Cache)"]
        Axios["Axios Client (Auth Interceptors, X-Request-ID)"]
        UI --> Router --> Query --> Axios
    end

    subgraph Gateway["API Gateway & Ingress Layer"]
        FastAPI["FastAPI Application (Port 8000)"]
        CORS["CORS Middleware (Whitelisted Origins)"]
        ReqID["Correlation ID Middleware (X-Request-ID)"]
        AuthMid["JWT & RBAC Dependency Injection"]
        FastAPI --> CORS --> ReqID --> AuthMid
    end

    subgraph Services["Core Application Services"]
        ScanSvc["Scan & Discovery Service"]
        FindingsSvc["Findings & History Service"]
        RemediationSvc["Remediation Service (6-Stage Lifecycle)"]
        AISvc["AI Security Analyst & Agent Orchestration"]
        MCPSvc["MCP Control Plane & Gateway"]
        AutoSvc["Policy Automation Engine & Kill Switch"]
    end

    subgraph Engines["Deterministic Security Engines"]
        DetectEng["Detection Engine (44 Security Rules)"]
        RiskEng["Risk Engine (Composite Score Formula)"]
        RemedEng["Remediation Strategy Registry (Allowlist)"]
    end

    subgraph Persistence["Persistence & Infrastructure"]
        Postgres[(PostgreSQL 15/16 Relational DB)]
        Alembic["Alembic Migration Engine (Head: c0d1e2f3a4b5)"]
        AuditTrail["Tamper-Evident SHA-256 Hash Chain"]
    end

    subgraph Providers["Cloud Providers"]
        DemoProv["DemoProvider (Deterministic Mock Cloud)"]
        AWSProv["AWSProvider (Boto3 / Real AWS APIs)"]
    end

    Axios -->|"HTTP/JSON + Bearer Token"| FastAPI
    AuthMid --> Services
    ScanSvc --> DetectEng --> RiskEng
    RemediationSvc --> RemedEng
    Services --> Persistence
    ScanSvc --> Providers
    RemediationSvc --> Providers
    AuditTrail --> Postgres
```

---

## 3. Core Architectural Principles

1. **Deterministic Core with Advisory AI**: Security rules, risk calculations, policy evaluations, and remediation strategies execute with mathematical determinism. Generative AI is strictly advisory and cannot execute cloud mutations directly.
2. **Strict Remediation Allowlist**: Remediation is limited to explicitly validated and safe strategies (`S3-001`, `SG-001`). Unrecognized or generic remediation requests are blocked at the engine boundary.
3. **Defense-in-Depth Authorization**: Every backend endpoint enforces server-side RBAC using JWT bearer tokens and Argon2id password verification. Client-side role visibility is purely UX ergonomics.
4. **Append-Only Tamper-Evident Auditability**: All security actions, policy progressions, and MCP invocations generate cryptographic audit events chained via SHA-256 hashes (`previous_hash` + event contents -> `event_hash`).
5. **Separation of Duties**: The creator of a remediation plan cannot approve their own plan in environments requiring separation of duties.
6. **Fail-Closed Emergency Protection**: The global automation kill switch immediately halts all automated remediation progressions and policy executions.
