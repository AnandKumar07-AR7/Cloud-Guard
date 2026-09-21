# CloudGuard — Testing, Discovery & Audit Verification

## 1. Overview
CloudGuard maintains rigorous quality and security standards across the full development lifecycle. All core detection, risk quantification, authentication, and remediation behaviors are verified via automated test suites.

- **Backend Baseline**: 778 / 778 tests passing (`pytest` with PostgreSQL 15/16).
- **Frontend Baseline**: 63 / 63 tests passing across 10 test suites (`vitest` with React Testing Library).

---

## 2. Cloud Discovery Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as Security Operator
    participant API as FastAPI Scan Route
    participant ScanSvc as Scan Orchestrator
    participant Provider as Cloud Provider (Demo / AWS)
    participant Engine as Detection Engine (44 Rules)
    participant Risk as Risk Engine
    participant DB as PostgreSQL DB

    User->>API: POST /scans {mode: "demo"}
    API->>ScanSvc: Create Scan Record (Status: DISCOVERING)
    ScanSvc->>Provider: Query Resources (S3, EC2, IAM, Lambda, RDS, VPC)
    Provider-->>ScanSvc: Resource Inventory List
    ScanSvc->>ScanSvc: Transition Status: ANALYZING
    loop For each discovered resource
        ScanSvc->>Engine: Evaluate matching security rules
        Engine->>Engine: Run deterministic rule predicate
        alt Rule Violated
            Engine-->>ScanSvc: Security Finding Created
        end
    end
    ScanSvc->>ScanSvc: Transition Status: RISK_SCORING
    ScanSvc->>Risk: Calculate composite risk scores & posture
    Risk-->>ScanSvc: Aggregated Posture & Risk Metrics
    ScanSvc->>DB: Persist Scan, Resources, Findings & Snapshots
    ScanSvc->>ScanSvc: Transition Status: COMPLETED
    ScanSvc-->>User: 201 Created (ScanSummaryResponse)
```

---

## 3. Cryptographic Audit Trail Flow

```mermaid
graph LR
    subgraph Event["Security Event Occurs"]
        Action["Remediation / Policy / MCP Invocation"]
    end

    subgraph HashCalculation["Cryptographic Hash Computation"]
        PrevHash["Previous Event Hash (H_{n-1})"]
        Payload["Event Data + Timestamp + User ID"]
        Hasher["SHA-256 Hash Function"]

        Action --> Payload
        PrevHash --> Hasher
        Payload --> Hasher
        Hasher --> NewHash["New Event Hash (H_n)"]
    end

    subgraph Ledger["Tamper-Evident Ledger"]
        Row1["Event #1<br/>H_1: a8f9...<br/>Prev: 0000..."]
        Row2["Event #2<br/>H_2: b4c2...<br/>Prev: a8f9..."]
        Row3["Event #3<br/>H_3: e1d8...<br/>Prev: b4c2..."]

        Row1 --> Row2 --> Row3
        NewHash -.-> Row3
    end

    subgraph Verification["Verification Algorithm"]
        ChainCheck{"Verify H_n == SHA256(Payload + H_{n-1})"}
        Valid["Integrity Confirmed: Chain Valid"]
        Tampered["ALERT: Tamper Detected at Sequence #k"]

        Ledger --> ChainCheck
        ChainCheck -->|All match| Valid
        ChainCheck -->|Mismatch| Tampered
    end
```

---

## 4. Running the Master Test Suites

### 4.1 Backend Test Execution
Run the full backend test suite with PostgreSQL:
```bash
cd backend
pytest -v
```
To run with coverage reporting:
```bash
pytest --cov=. --cov-report=term-missing
```

### 4.2 Frontend Test Execution
Run all 63 unit and integration tests:
```bash
cd frontend
npm test -- --run
```
To run type checking and linting:
```bash
npm run build   # Runs tsc -b && vite build
npm run lint    # Runs oxlint
```

### 4.3 End-to-End API Integration Verification
Execute the master E2E verification script:
```bash
python scratch/security_audit_verify.py
```
