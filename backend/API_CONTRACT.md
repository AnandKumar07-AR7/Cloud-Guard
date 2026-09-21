# CloudGuard API Contract (Phase 4)

**Version:** 1.0.0-phase4  
**Mode:** Demo (default) | AWS  
**Base URL:** `http://localhost:8000`

---

## Canonical Rule Inventory (44 Rules)

Historical count discrepancy reconciled: Phase 1/2 had 23 rules. Phase 3 completed full cloud coverage across 7 services totaling 44 unique deterministic rules.

| Service | Count | Rule IDs |
|---|---|---|
| **S3** | 8 | `S3-001` to `S3-008` |
| **IAM** | 8 | `IAM-001` to `IAM-008` |
| **EC2** | 12 | `EC2-001` to `EC2-004`, `SG-001` to `SG-008` |
| **Lambda** | 5 | `LAM-001` to `LAM-005` |
| **RDS** | 4 | `RDS-001` to `RDS-004` |
| **VPC** | 3 | `VPC-001` to `VPC-003` |
| **CloudTrail** | 4 | `CT-001` to `CT-004` |

---

## Authentication

Phase 4: No authentication required.  
Phase 6+ will add JWT/API key authentication.

---

## Common Conventions

| Convention | Value |
|---|---|
| Timestamps | ISO-8601 UTC strings (`2026-09-03T05:08:57.153184+00:00`) |
| Severity | lowercase: `critical` \| `high` \| `medium` \| `low` \| `informational` |
| Scan Status | UPPERCASE: `CREATED` \| `QUEUED` \| `DISCOVERING` \| `ANALYZING` \| `RISK_SCORING` \| `COMPLETED` \| `FAILED` |
| Finding Status | `OPEN` (active) |
| Resource Posture | `SECURE` \| `AT_RISK` \| `HIGH_RISK` \| `CRITICAL` \| `UNKNOWN` |
| Relationship Types | `USES` \| `ASSUMES` \| `ATTACHED_TO` \| `MEMBER_OF` \| `LOCATED_IN` \| `PROTECTED_BY` \| `EXPOSED_THROUGH` \| `DEPENDS_ON` |
| Risk Score | float 0.0–100.0 (100 = maximum risk) |
| Posture Score | float 0.0–100.0 (100 = perfectly secure) |
| Finding Canonical ID | 32-char hex string: SHA-256 hash of `(rule_id, resource_id, account_id, field_path)` |
| Pagination | `limit` + `offset` query params |

---

## Error Response Format

```json
{
  "error_code": "NOT_FOUND",
  "message": "Finding 'xyz' not found.",
  "request_id": "a1b2c3d4",
  "details": null
}
```

---

## Endpoints

### System Endpoints
- `GET /health` — Application health, operating mode, uptime, AI status.
- `GET /mode` — Current operating mode and demo scenario list.

### Scan Endpoints
- `POST /scans` — Initiate scan (`{"scenario": "default|healthy|critical", "enrich_with_ai": false}`).
- `GET /scans` — List paginated scans.
- `GET /scans/{scan_id}` — Get single scan record summary.

### Detection Rule Catalog Endpoints
- `GET /rules` — List detection rules (filterable by `service`, `severity`, `category`).
- `GET /rules/{rule_id}` — Full metadata for a specific rule.

### Finding Endpoints
- `GET /findings` — List findings (filterable by `scan_id`, `service`, `severity`, `category`, `rule_id`, `internet_exposed`).
- `GET /findings/{finding_id}` — Get single finding (supports lookup by UUID or canonical ID).
- `GET /findings/{finding_id}/investigation` — Full investigation context.

### Resource Explorer Endpoints
- `GET /resources` — List discovered cloud resources with security posture, finding counts, and relationships.
- `GET /resources/{resource_id}` — Full resource detail, safe configuration, and all associated findings.

### Security Posture Endpoints
- `GET /posture` — Aggregate security posture score, risk level, service posture breakdown, and resource counts.

---

## Finding Investigation Schema (`GET /findings/{finding_id}/investigation`)

```json
{
  "finding": {
    "finding_id": "971aea67-...",
    "canonical_id": "b9688d08...",
    "rule_id": "SG-001",
    "rule_version": "1.0",
    "resource_id": "sg-0a1b2c3d4e5f67890",
    "resource_name": "acme-web-servers",
    "service": "ec2",
    "severity": "high",
    "risk_score": 86.4,
    "status": "OPEN",
    "internet_exposed": true,
    "security_context": {
      "internet_exposed": true,
      "publicly_accessible": true,
      "network_exposure": true
    },
    "risk_context": {
      "base_score": 72.0,
      "severity_factor": "high",
      "internet_exposure_applied": true,
      "internet_exposure_factor": 1.2,
      "final_score": 86.4,
      "rationale": "Base score (high): 72 -> Internet exposure: x1.2 (+20%) -> Final score: 86.4/100"
    }
  },
  "rule": { "rule_id": "SG-001", "name": "...", "severity": "high" },
  "resource": { "resource_id": "sg-0a1b2c3d4e5f67890", "config": { ... } },
  "evidence": {
    "rule_id": "SG-001",
    "field_path": "config.inbound_rules[2].cidr",
    "observed_value": "0.0.0.0/0",
    "expected_value": "restricted CIDR",
    "summary": "Field 'config.inbound_rules[2].cidr' is '0.0.0.0/0' (expected: 'restricted CIDR')"
  },
  "related_resources": [
    { "resource_id": "i-0a1b2c3d4e5f67890", "resource_type": "ec2_instance", "service": "ec2" }
  ],
  "related_findings": [ ... ],
  "ai_analysis": {
    "ai_source": "template",
    "executive_summary": "...",
    "technical_analysis": "...",
    "business_impact": "...",
    "attack_relevance": "...",
    "recommended_action": "...",
    "confidence": "high",
    "observed_facts": [ ... ],
    "ai_inferences": [ ... ]
  },
  "remediation_context": {
    "available": true,
    "safety": "REVIEW_REQUIRED",
    "recommended_action": "...",
    "affected_fields": ["config.inbound_rules[2].cidr"]
  },
  "compliance_context": {
    "references": [
      { "framework": "CIS", "control_id": "CIS-4.1" }
    ]
  }
}
```

---

## Security Guarantees

- **No secret leakage:** Passwords, private keys, database credentials, and AWS access tokens are masked with `[MASKED]` / `[REDACTED]` before appearing in any API response or AI prompt.
- **No fabricated graph edges:** Relationships are only derived when explicitly declared in resource configuration.
- **Deterministic findings:** All findings come from pure Python rules executing on collected resource state.
- **Separation of Fact and Inference:** AI analysis strictly separates `observed_facts` from `ai_inferences`.

---

## Phase 10: Model Context Protocol (MCP) Control Plane

The Model Context Protocol (MCP) layer establishes a bounded, observable, and audited interface for AI agents and external tools to interact with CloudGuard discovery, security posture, and remediation orchestration without bypassing CloudGuard's security hierarchy.

### Control Plane Endpoints

| Method | Path | Permission Required | Description |
|---|---|---|---|
| `GET` | `/api/v1/mcp/servers` | `mcp.read` | List registered MCP servers with live health, status, and metrics. |
| `GET` | `/api/v1/mcp/servers/{server_id}` | `mcp.read` | Get detailed metadata for a specific MCP server. |
| `GET` | `/api/v1/mcp/servers/{server_id}/tools` | `mcp.read` | List all tools exposed by an MCP server with schemas. |
| `GET` | `/api/v1/mcp/servers/{server_id}/health` | `mcp.read` | Retrieve live health metrics and error statistics. |
| `POST` | `/api/v1/mcp/servers/{server_id}/toggle` | `mcp.manage` | Admin endpoint to enable or disable an MCP server. |
| `GET` | `/api/v1/mcp/tools` | `mcp.read` | List all registered MCP tools across all servers. |
| `GET` | `/api/v1/mcp/audit` | `mcp.audit.read` | Query tamper-evident MCP audit logs with SHA-256 chain. |
| `POST` | `/api/v1/mcp/invoke` | `mcp.execute` | Invoke an authorized MCP tool via the secure MCP gateway. |

### Tool Operation Classification & RBAC

Every MCP tool is strictly classified:
- `READ`: Information retrieval (e.g. `list_resources`, `get_finding`, `get_risk_context`).
- `WRITE`: Safe, governed state modifications (e.g. `create_remediation_plan`, `validate_remediation_plan`, `request_approval`).
- `DESTRUCTIVE`: Blocked at the MCP boundary. Never exposed to AI agents.

### MCP Invocations (`POST /api/v1/mcp/invoke`)

**Request Payload:**
```json
{
  "server_id": "cloudguard-discovery-mcp",
  "tool_name": "list_resources",
  "arguments": {
    "service": "s3",
    "limit": 10
  }
}
```

**Response Payload:**
```json
{
  "success": true,
  "data": {
    "items": [ ... ],
    "count": 10,
    "limit": 10,
    "offset": 0
  },
  "error": null,
  "execution_time_ms": 14,
  "request_id": "3b2c1a0f-..."
}
```

### Security & Audit Guarantees
- **No Security Bypass:** MCP adheres strictly to CloudGuard RBAC, Phase 7 remediation state machines, and Phase 9 policy governance (kill-switch, blast radius, separation of duties).
- **Strict Input Validation:** Tool parameters are strictly validated against Pydantic schemas forbidding unknown fields (`extra="forbid"`).
- **Tamper-Evident Audit Chain:** Every invocation produces an append-only audit event with cryptographic SHA-256 hash chaining.
- **Strict Secret Redaction:** AWS credentials, JWT tokens, and database passwords are sanitized before audit persistence.
- **Fail-Closed:** Any ambiguous authorization, disabled server, or unrecognized tool immediately blocks execution.
