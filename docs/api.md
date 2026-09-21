# CloudGuard — API Reference & Contract Specification

## 1. Overview
The CloudGuard API is a RESTful service built on FastAPI. All authenticated endpoints require an `Authorization: Bearer <token>` header. Request correlation is tracked via the `X-Request-ID` HTTP header across all requests and responses.

---

## 2. Route Endpoints & Access Control

### 2.1 System & Authentication
| Method | Endpoint | Access | Required Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | None | Liveness and health check endpoint. |
| `GET` | `/mode` | Public | None | Operating mode (`demo` or `aws`). |
| `POST` | `/auth/login` | Public | None | Exchange credentials for JWT token pair. |
| `POST` | `/auth/refresh` | Public | None | Rotate refresh token for a new access token. |
| `POST` | `/auth/logout` | Authenticated | None | Invalidate current user refresh tokens. |
| `GET` | `/auth/me` | Authenticated | None | Retrieve authenticated user profile & roles. |
| `GET` | `/auth/users` | Authenticated | `users.manage` | List users in the system. |
| `POST` | `/auth/users` | Authenticated | `users.manage` | Create a new user with assigned role. |

### 2.2 Discovery & Posture
| Method | Endpoint | Access | Required Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/scans` | Authenticated | `scans.create` | Initiate an asset discovery & analysis scan. |
| `GET` | `/scans` | Authenticated | `scans.read` | List historical scans with pagination. |
| `GET` | `/scans/{id}` | Authenticated | `scans.read` | Get detailed summary of a specific scan. |
| `GET` | `/findings` | Authenticated | `findings.read` | List security findings with multi-facet filters. |
| `GET` | `/findings/{id}` | Authenticated | `findings.read` | Retrieve complete finding detail and evidence. |
| `GET` | `/findings/{id}/investigation` | Authenticated | `investigation.read` | Tri-partite investigation (Facts, AI Inferences, Guidance). |
| `GET` | `/resources` | Authenticated | `resources.read` | List discovered cloud assets. |
| `GET` | `/rules` | Authenticated | `rules.read` | List security rule catalog (44 rules). |
| `GET` | `/posture` | Authenticated | `posture.read` | Aggregate security posture metrics & risk breakdown. |

### 2.3 Governed Remediation (6-Stage Lifecycle)
| Method | Endpoint | Access | Required Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/remediations/plans?finding_id={id}` | Authenticated | `remediations.create` | Generate deterministic remediation plan. |
| `GET` | `/api/v1/remediations/plans/{id}` | Authenticated | `remediations.read` | Retrieve remediation plan status & parameters. |
| `POST` | `/api/v1/remediations/plans/{id}/validate` | Authenticated | `remediations.validate` | Validate preconditions & safety parameters. |
| `POST` | `/api/v1/remediations/plans/{id}/approve` | Authenticated | `remediations.approve` | Approve plan (Separation of duties enforced). |
| `POST` | `/api/v1/remediations/plans/{id}/execute` | Authenticated | `remediations.execute` | Execute approved strategy against cloud provider. |
| `POST` | `/api/v1/remediations/plans/{id}/verify` | Authenticated | `remediations.read` | Post-remediation verification scan. |
| `GET` | `/api/v1/remediations/audit` | Authenticated | `remediations.read` | Retrieve SHA-256 hash-chained remediation audit logs. |

### 2.4 Policy Automation & Emergency Kill Switch
| Method | Endpoint | Access | Required Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/automation/policies` | Authenticated | `automation.read` | List active automation policies. |
| `POST` | `/api/v1/automation/policies` | Authenticated | `automation.manage` | Create new policy with safety tier & conditions. |
| `GET` | `/api/v1/automation/kill-switch` | Authenticated | `automation.read` | Inspect global emergency kill switch status. |
| `POST` | `/api/v1/automation/kill-switch/enable` | Authenticated | `automation.killswitch` | Activate emergency halt across cluster. |
| `POST` | `/api/v1/automation/kill-switch/disable` | Authenticated | `automation.killswitch` | Restore automation operations. |

### 2.5 Model Context Protocol (MCP) Control Plane
| Method | Endpoint | Access | Required Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/mcp/servers` | Authenticated | `mcp.read` | List registered MCP servers with live health. |
| `GET` | `/api/v1/mcp/tools` | Authenticated | `mcp.read` | List registered MCP tools across servers. |
| `POST` | `/api/v1/mcp/invoke` | Authenticated | `mcp.execute` | Execute governed tool through MCP gateway. |
| `GET` | `/api/v1/mcp/audit` | Authenticated | `mcp.audit_read` | Query MCP invocation audit trail. |

---

## 3. Standard Error Envelope
All error responses return structured JSON:
```json
{
  "detail": "Error description message",
  "error_code": "RESOURCE_NOT_FOUND",
  "request_id": "8f3b2a1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
}
```
Stack traces are never exposed in production error responses.
