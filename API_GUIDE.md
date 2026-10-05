# BAP Control Plane (`bapcontrolplane`) REST API Guide

This document is the complete REST API specification for **`bapcontrolplane`**, the central Bounded Authority Plane governance service.

`bapcontrolplane` is **strictly API-based (no UI)**. All endpoints accept and return JSON. The registration flow is designed for frictionless self-service onboarding: app owners can pre-register unauthenticated or with standard service tokens, receive a single-use high-entropy One-Time Code (OTC), and edge brokers (**`bapedge`**, the Local Trusted Daemon) authenticate and enroll by consuming the OTC alongside cryptographic binary attestation.

---

## 1. Quick Reference: Endpoints Table

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service liveness & health check | None |
| `POST` | `/api/v1/agents/pre-register` | Pre-register agent/fleet & mint OTC or fleet token | None (Self-Service) |
| `POST` | `/api/v1/agents/register` | Edge LTD enrollment, binary attestation & SPIFFE SVID | One-Time Code / Fleet Token |
| `GET` | `/api/v1/agents` | List all registered agents and attestation status | None |
| `POST` | `/api/v1/grants/acquire` | Mint short-lived OBO JWT authority grants (with SPIFFE ID) | Attested Agent ID |
| `POST` | `/api/v1/grants/consume` | Downstream PEP atomic grant consumption | Bearer Token |
| `GET` | `/api/v1/policy/bundle` | Get current authoritative Cedar policy & schema | None |
| `POST` | `/api/v1/policy/sync` | Edge LTD policy synchronization & directives | None |
| `POST` | `/api/v1/audit/ingest` | Central ingestion for edge audit logs | None |
| `GET` | `/api/v1/audit/events` | Inspect central tamper-evident audit chain | None |
| `POST` | `/api/v1/agents/revoke` | Emergency kill-switch revoking a specific agent instance | None |
| `POST` | `/api/v1/apps/revoke` | Emergency kill-switch revoking an entire fleet/app | None |
| `POST` | `/api/v1/instances/heartbeat`| Edge agent instance liveness heartbeat | Agent ID |
| `POST` | `/api/v1/sessions/start` | Start an agent execution session (Claude Code, Copilot, CLI) | None |
| `POST` | `/api/v1/sessions/prompt` | Submit locally classified Claude mission context; raw prompt optional | Prototype hook contract |
| `POST` | `/api/v1/sessions/end` | Record conclusion or shutdown of an agent session | None |
| `GET` | `/api/v1/sessions` | List recent agent execution sessions with stats | None |
| `GET` | `/api/v1/sessions/{id}` | Retrieve details and stats for a specific session | None |
| `GET` | `/api/v1/inspector/data` | Unified polling endpoint for Inspector UI | None |
| `POST` | `/api/v1/auth/otc/dev-request` | Auto-mint OTC for local developers (dev mode only) | None (Dev Only, 403 in Prod) |
| `GET` | `/api/v1/auth/oidc/config` | Public OIDC provider configuration & discovery | None |
| `POST` | `/api/v1/auth/oidc/device-code` | Initiate RFC 8628 Device Authorization Flow | None |
| `POST` | `/api/v1/auth/oidc/device-token` | Poll for RFC 8628 device token authorization | Device Code |
| `POST` | `/api/v1/auth/oidc/device-verify` | Verify & approve device session with corporate IdP claims | MFA / Corporate User |
| `POST` | `/api/activity/ingest` | Ingest canonical AgentActivityEvent | None / Edge Client |
| `GET` | `/api/activity/live` | Query currently active agent sessions & status | None / RBAC Redacted |
| `GET` | `/api/activity/summary` | Aggregate workforce KPIs (active agents, governed %, BU active) | None / RBAC Redacted |
| `GET` | `/api/activity/intents` | Intent category distributions & sub-intent drill-downs | None / RBAC Redacted |
| `GET` | `/api/activity/business-units` | Business unit activity counts and risk postures | None / RBAC Redacted |
| `GET` | `/api/activity/topology` | Enterprise activity topology hierarchy tree | None / RBAC Redacted |
| `GET` | `/api/activity/stream` | Real-time Server-Sent Events (SSE) stream of activity events | None / RBAC Redacted |
| `GET` | `/api/activity/deviation` | Evaluate intent-to-action contract & deviation level | None |

---

## 2. Server Startup & HTTPS/TLS Configuration

Compile and start the BAP Control Plane daemon:
```cmd
cd bap-controlplane
go build -o bapcontrolplane.exe ./cmd/server
```

### Standard HTTP (Development / Internal Mesh)
```cmd
# Development mode (self-service OTC permitted):
.\bapcontrolplane.exe -port 8080 -mode dev -trust-domain bap.internal
```

### Secure HTTPS / TLS (Production Mode with OIDC Federation)
```cmd
# Production mode with Microsoft Entra ID or Okta IdP federation:
.\bapcontrolplane.exe -port 8443 -mode prod \
  -tls -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem \
  -oidc-provider entra \
  -oidc-issuer https://login.microsoftonline.com/your-tenant-id/v2.0 \
  -oidc-client-id your-entra-client-id \
  -oidc-tenant-id your-tenant-id \
  -oidc-allowed-domains "company.com,subsidiary.com" \
  -trust-domain bap.internal

# In production mode:
# - Self-service OTC endpoint (/api/v1/auth/otc/dev-request) returns HTTP 403 Forbidden.
# - Out-of-band admin pre-registration requires X-BAP-Admin-Token header.
# - Interactive engineers enroll via RFC 8628 OIDC device flow (MFA authenticated).
```

---

## 3. Endpoints Detail

### 3.1. Health Check
Checks if `ltd-service` is healthy and ready.
- **Method**: `GET`
- **Path**: `/api/v1/health`
- **Example Request**:
  ```bash
  curl -s http://localhost:8080/api/v1/health
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "service": "ltd-service-control-plane",
    "status": "ok"
  }
  ```

---

### 3.2. Pre-Register Agent (Mint One-Time Code)
App owners self-register an agent definition. Generates a short-lived, high-entropy single-use registration code (`LTD-OTC-XXXX-XXXX`).
- **Method**: `POST`
- **Path**: `/api/v1/agents/pre-register`
- **Request Body**:
  ```json
  {
    "app_id": "payments-worker",
    "owner_email": "alice@company.internal",
    "agent_name": "BillingReconciler",
    "env_profile": "production",
    "allowed_binary_hashes": [
      "4e75b1590ef4ac3a871ba7ed2075f32d7a4cfbad773e700b583fcb4643d709fb"
    ],
    "permitted_scopes": ["cli:exec", "billing:reconcile"],
    "ttl_minutes": 15
  }
  ```
  *Parameters:*
  - `app_id` (string, required): Application identifier.
  - `agent_name` (string, required): Descriptive name of agent.
  - `owner_email` (string, optional): Owner contact email.
  - `env_profile` (string, optional): `"production"` (strict hash whitelist) or `"development"` (TOFU / flexible). Default: `"development"`.
  - `allowed_binary_hashes` (array of strings, required in prod): Authorized SHA-256 binary checksums.
  - `permitted_scopes` (array of strings, optional): Scopes granted to this agent.
  - `ttl_minutes` (int, optional): Expiry time for the one-time code in minutes (default 15).
- **Example Request**:
  ```bash
  curl -s -X POST http://localhost:8080/api/v1/agents/pre-register \
    -H "Content-Type: application/json" \
    -d '{
      "app_id": "payments-worker",
      "owner_email": "alice@company.internal",
      "agent_name": "BillingReconciler",
      "env_profile": "development",
      "permitted_scopes": ["cli:exec", "billing:read"]
    }'
  ```
- **Example Response** (`201 Created`):
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402",
    "one_time_code": "LTD-OTC-63523708-33895c03",
    "expires_at": "2026-09-12T10:45:00Z"
  }
  ```

---

### 3.3. Edge Agent Registration & Attestation
Called once by the edge agent to enroll. It consumes and burns the one-time code, validates the executing binary hash against the environment profile, and records host metadata.
- **Method**: `POST`
- **Path**: `/api/v1/agents/register`
- **Request Body**:
  ```json
  {
    "one_time_code": "LTD-OTC-63523708-33895c03",
    "binary_hash": "4e75b1590ef4ac3a871ba7ed2075f32d7a4cfbad773e700b583fcb4643d709fb",
    "hostname": "prod-node-04",
    "os": "windows",
    "arch": "amd64",
    "public_key": ""
  }
  ```
- **Example Request (CLI or curl)**:
  ```bash
  # Using ltd-agent CLI:
  ltd-agent register --server http://localhost:8080 --code LTD-OTC-63523708-33895c03

  # Or using raw curl:
  curl -s -X POST http://localhost:8080/api/v1/agents/register \
    -H "Content-Type: application/json" \
    -d '{
      "one_time_code": "LTD-OTC-63523708-33895c03",
      "binary_hash": "4e75b1590ef4ac3a871ba7ed2075f32d7a4cfbad773e700b583fcb4643d709fb",
      "hostname": "prod-node-04",
      "os": "windows",
      "arch": "amd64"
    }'
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402",
    "app_id": "payments-worker",
    "status": "active",
    "server_time": "2026-09-12T10:31:00Z",
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```
- **Replay Protection**: Re-submitting an already-consumed OTC returns `401 Unauthorized`:
  ```json
  {"error": "Enrollment failed: one-time code has already been consumed (replay attempt blocked)"}
  ```

---

### 3.4. List Registered Agents
Lists all registered agents in the control plane state store.
- **Method**: `GET`
- **Path**: `/api/v1/agents`
- **Example Request**:
  ```bash
  curl -s http://localhost:8080/api/v1/agents
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "count": 1,
    "agents": [
      {
        "agent_id": "agent-payments-worker-9fa1b402",
        "app_id": "payments-worker",
        "owner_email": "alice@company.internal",
        "agent_name": "BillingReconciler",
        "env_profile": "development",
        "status": "active",
        "enrolled_binary_hash": "4e75b1590ef4ac3a871ba7ed2075f32d7a4cfbad773e700b583fcb4643d709fb",
        "hostname": "prod-node-04",
        "os": "windows",
        "arch": "amd64",
        "created_at": "2026-09-12T10:30:00Z",
        "enrolled_at": "2026-09-12T10:31:00Z"
      }
    ]
  }
  ```

---

### 3.5. Acquire Short-Lived Authority Grant
Edge agent requests a signed, short-lived OBO JWT authority token (TTL 15–60 mins) bound to its attested binary hash and allowed scopes.
- **Method**: `POST`
- **Path**: `/api/v1/grants/acquire`
- **Request Body**:
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402",
    "binary_hash": "4e75b1590ef4ac3a871ba7ed2075f32d7a4cfbad773e700b583fcb4643d709fb",
    "scopes": ["cli:exec"]
  }
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJncmFudC03ZmQ5YjJkMSIsInN1YiI6ImFnZW50LXBheW1lbnRzLXdvcmtlci05ZmExYjQwMiIsImFwcF9pZCI6InBheW1lbnRzLXdvcmtlciIsInNjb3BlcyI6WyJjbGk6ZXhlYyJdLCJleHAiOjE3ODkxODA2NjB9...",
    "token_type": "Bearer",
    "expires_at": "2026-09-12T11:01:00Z",
    "expires_in": 1800,
    "scopes": ["cli:exec"]
  }
  ```

---

### 3.6. Consume Grant (Resource PEP / API Gateway Interface)
Downstream API Gateways or resource PEPs validate and atomically consume a short-lived grant to prevent replay attacks and verify the target resource.
- **Method**: `POST`
- **Path**: `/api/v1/grants/consume`
- **Request Body**:
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "resource": "cli:exec"
  }
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "consumed": true,
    "grant_id": "grant-7fd9b2d1",
    "agent_id": "agent-payments-worker-9fa1b402",
    "app_id": "payments-worker",
    "scopes": ["cli:exec"],
    "expires_at": 1789180660
  }
  ```
- **Replay Protection**: Subsequent consumption of the same grant ID returns `403 Forbidden`:
  ```json
  {"error": "Grant consumption failed: grant grant-7fd9b2d1 has already been consumed (replay blocked)"}
  ```

---

### 3.7. Central Policy Bundle & Remote Sync
Enables central security teams to distribute updated Cedar policies and schemas without touching edge agents.

#### Get Active Bundle
- **Method**: `GET`
- **Path**: `/api/v1/policy/bundle`
- **Example Response** (`200 OK`):
  ```json
  {
    "version": 1,
    "digest": "b8a91ec5f79b32e6...",
    "policy_cedar": "permit(principal, action, resource);",
    "schema_json": "{...}",
    "kill_switch": false,
    "updated_at": "2026-09-12T10:00:00Z"
  }
  ```

#### Edge Sync Policy
- **Method**: `POST`
- **Path**: `/api/v1/policy/sync`
- **Request Body**:
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402",
    "installed_version": 1,
    "installed_digest": "b8a91ec5f79b32e6..."
  }
  ```
- **Responses by Directive**:
  1. **Up-to-Date** (`CURRENT`):
     ```json
     {
       "directive": "CURRENT"
     }
     ```
  2. **Update Available** (`UPDATE_REQUIRED`):
     ```json
     {
       "directive": "UPDATE_REQUIRED",
       "bundle": {
         "version": 2,
         "digest": "c9b20...",
         "policy_cedar": "permit(...) forbid(...);",
         "schema_json": "{...}",
         "kill_switch": false,
         "updated_at": "2026-09-12T10:30:00Z"
       }
     }
     ```
  3. **Emergency Lock** (`KILL_SWITCH`):
     ```json
     {
       "directive": "KILL_SWITCH",
       "bundle": { "kill_switch": true }
     }
     ```

---

### 3.8. Central Audit Ingestion & Tamper-Evident Chain
Edge agents stream their execution decisions and telemetry into the central control plane. Central storage cryptographically links records via SHA-256 hash chaining.

#### Ingest Audit Events
- **Method**: `POST`
- **Path**: `/api/v1/audit/ingest`
- **Request Body**: Single object or array of event objects:
  ```json
  [
    {
      "event_id": "ev-edge-001",
      "session_id": "sess-claude-20260912-140000",
      "timestamp": "2026-09-12T10:14:00Z",
      "source": "claude-code",
      "executable": "git",
      "arguments": "status",
      "full_command": "git status",
      "decision": "allow",
      "duration_ms": 35,
      "exit_code": 0
    },
    {
      "event_id": "ev-edge-002",
      "session_id": "sess-claude-20260912-140000",
      "timestamp": "2026-09-12T10:14:05Z",
      "source": "claude-code",
      "executable": "cat",
      "arguments": ".env",
      "full_command": "cat .env",
      "decision": "deny",
      "reason": "policy policy1",
      "duration_ms": 2,
      "exit_code": 1
    }
  ]
  ```
- **Example Response** (`200 OK` - Clean Cryptographic Handshake):
  ```json
  {
    "ingested": 2,
    "chain_valid": true,
    "receipt_hash": "a59b34f8263de7890b561c29e4d0725a33b018591ef8634c01d4a8e630f9a721",
    "status": "acknowledged"
  }
  ```

#### Inspect Central Audit Chain
- **Method**: `GET`
- **Path**: `/api/v1/audit/events`
- **Example Response** (`200 OK`):
  ```json
  {
    "count": 2,
    "chain_status": "valid",
    "events": [
      {
        "event_id": "ev-edge-001",
        "timestamp": "2026-09-12T10:14:00Z",
        "source": "claude-code",
        "executable": "git",
        "full_command": "git status",
        "decision": "allow",
        "exit_code": 0,
        "previous_hash": "genesis-bapltd-control-plane",
        "event_hash": "a59b34f8..."
      },
      {
        "event_id": "ev-edge-002",
        "timestamp": "2026-09-12T10:14:05Z",
        "source": "claude-code",
        "executable": "cat",
        "full_command": "cat .env",
        "decision": "deny",
        "reason": "policy policy1",
        "exit_code": 1,
        "previous_hash": "a59b34f8...",
        "event_hash": "f81c9a02..."
      }
    ]
  }
  ```

---

### 3.9. Remote Kill-Switch (Single Agent Revocation)
Immediately marks a specific agent instance as `revoked`. Once revoked, all subsequent grant acquisitions are denied with `403 Forbidden`.
- **Method**: `POST`
- **Path**: `/api/v1/agents/revoke`
- **Request Body**:
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402"
  }
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402",
    "status": "revoked",
    "message": "Agent has been revoked. All subsequent grants will be denied."
  }
  ```

---

### 3.10. Fleet-Wide App Kill-Switch (Revoke All App Instances)
Immediately revokes **all** active agent instances belonging to a target application (`app_id`).
- **Method**: `POST`
- **Path**: `/api/v1/apps/revoke`
- **Request Body**:
  ```json
  {
    "app_id": "payments-worker"
  }
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "app_id": "payments-worker",
    "revoked_count": 5,
    "status": "revoked"
  }
  ```

---

### 3.11. Instance Liveness Heartbeat
Edge agent instances periodically send liveness heartbeats to maintain active status and update `last_heartbeat_at`.
- **Method**: `POST`
- **Path**: `/api/v1/instances/heartbeat`
- **Request Body**:
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402-worker-01"
  }
  ```json
  {
    "agent_id": "agent-payments-worker-9fa1b402-worker-01",
    "status": "alive",
    "time": "2026-09-12T10:35:00Z"
  }
  ```

---

### 3.12. Agent Session Lifecycle Engine & Live Radar Endpoints
The Session Engine tracks discrete agent execution sessions (Claude Code interactive sessions, GitHub Copilot CLI runs, automated worker workflows), providing real-time presence detection and session-level metrics.

#### Start Session
- **Method**: `POST`
- **Path**: `/api/v1/sessions/start`
- **Request Body**:
  ```json
  {
    "session_id": "sess-claude-20260912-140000",
    "source": "claude-code",
    "pid": 14208,
    "model": "claude-3-5-sonnet-20241022",
    "cwd": "C:\\Users\\User\\pyprj\\bapltd"
  }
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "status": "started",
    "session": {
      "session_id": "sess-claude-20260912-140000",
      "source": "claude-code",
      "pid": 14208,
      "model": "claude-3-5-sonnet-20241022",
      "started_at": "2026-09-12T14:00:00Z",
      "status": "active",
      "total_events": 0,
      "allow_count": 0,
      "deny_count": 0
    }
  }
  ```

#### Submit Claude Mission Context

- **Method**: `POST`
- **Path**: `/api/v1/sessions/prompt`
- **Producer**: the managed Claude Code `UserPromptSubmit` hook through BAP Edge
- **Request Body**:
  ```json
  {
    "session_id": "sess-claude-20260912-140000",
    "producer": "claude-lifecycle-hook",
    "user_prompt": "Fix the login bug and update the database schema",
    "prompt_hash": "7cb8d5d32db030d0bf4e9f57933078b5fb7cb91b38d92c1914975436d6c1621b",
    "prompt_capture_enabled": true,
    "intent": {
      "primary": "BUG_FIX",
      "secondary": ["DATABASE_CHANGE"],
      "tags": ["DATABASE"],
      "confidence": 0.98,
      "classifier_version": "bap-intent-rules-v1",
      "source": "claude-user-prompt-submit",
      "evidence": ["BUG_FIX:fix the bug", "DATABASE_CHANGE:update database"]
    }
  }
  ```

`intent.primary` is mandatory and may be `UNKNOWN`. If endpoint policy disables raw prompt capture, `user_prompt` is omitted and `prompt_capture_enabled` is `false`; the normalized intent and prompt hash are still required. Intent is observability context and is not accepted as authority for an operation.

The current repository validates the hook contract but does not yet cryptographically authenticate this endpoint. Production edge authentication is tracked as `BAP-221`.

#### End Session
- **Method**: `POST`
- **Path**: `/api/v1/sessions/end`
- **Request Body**:
  ```json
  {
    "session_id": "sess-claude-20260912-140000",
    "status": "completed"
  }
  ```
- **Example Response** (`200 OK`):
  ```json
  {
    "status": "ended",
    "session": {
      "session_id": "sess-claude-20260912-140000",
      "status": "completed",
      "started_at": "2026-09-12T14:00:00Z",
      "ended_at": "2026-09-12T14:15:30Z",
      "duration_sec": 930.25,
      "total_events": 14,
      "allow_count": 12,
      "deny_count": 2
    }
  }
  ```

#### List Sessions
- **Method**: `GET`
- **Path**: `/api/v1/sessions`
- **Example Response** (`200 OK`):
  ```json
  {
    "count": 2,
    "sessions": [
      {
        "session_id": "sess-claude-20260912-140000",
        "source": "claude-code",
        "pid": 14208,
        "model": "claude-3-5-sonnet-20241022",
        "started_at": "2026-09-12T14:00:00Z",
        "status": "active",
        "total_events": 14,
        "allow_count": 12,
        "deny_count": 2
      }
    ]
  }
  ```

#### Get Session Detail
- **Method**: `GET`
- **Path**: `/api/v1/sessions/{id}`
- **Example Response** (`200 OK`):
  ```json
  {
    "session": {
      "session_id": "sess-claude-20260912-140000",
      "source": "claude-code",
      "status": "active",
      "total_events": 14,
      "allow_count": 12,
      "deny_count": 2
    }
  }
  ```

#### Inspector Unified Polling Data
- **Method**: `GET`
- **Path**: `/api/v1/inspector/data`
- **Example Response** (`200 OK`):
  ```json
  {
    "events": [ ... ],
    "chain_status": "valid",
    "sessions": [ ... ]
  }
  ```

---

### 3.12. Enterprise Identity Provider Federation & OIDC Device Flow

BAP natively federates with enterprise Identity Providers (Okta, Microsoft Entra ID, Ping, Google Workspace) via RFC 8628 OAuth 2.0 Device Authorization Grant.

#### 3.12.1. Dev Mode One-Time Code Auto-Mint
In `dev` mode (`-mode dev`), allows local developers to bootstrap an OTC without manual admin intervention. In `prod` mode (`-mode prod`), this endpoint strictly returns `403 Forbidden`.
- **Method**: `POST`
- **Path**: `/api/v1/auth/otc/dev-request`
- **Request Body**:
  ```json
  {
    "app_id": "claude-code-dev",
    "agent_name": "LocalDeveloperAgent",
    "owner_email": "developer@local.internal"
  }
  ```
- **Example Response (`200 OK` in Dev Mode)**:
  ```json
  {
    "code": "LTD-OTC-A1B2-C3D4",
    "app_id": "claude-code-dev",
    "expires_at": "2026-10-04T18:00:00Z"
  }
  ```
- **Example Response (`403 Forbidden` in Prod Mode)**:
  ```json
  {
    "error": "dev-request is disabled in production mode; offline admin registration or OIDC login required"
  }
  ```

#### 3.12.2. Public OIDC Configuration Discovery
Clients query the active IdP federation configuration and RFC 8628 device flow endpoints. Client secrets are never exposed.
- **Method**: `GET`
- **Path**: `/api/v1/auth/oidc/config`
- **Example Response (`200 OK`)**:
  ```json
  {
    "enabled": true,
    "provider": "entra",
    "issuer": "https://login.microsoftonline.com/tenant-id/v2.0",
    "client_id": "00000000-0000-0000-0000-000000000000",
    "device_auth_endpoint": "https://controlplane.company.internal/api/v1/auth/oidc/device-code",
    "token_endpoint": "https://controlplane.company.internal/api/v1/auth/oidc/device-token",
    "allowed_domains": ["company.com", "partner.org"],
    "claim_mappings": {
      "department": "department",
      "email": "user_email",
      "groups": "groups"
    }
  }
  ```

#### 3.12.3. Initiate RFC 8628 Device Authorization
Initializes an interactive MFA login flow for the developer's CLI agent workstation.
- **Method**: `POST`
- **Path**: `/api/v1/auth/oidc/device-code`
- **Request Body**:
  ```json
  {
    "client_id": "bapedge-cli",
    "scope": "openid profile email department"
  }
  ```
- **Example Response (`200 OK`)**:
  ```json
  {
    "device_code": "devcode-a83f9c0e48a17d23",
    "user_code": "WDJB-MJHT",
    "verification_uri": "https://controlplane.company.internal/device",
    "verification_uri_complete": "https://controlplane.company.internal/device?user_code=WDJB-MJHT",
    "expires_in": 900,
    "interval": 5
  }
  ```

#### 3.12.4. Poll Device Token
The edge daemon polls this endpoint while the engineer completes browser MFA authentication.
- **Method**: `POST`
- **Path**: `/api/v1/auth/oidc/device-token`
- **Request Body**:
  ```json
  {
    "device_code": "devcode-a83f9c0e48a17d23",
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
  }
  ```
- **Pending Response (`400 Bad Request` per RFC 8628 §3.5)**:
  ```json
  {
    "error": "authorization_pending"
  }
  ```
- **Success Response (`200 OK` once user completes MFA)**:
  ```json
  {
    "access_token": "bap_idp_tok_89f02c4819d...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user_email": "alice@company.com",
    "department": "Finance",
    "groups": ["ai-developers", "finance-reconcilers"]
  }
  ```

#### 3.12.5. Approve Device Verification (IdP Callback / MFA Approval)
Internal or IdP callback endpoint verifying the developer's corporate identity and passing validated directory claims into the active session.
- **Method**: `POST`
- **Path**: `/api/v1/auth/oidc/device-verify`
- **Request Body**:
  ```json
  {
    "user_code": "WDJB-MJHT",
    "user_email": "alice@company.com",
    "department": "Finance",
    "groups": ["ai-developers", "finance-reconcilers"]
  }
  ```
- **Example Response (`200 OK`)**:
  ```json
  {
    "status": "approved",
    "user_email": "alice@company.com"
  }
  ```

---

### 3.13. Canonical Agent Activity & Persona Telemetry (Epic 28)

These endpoints provide real-time, privacy-safe telemetry for the Agent Watch persona architecture (CIO, CISO, SRE/Ops, IT Enablement) and power the Workforce Pulse, Live Agent Map, and Intent Contract.

#### 3.13.1. Ingest Canonical Activity Event
Ingests a normalized `AgentActivityEvent` from edge interceptors (`cchook`, `copilot`) or agent runtimes (`bapedge`).
- **Method**: `POST`
- **Path**: `/api/activity/ingest` (or `/api/v1/activity/ingest`)
- **Request Body**:
  ```json
  {
    "timestamp": "2026-10-05T09:00:00Z",
    "session_id": "sess-live-01",
    "agent_id": "agent-claude-pay01",
    "agent_type": "claude-code",
    "runtime_id": "macbook-pro-419",
    "user_id": "dev@enterprise.internal",
    "business_unit": "Payments Engineering",
    "application": "checkout-api",
    "prompt_id": "prmpt-81923",
    "prompt_summary": "Investigating checkout latency spike following deployment",
    "intent": "PRODUCTION_DIAGNOSIS",
    "intent_category": "Investigate / Diagnose",
    "action": "kubectl logs -n prod deploy/checkout-api --tail=100",
    "tool": "kubectl",
    "target_resource": "k8s://prod/checkout-api",
    "data_classification": "Internal",
    "policy_decision": "ALLOW",
    "risk_score": 0.12,
    "grant_id": "zsp-pay-read-991",
    "grant_scope": "read:observability",
    "grant_ttl": 300,
    "action_status": "working",
    "outcome_category": "Success",
    "trace_id": "tr-pay-8192301"
  }
  ```
- **Example Response (`200 OK`)**:
  ```json
  {
    "status": "ingested",
    "session_id": "sess-live-01",
    "deviation": "NONE"
  }
  ```

#### 3.13.2. Query Activity Summary
Returns executive KPIs for the CIO AI Workforce Pulse dashboard.
- **Method**: `GET`
- **Path**: `/api/activity/summary` (Supports `?demo=true` for prototype dataset)
- **Example Response (`200 OK`)**:
  ```json
  {
    "total_active_agents": 12,
    "governed_agent_users": 8,
    "work_intents_completed": 142,
    "business_units_active": "4/6",
    "governed_percent": 98.6,
    "high_risk_prevented": 2,
    "department_mix": {
      "Engineering": 60,
      "Operations": 25,
      "Security": 15
    },
    "intent_mix": {
      "Build / Change": 45,
      "Investigate / Diagnose": 30,
      "Search / Explain": 25
    },
    "timestamp": "2026-10-05T10:14:00Z"
  }
  ```

#### 3.13.3. Query Intent Breakdown & Sub-Intent Drill-Down
Returns primary intent categories and nested sub-intent distributions.
- **Method**: `GET`
- **Path**: `/api/activity/intents` (Supports `?demo=true`)
- **Example Response (`200 OK`)**:
  ```json
  {
    "intents": [
      {
        "category": "Investigate / Diagnose",
        "share": 0.30,
        "subtypes": {
          "Production Incidents": 47,
          "Code Analysis": 28,
          "Infrastructure Telemetry": 16,
          "Security & Auth": 9
        }
      }
    ]
  }
  ```

#### 3.13.4. Query Enterprise Activity Topology
Returns the hierarchical activity tree (Divisions, Teams, Platform Counts) for the Live Agent Map.
- **Method**: `GET`
- **Path**: `/api/activity/topology` (Supports `?demo=true` and `?group_by=bu|team|platform`)
- **Example Response (`200 OK`)**:
  ```json
  {
    "id": "enterprise-root",
    "name": "Enterprise AI Workforce",
    "type": "root",
    "active_sessions": 12,
    "risk_posture": "healthy",
    "platform_counts": {
      "claude-code": 8,
      "copilot": 4
    },
    "children": [
      {
        "id": "div-engineering",
        "name": "Engineering",
        "type": "division",
        "active_sessions": 8,
        "risk_posture": "healthy",
        "platform_counts": { "claude-code": 8 },
        "children": [
          {
            "id": "team-checkout-api",
            "name": "checkout-api",
            "type": "team",
            "active_sessions": 5,
            "risk_posture": "healthy"
          }
        ]
      }
    ]
  }
  ```

#### 3.13.5. Evaluate Intent Contract & Critical Deviation
Evaluates whether a proposed agent action or tool command complies with declared human intent.
- **Method**: `GET`
- **Path**: `/api/activity/deviation?intent=...&action=...&tool=...&target_resource=...`
- **Example Compliant Response (`200 OK`)**:
  ```json
  {
    "intent": "CODE_REFACTOR",
    "action": "pytest tests/unit",
    "is_deviated": false,
    "deviation_level": "NONE",
    "policy_decision": "ALLOW",
    "risk_score": 0.10,
    "reason": "Action complies with declared intent contract."
  }
  ```
- **Example Critical Deviation Response (`200 OK`)**:
  ```json
  {
    "intent": "PRODUCTION_DIAGNOSIS",
    "action": "UPDATE customer_records SET balance = 0",
    "is_deviated": true,
    "deviation_level": "CRITICAL",
    "policy_decision": "DENY",
    "risk_score": 0.95,
    "reason": "Blocked because the requested customer-record modification was inconsistent with the session's declared production-diagnosis intent."
  }
  ```

---

## 4. `bapedge` (LTD) CLI Reference & Offline Operation

The edge daemon (`bapedge.exe`, backwards-compatible alias: `ltd-agent.exe`) provides direct CLI interfaces for enrollment, remote synchronization, zero-trust execution, and attestation.

### 4.1. Edge Self-Enrollment (`bapedge register`)
Computes the local executable's SHA-256 hash, submits hardware and OS telemetry alongside the One-Time Code or Fleet Token, enrolls the SPIFFE workload identity, and caches the initial Cedar policy bundle.
```bash
bapedge register --server <url> --code <OTC_OR_FLEET_TOKEN> [--instance-id <id>] [--ca-cert <path>] [--insecure]

# In development mode, auto-mint OTC on the fly:
bapedge register --server <url> --dev [--insecure]
```
- **Options**:
  - `--server` (string, required): Central `bapcontrolplane` URL (e.g. `https://controlplane.company.internal:8443` or `http://localhost:8080`).
  - `--code` (string, optional if `--dev`): Registration token received during pre-registration (`LTD-OTC-XXXX-XXXX` for single agent, or `BAP-FLEET-XXXX-XXXX` for quota-based fleet).
  - `--dev` (bool, optional): Auto-request a single-use dev OTC from control plane (only supported when control plane runs in `-mode dev`).
  - `--instance-id` (string, optional): Explicit instance identifier (e.g. `worker-prod-01`). Defaults to `<hostname>-<random_hex>`.
  - `--ca-cert` (string, optional): Path to custom CA certificate PEM file to establish TLS trust for `bapcontrolplane`.
  - `--insecure` (bool, optional): Skip TLS verification (development/test environments only).
  - `--config` (string, optional): Local path to store enrolled credentials. Defaults to `~/.ltd/credentials.json`.
- **Output**:
  ```text
  ==================================================
    Bounded Authority Plane (BAP) Agent Enrolled!
  ==================================================
  Agent ID:      agent-payments-worker-9fa1b402-worker-01
  App ID:        payments-worker
  Instance ID:   worker-01
  SPIFFE ID:     spiffe://bap.internal/app/payments-worker/instance/worker-01
  Status:        active
  Binary Hash:   f74e45ee7ca017e225b72a0107529469ae612c308ded4b0221c60e85ccdf9584
  Credentials:   C:\Users\User\.ltd\credentials.json
  Policy Synced: Version 1 (Cached in C:\Users\User\.ltd\policy)
  ==================================================
  ```
- **Exit Codes**:
  - `0`: Registration successful, SPIFFE ID assigned, policy bundle cached.
  - `1`: Network failure, expired token, fleet quota exceeded, replay attempt, or binary hash mismatch.

### 4.2. Interactive Corporate Identity Login (`bapedge login`)
Initiates the RFC 8628 OAuth 2.0 Device Authorization Grant. Engineers authenticate via Okta, Microsoft Entra ID, or corporate MFA in the browser. The agent inherits the verified user email, department, and group claims.
```bash
bapedge login --server <url> [--insecure]
```
- **Terminal Flow**:
  ```text
  ==================================================
    BAP Enterprise Identity Login (OIDC Device Flow)
  ==================================================
  To authenticate this agent session:
  1. Open: https://controlplane.company.internal/device
  2. Enter code: WDJB-MJHT

  Waiting for corporate browser authentication...
  [+] Successfully authenticated as alice@company.com!
  [+] Department: Finance
  [+] Groups:     ai-developers, finance-reconcilers
  [+] Authority grants now evaluated against your enterprise identity.
  ```
- **Exit Codes**:
  - `0`: Authentication succeeded; credentials and identity claims cached in `~/.ltd/credentials.json`.
  - `1`: Timeout, authorization declined, or network error.

### 4.3. Central Policy Synchronization (`bapedge sync`)
Synchronizes the local Cedar rules and schema with `bapcontrolplane`.
```bash
bapedge sync --server <url> [--policy-dir <path>]
```
- **Online Behavior**: Compares local digest and version. If the server has a newer bundle, downloads and writes `policy.cedar`, `schema.json`, and updates `policy-state.json`.
- **Offline Behavior (Control Plane Outage)**: If `bapcontrolplane` is unreachable, `bapedge` detects the network partition, prints `[!] OFFLINE RESILIENCE ACTIVE`, and exits `0` with the prior cached settings intact.
- **Persistent Emergency Lock**: If the server returns directive `KILL_SWITCH`, `bapedge` marks `kill_switch: true` in `policy-state.json`.

### 4.4. Zero-Trust Command Execution (`bapedge exec`)
Evaluates and executes commands through in-process Cedar authorization and sandboxing, appending to local audit logs and streaming telemetry to the control plane.
```bash
bapedge exec --raw "<command_string>" [--session-id <id>] [--server <url>] [--policy <file>] [--schema <file>]
```
- **Options**:
  - `--raw` (string, required): Full shell command string to evaluate and execute.
  - `--session-id` (string, optional): Links execution telemetry to an active agent session (e.g. from `BAP_SESSION_ID`).
  - `--server` (string, optional): Central control plane URL for real-time audit streaming (defaults to `BAP_SERVER` or `http://localhost:8080`).
  - `--policy` (string, optional): Explicit path to `policy.cedar`. Defaults to `~/.ltd/policy/policy.cedar` or working directory.
  - `--schema` (string, optional): Explicit path to `schema.json`.
- **Exit Codes**:
  - `0`: Authorized command executed successfully.
  - `1`: Command denied by Cedar policy, emergency kill-switch active, or execution failure.

### 4.5. Attestation Server & Client (`bapedge serve` / `bapedge attest`)
Used for local peer process verification on Linux/Unix domain sockets (`SO_PEERCRED`):
```bash
# Start attestation server
bapedge serve --socket /tmp/ltd.sock [--allowed-hash <sha256>]

# Query attestation server
bapedge attest --socket /tmp/ltd.sock
```

### 4.6. Local Audit Log Verification & Anti-Tamper Check (`bapedge verify-log`)
Validates the cryptographic sequential SHA-256 hash-chain of the local audit log file, detecting any content tampering, line modifications, or retroactive deletions:
```bash
bapedge verify-log [--file <path>]
```
- **Options**:
  - `--file` (string, optional): Path to audit log file. Defaults to `LTD_AUDIT_LOG` or `ltd-audit.jsonl`.
- **Exit Codes**:
  - `0`: All records cryptographically verified; zero tampering detected.
  - `1`: Tamper alert (hash mismatch, broken previous_hash chain, or corrupted JSON).
