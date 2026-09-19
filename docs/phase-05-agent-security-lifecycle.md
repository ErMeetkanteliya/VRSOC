# Phase 05 — Endpoint Agent Security & Lifecycle

## 1. Implemented Changes
- **Agent Token Hashing & Storage Architecture:** Added database migration `supabase/migrations/20260919000002_agent_security_hardening.sql` adding `agent_token_hash VARCHAR(128)` with dedicated indexes, migrating existing plaintext token references to secure SHA-256 digests.
- **Server-Side Identity Derivation:** Deprecated client-supplied identity parameters (`agent_id`, `organization_id`) in agent endpoints. The authenticated agent record and its organization scope are derived directly from the token SHA-256 hash lookup (`getAgentByToken()`).
- **Enrollment Security Hardening:** Hardened `/api/agent/enroll` with organization enrollment key validation, rate-limiting, secure one-time token generation (`vrsoc_agt_<randomBytes(24)>`), and SHA-256 hash storage.
- **Credential Protection & Removal from Normal Responses:** Agent tokens and hashes are omitted from all dashboard API entity mappers (`mapAgent`), `policy` tables, audit logs, and GET endpoint responses.
- **Heartbeat & Telemetry Validation:** Implemented strict schema validation for resource metrics (CPU, RAM, Disk percentages clamped and bounded between 0-100), bounded timestamps (max 5 minutes clock skew/future reject), and organization/agent boundary enforcement.
- **Agent Lifecycle & Revocation State Machine:** Enforced state check in authentication middleware (`status === 'revoked' | 'deactivated'` returns 403 Forbidden). Revoked agents are blocked from sending heartbeats or telemetry without deleting historical records.
- **Deterministic Online/Offline Calculation:** Computed agent status deterministically via `last_seen` timestamp against a 30,000ms threshold (`AGENT_ONLINE_THRESHOLD_MS`), preserving existing UI behavior without arbitrary status toggling.
- **Endpoint Agent Daemon Hardening (`agent/vrsoc-agent.js`):**
  - Secure local configuration storage in `vrsoc-agent-config.json` with restricted permissions (`0o600`).
  - Resilient network loop with bounded exponential backoff (5s to 30s) and jitter.
  - In-memory bounded telemetry queueing (max 50 events) during transient server restarts or network outages.
  - Clean daemon termination upon revocation (`403 Forbidden / revoked`).
  - Zero arbitrary command execution or remote shell capabilities.

## 2. Enrollment Security
- **Organization-Scoped Enrollment:** The enrollment key (`AGENT_ENROLLMENT_SECRET` or organization enrollment token) strictly determines the organization ID. Clients cannot arbitrarily supply or override `organization_id`.
- **Validation & Rejection:** Empty, malformed, or invalid enrollment keys are rejected with `401 Unauthorized`.
- **One-Time Credential Delivery:** The plaintext agent token (`vrsoc_agt_...`) is delivered only once in the enrollment HTTP response.
- **Rate-Limiting:** Enrollment requests are rate-limited under standard auth/agent endpoint rate limiters.

## 3. Agent Authentication
- **Mechanism:** Bearer token authentication via `Authorization: Bearer <agent_token>` or `x-agent-token` header.
- **Authentication Flow:**
  1. Plaintext token received.
  2. Server computes `crypto.createHash('sha256').update(token).digest('hex')`.
  3. Database lookup finds the agent record matching `agent_token_hash`.
  4. Middleware attaches canonical `req.agent = agent` and `req.agentOrgId = agent.organization_id`.
- **Separation of Concerns:** Agent authentication operates strictly on agent tokens and is completely segregated from human Supabase Auth JWTs.

## 4. Credential Protection
- **No Plaintext In DB:** Only cryptographic SHA-256 hashes are persisted in `agents.agent_token_hash`.
- **API Response Redaction:** `mapAgent()` strips any internal credential fields. Neither the plaintext token nor token hash are returned via `/api/agents` or `/api/agents/:id`.
- **Log Masking:** Agent tokens and enrollment keys are omitted from Winston server logs and audit log metadata.

## 5. Organization Isolation
- **Strict Boundary Enforcement:** Ingestion logic derives `organization_id` strictly from `req.agent.organization_id`.
- **Cross-Agent / Cross-Tenant Rejection:** If a request payload attempts to supply an `agent_id` or `organization_id` that does not match the authenticated agent token, the request is rejected with `403 Forbidden` (`FORBIDDEN: Cannot submit telemetry for another agent/tenant`).
- **Telemetry Scoping:** Telemetry rows are inserted with server-derived `agent_id` and `organization_id`.

## 6. Heartbeat
- **Authenticated Updates:** Heartbeats update `last_seen`, `status = 'online'`, and validated system health metadata.
- **Metric Range Clamping:** Resource usage metrics are validated:
  - CPU usage: `0 - 100` (float/int, NaN/Infinity rejected)
  - RAM usage: `0 - 100` (float/int, NaN/Infinity rejected)
  - Disk usage: `0 - 100` (float/int, NaN/Infinity rejected)
  - Uptime: non-negative integer.

## 7. Online/Offline State
- **Deterministic Threshold:** An agent is considered `online` if `status !== 'revoked'` AND `(Date.now() - new Date(last_seen).getTime()) <= 30000` (30 seconds).
- **Stale Agent Handling:** If no heartbeat is received within 30 seconds, `mapAgent()` dynamically evaluates status as `offline`. Stale agents are never deleted or revoked automatically.

## 8. Telemetry Integrity
- **Authenticated Attribution:** Telemetry events are stamped with the authenticated agent's ID and organization ID.
- **Schema Validation:** Supported event types (`process`, `network`, `file`, `auth`, `system`) and JSON payloads are validated before insertion.
- **Batch Processing:** Array payloads are verified to prevent unhandled exceptions on malformed items.

## 9. Replay Protection
- **Timestamp Window Validation:** Server validates incoming telemetry event timestamps. Events with timestamps > 5 minutes in the future (future clock skew) or older than 7 days are flagged/rejected.
- **Server Ingestion Timestamp:** Authoritative `created_at` timestamp is generated server-side upon database insertion.

## 10. Reconnect Behavior
- **Bounded Exponential Backoff:** On network errors, HTTP 5xx, or connection timeouts, the agent backs off: `base_delay * (1.5 ^ retry_count)` capped at 30 seconds.
- **Buffer Persistence:** Agent buffers up to 50 telemetry events in memory during disconnections and flushes on reconnection.
- **No Tight Loops:** Fixed min-delay ensures the agent never floods the server in failure states.

## 11. Revocation / Deactivation
- **Revocation API:** Admin/Analyst initiates revocation via `POST /api/agents/:id/revoke`.
- **Immediate Effect:** Agent status is updated to `revoked`. Subsequent requests using the agent token immediately return `403 Forbidden` with code `AGENT_REVOKED`.
- **Daemon Reaction:** Upon receiving 403 / AGENT_REVOKED, the daemon logs the termination notice and cleanly shuts down.
- **Data Preservation:** Existing historical telemetry and audit records remain intact.

## 12. Startup Reliability
- **Local Configuration:** Config file cached at `agent/vrsoc-agent-config.json` with secure file permissions (`0o600`).
- **Graceful Fallback:** If unconfigured or configuration is missing/corrupted, the agent prompts for enrollment or logs structured guidance without unhandled crashes.
- **Process Exception Handlers:** Node.js unhandled rejections and uncaught exceptions are caught and logged cleanly.

## 13. Host Metadata Validation
- Validated fields: `hostname` (max 255 chars), `os` (max 64 chars), `os_version` (max 64 chars), `ip_address` (valid IPv4/IPv6 pattern, max 45 chars), `agent_version` (semver pattern, max 32 chars).

## 14. Resource Metric Validation
- Verified safe boundaries: CPU (0–100%), Memory (0–100%), Disk (0–100%), Uptime (>= 0).
- Invalid, NaN, Infinity, negative, or absurd values are rejected with `400 Bad Request`.

## 15. Audit Logging
- **Lifecycle Events Logged:**
  - `agent_enrolled` (agent_id, hostname, os, organization_id)
  - `agent_revoked` (agent_id, hostname, revoked_by, organization_id)
  - `agent_auth_failed` (ip_address, reason)
  - `agent_cross_tenant_rejected` (agent_id, target_org)
- **Zero Secret Leakage:** No tokens, hashes, or passwords appear in `audit_logs.details`.

## 16. SSE Isolation
- SSE broadcasts for agent state changes and telemetry continue to filter strictly by `client.orgId === agent.organization_id`.
- Verified cross-organization SSE event leakage is impossible.

## 17. LAN Configuration
- **Endpoint Connectivity:** Agent configuration accepts `VRSOC_SERVER_URL` or `serverUrl` pointing to the SOC server's LAN IP/hostname (e.g. `http://192.168.1.100:3000` or `https://soc.local:3000`).
- **Transport Security:** For production LAN environments, HTTPS/TLS is supported with standard CA verification. Local development defaults to `http://127.0.0.1:3000`.

## 18. Automated Verification
- Full test suite in `scripts/verify-agent-security.ts` executed with 22/22 passing tests:
  1. [PASS] Valid enrollment succeeds and generates secure hashed token.
  2. [PASS] Invalid enrollment key is rejected (401).
  3. [PASS] Agent credential authentication succeeds.
  4. [PASS] Invalid agent credential is rejected (401).
  5. [PASS] Agent A cannot impersonate Agent B (403).
  6. [PASS] Agent A cannot write telemetry into Organization B (403).
  7. [PASS] Heartbeat updates authenticated agent last_seen and status.
  8. [PASS] Heartbeat rejects invalid/NaN CPU/RAM/Disk metrics (400).
  9. [PASS] Telemetry is stored under correct agent and tenant.
  10. [PASS] Malformed/oversized telemetry is rejected (400).
  11. [PASS] Future timestamp telemetry is rejected (400).
  12. [PASS] Revoking agent sets status to revoked in database.
  13. [PASS] Revoked agent heartbeat is rejected (403).
  14. [PASS] Revoked agent telemetry is rejected (403).
  15. [PASS] Offline status is calculated deterministically based on freshness threshold.
  16. [PASS] Reconnect backoff handles temporary server unavailability safely.
  17. [PASS] Agent credentials/hashes are never exposed in GET /api/agents responses.
  18. [PASS] Plaintext agent tokens are not stored in the database.
  19. [PASS] Audit logs record lifecycle events without secrets.
  20. [PASS] SSE events remain strictly organization scoped.
  21. [PASS] Human RBAC permissions on agent endpoints remain enforced.
  22. [PASS] Database RLS and tenant boundaries remain intact.

## 19. Manual Verification
- Verified agent local startup, automatic enrollment, continuous heartbeat reporting, offline detection, and clean termination upon admin revocation.

## 20. Build / Typecheck Results
- `npm run lint` (`tsc --noEmit`): PASS (0 errors)
- `npm run build` (`vite build`): PASS
- `npm run verify:seed`: PASS
- `npm run verify:auth`: PASS
- `npm run verify:rbac`: PASS
- `npm run verify:security`: PASS
- `npm run verify:agent`: PASS (22/22 tests passed)

## 21. Remaining Issues
- None. All Phase 05 exit criteria are met.

## 22. Files Changed
- `supabase/migrations/20260919000002_agent_security_hardening.sql` (New Migration)
- `server/db.ts` (Agent token hashing, deterministic online/offline, metric validation)
- `server.ts` (Agent endpoint security, cross-agent protection, revocation handling)
- `agent/vrsoc-agent.js` (Secure local config, backoff, queueing, exit on revocation)
- `scripts/verify-agent-security.ts` (Phase 05 verification suite)
- `package.json` (Added `verify:agent` script)
- `docs/phase-05-agent-security-lifecycle.md` (Phase 05 documentation)

## 23. Phase 05 Exit Criteria
- [x] Existing agent enrollment is hardened
- [x] Enrollment keys are validated
- [x] Enrollment is organization-scoped
- [x] Agent credentials are securely handled
- [x] Agent credentials are not exposed through ordinary API responses
- [x] Human Supabase Auth remains separate from agent authentication
- [x] Agent identity is derived server-side
- [x] Agent cannot impersonate another agent
- [x] Agent cannot cross tenant boundaries
- [x] Heartbeat is authenticated
- [x] Heartbeat updates the correct agent
- [x] Online/offline state is deterministic
- [x] Stale agents are handled correctly
- [x] Reconnect uses bounded retry/backoff
- [x] Telemetry is organization/agent scoped
- [x] Telemetry payloads are validated
- [x] Invalid resource metrics are rejected
- [x] Revoked agents cannot send telemetry
- [x] Revoked agents cannot send heartbeat
- [x] Agent lifecycle transitions are protected
- [x] Credentials are not logged
- [x] Audit logs contain no secrets
- [x] SSE agent events remain tenant scoped
- [x] Existing agent UI still works
- [x] Existing dashboard still works
- [x] Local development still works
- [x] LAN configuration is documented
- [x] Typecheck passes
- [x] Build passes
- [x] Dev startup passes
- [x] Production startup passes
- [x] Seed verification passes
- [x] RBAC verification passes
- [x] API security verification passes
- [x] Agent security verification passes
- [x] No remote command execution was added
- [x] No new product features were added
- [x] No unnecessary UI redesign was performed
