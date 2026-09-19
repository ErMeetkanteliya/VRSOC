# VRSOC — Current Codebase Completion & SaaS Conversion Constitution

**Document purpose:** This file is the single execution guide for completing the VRSOC codebase contained in the supplied ZIP.

**Execution model:** One phase = one implementation prompt. The implementation agent/editor must read this file before executing every phase.

**Primary rule:** COMPLETE THE EXISTING PRODUCT. DO NOT INVENT A NEW PRODUCT.

---

## 0. Scope Lock — Non-Negotiable

This project must be converted from the current prototype/demo implementation into a proper production-capable SaaS application **without changing the intended frontend product surface**.

### Do NOT

- Do not redesign the UI.
- Do not replace the current visual language, layouts, routes, labels, workflows, or user-facing features unless required to fix a bug or security issue.
- Do not add unrelated modules or product ideas.
- Do not add random “enterprise” features that have no representation in the current product.
- Do not replace React/Vite frontend with another frontend framework.
- Do not replace Express backend with another backend framework unless the existing code absolutely requires it.
- Do not replace Supabase as the target auth/database platform.
- Do not rebuild working frontend components from scratch.
- Do not create a second parallel architecture.
- Do not leave fake/demo/local implementations in the production path.

### DO

- Preserve the existing frontend and its existing user-facing functionality.
- Make the backend actually support what the frontend already exposes.
- Make the current endpoint agent operational and secure.
- Replace local/demo persistence with real production persistence.
- Make multi-tenant SaaS isolation real.
- Make authentication, authorization, auditability, validation, security, realtime updates, and production operations real.
- Fix bugs caused by mismatched contracts between the existing frontend and backend.
- Reuse existing business logic where valid instead of duplicating it.
- Keep compatibility with existing API behavior where possible.

---

# 1. Current Codebase Snapshot

The supplied ZIP is a **React + Vite frontend with an Express/TypeScript server and a Node.js endpoint agent**.

### Current main technologies

- Frontend: React 19 + Vite
- Styling: Tailwind CSS v4
- Backend: Express
- Runtime/tooling: TypeScript, TSX, esbuild
- Database target: Supabase PostgreSQL
- Auth target: Supabase Auth
- AI: Google Gemini via `@google/genai`
- Realtime: Server-Sent Events (SSE)
- Endpoint agent: Node.js

### Current important files

```text
src/App.tsx
src/api.ts
src/types.ts
src/lib/supabase.ts

src/components/
  AddAgentModal.tsx
  AgentsView.tsx
  AiAssistantView.tsx
  AlertsView.tsx
  AuditLogsView.tsx
  AuthModal.tsx
  CommandPalette.tsx
  DashboardView.tsx
  DetectionRulesView.tsx
  IncidentsView.tsx
  Navbar.tsx
  PhishGuardView.tsx
  ReportsView.tsx
  SettingsView.tsx
  VerifyEmailPage.tsx
  VerifyPhonePage.tsx

server.ts
server/db.ts
server/supabase.ts
server/detectionEngine.ts
server/phishguard.ts
server/aiEngine.ts
server/sse.ts

agent/vrsoc-agent.js

supabase/migrations/20260919000000_vrsoc_core_schema.sql

data/vrsoc.db.json
```

---

# 2. Existing Product Surface — MUST BE PRESERVED

The current application exposes these existing product areas:

1. Dashboard
2. Endpoints & Agents
3. Alert Queue
4. Incidents & Cases
5. PhishGuard ML
6. Detection Rules
7. AI Copilot
8. Reports
9. Audit Logs
10. Settings

Existing authentication/onboarding flows include:

- Signup
- Login
- Email verification
- Phone verification
- Password reset
- MFA/TOTP enrollment/verification UI
- Organization onboarding
- Organization VRSOC security key
- VRSOC key rotation
- Logout

Existing SOC/backend capabilities include:

- Organization metrics
- Agent enrollment
- Agent heartbeat
- Agent telemetry ingestion
- Agent revoke
- Detection rule listing/creation/toggle
- Alert listing/detail/status/comment
- Alert AI analysis
- Incident create/update/detail
- Incident tasks
- Incident timeline
- Incident notes
- PhishGuard URL scanning
- Promotion of phishing result to alert
- Threat indicators
- AI chat
- Audit logs
- Report generation/listing
- Realtime event stream
- Training/telemetry simulation

Existing agent capabilities include:

- Enrollment with organization key
- Agent token receipt
- Heartbeat
- Startup telemetry
- Optional lab telemetry generation

These capabilities are the scope to complete. Anything not represented above should not be introduced as a new product feature during this execution.

---

# 3. Current-State Audit — What Is Already There

## 3.1 Backend API exists

There is already a substantial Express API in `server.ts`.

### Existing auth APIs

```text
GET  /api/auth/config
POST /api/auth/complete-onboarding
POST /api/auth/signup
POST /api/auth/login
POST /api/auth/resend-email-otp
POST /api/auth/resend-phone-otp
POST /api/auth/verify-email-otp
POST /api/auth/verify-phone-otp
POST /api/auth/mfa-setup
POST /api/auth/mfa-verify
GET  /api/auth/me
POST /api/auth/logout
```

### Existing organization APIs

```text
POST /api/organizations/key/rotate
GET  /api/organizations/metrics
```

### Existing agent APIs

```text
GET  /api/agents
GET  /api/agents/:id
POST /api/agents/:id/revoke
POST /api/agent/enroll
POST /api/agent/heartbeat
POST /api/agent/telemetry
GET  /api/agent/script
```

### Existing training/simulation API

```text
POST /api/telemetry/simulate
```

### Existing detection/alert APIs

```text
GET   /api/detection-rules
POST  /api/detection-rules
POST  /api/detection-rules/:id/toggle

GET   /api/alerts
GET   /api/alerts/:id
PATCH /api/alerts/:id/status
POST  /api/alerts/:id/comment
POST  /api/alerts/:id/ai-analyze
```

### Existing incident APIs

```text
GET   /api/incidents
GET   /api/incidents/:id
POST  /api/incidents
PATCH /api/incidents/:id
POST  /api/incidents/:id/task
PATCH /api/incidents/:id/task/:taskId
POST  /api/incidents/:id/timeline
POST  /api/incidents/:id/note
```

### Existing PhishGuard/AI/IOC/report APIs

```text
POST /api/phishguard/scan
POST /api/phishguard/promote-to-alert
GET  /api/phishguard/scans

POST /api/ai/chat

GET  /api/indicators
POST /api/indicators

GET  /api/audit-logs

POST /api/reports/generate
GET  /api/reports
```

### Existing realtime API

Server currently exposes:

```text
GET /api/events/stream
```

But the frontend currently attempts:

```text
/api/sse/stream
```

This is a concrete existing integration bug and must be corrected while preserving the existing SSE product behavior.

---

# 4. Current-State Audit — Major Gaps / Problems To Fix

## GAP-01 — Local JSON database is still the effective backend store

`server/db.ts` persists application state to:

```text
data/vrsoc.db.json
```

This is not a production SaaS datastore.

### Required outcome

Supabase PostgreSQL becomes the authoritative production datastore. The JSON database must be removed from the production request path.

---

## GAP-02 — Supabase migration exists but is not the authoritative runtime path

A substantial PostgreSQL schema already exists in:

```text
supabase/migrations/20260919000000_vrsoc_core_schema.sql
```

It includes tables for organizations, profiles, members, teams, sessions, agents, heartbeats, endpoint events, rules, alerts, alert comments, incidents, incident links/timeline/tasks, phishing scans, indicators, audit logs, reports, and AI analyses.

### Required outcome

Reconcile the migration with the actual application types/API contracts and make PostgreSQL the real persistence layer.

---

## GAP-03 — Authentication is mixed between local auth and Supabase auth

Current server behavior attempts Supabase JWT verification and then falls back to local session-token storage.

Current local persistence also contains password hashes and session tokens.

### Required outcome

Production authentication must have one clear authoritative identity/session model using Supabase Auth, while the application profile/organization layer is mapped to the authenticated Supabase user.

Local fallback authentication must not remain the production path.

---

## GAP-04 — Session token is exposed to browser JavaScript

`src/api.ts` stores `vrsoc_token` in `localStorage`.

The server also issues an HttpOnly cookie.

This creates two competing session mechanisms and exposes the application session token to JavaScript/XSS risk.

### Required outcome

Use a single production session strategy. Prefer the existing Supabase Auth session model and secure HttpOnly/managed session behavior where server authentication requires cookies/tokens. Do not retain an unnecessary long-lived localStorage application token.

---

## GAP-05 — MFA implementation is not production-safe

The current server contains a static MFA secret:

```text
JBSWY3DPEHPK3PXP
```

The UI also displays a fallback secret.

### Required outcome

Use real Supabase MFA/TOTP enrollment and verification. Never use a static secret, fallback secret, or hard-coded shared MFA secret.

MFA must be tied to the actual user factor.

---

## GAP-06 — OTP implementation exposes verification codes in API responses

The current local auth path returns `emailOtp`, `phoneOtp`, and `devHint` values.

### Required outcome

Production OTP codes must be delivered through the configured verification provider/Supabase Auth flow and never returned in API JSON responses.

The frontend verification UI must remain functionally the same.

---

## GAP-07 — Demo/seed credentials and personal/demo records exist in source data

`data/vrsoc.db.json` includes seeded users, hashed passwords, MFA data, sessions, agents, and realistic SOC data.

The authentication UI also contains a demo credential shortcut.

### Required outcome

Remove production reliance on hard-coded demo credentials and seeded secrets. Preserve training/demo capability only where it is already explicitly represented by the Training Lab functionality, and do not ship real secrets.

---

## GAP-08 — Agent tokens are stored/compared as plaintext

The current agent token is generated and stored directly in application data.

### Required outcome

Use secure agent credential handling:

- generate high-entropy agent credentials
- never log full credentials
- do not expose credentials unnecessarily in API responses
- store credential verification material safely
- support rotation/revocation
- reject revoked agents
- bind the credential to the correct organization/agent identity

---

## GAP-09 — Organization key is used directly as agent enrollment credential

The current 14-character VRSOC organization key is used to enroll endpoints.

This is part of the existing product behavior and must remain understandable to users, but its security handling must be hardened.

### Required outcome

Preserve the existing VRSOC-key enrollment workflow, but make validation, brute-force protection, rotation, audit logging, and credential exposure safe.

---

## GAP-10 — Agent is not a real operating-system service yet

`agent/vrsoc-agent.js` is a Node process/daemon script. It is not currently packaged as a proper Windows/Linux service installer.

### Required outcome

Make the existing agent deployable and auto-startable on supported endpoint environments without creating a new product module.

For the current 10-PC LAN scenario, Windows is the primary operational target and the agent must be able to start automatically with the machine and reconnect to the SOC server after reboot/network loss.

---

## GAP-11 — Endpoint telemetry contains hard-coded/fake values

Examples include hard-coded disk usage, process counts, and network connection counts in the agent.

### Required outcome

Use actual local system data for the metrics already represented by the existing agent and UI.

Do not expand into unrelated endpoint capabilities.

---

## GAP-12 — No robust agent connectivity lifecycle

Current heartbeat logic is present, but production-grade lifecycle behavior is incomplete.

### Required outcome

Implement:

- heartbeat persistence
- offline detection based on timeout
- reconnect behavior
- last-seen accuracy
- agent health state updates
- revocation handling
- duplicate enrollment handling
- durable agent identity

---

## GAP-13 — Telemetry ingestion needs production controls

Current telemetry ingestion accepts general JSON payloads with minimal validation.

### Required outcome

Add strict request/event validation, size limits, field allowlists where appropriate, idempotency/deduplication strategy, tenant binding from the authenticated agent identity, and safe error handling.

---

## GAP-14 — RBAC exists as role labels but enforcement is incomplete

Roles exist in application types, but server-side authorization is not systematically enforced for every mutation/read operation.

### Required outcome

Create a centralized authorization policy using the existing roles:

```text
Super Admin
Organization Admin
Instructor
SOC Analyst
Incident Responder
Threat Hunter
Auditor
Viewer
Student
```

Do not invent additional roles unless required to reconcile the existing code safely.

Authorization must happen server-side, not only in the UI.

---

## GAP-15 — Multi-tenant isolation is not yet proven end-to-end

The Supabase schema contains RLS, but the application runtime still primarily uses in-memory/local JSON data and first-organization lookup behavior.

### Required outcome

A request from Organization A must never be able to read or mutate Organization B data.

Tenant scope must be derived from authenticated membership/agent identity, not trusted blindly from client payloads.

---

## GAP-16 — Supabase RLS coverage is incomplete

The schema enables RLS on many tables, but policy coverage is uneven and not all tables have explicit read/write policies.

### Required outcome

Every production-exposed table must have deliberate RLS behavior appropriate to its usage, especially:

- organizations
- profiles
- organization_members
- agents
- agent_heartbeats
- endpoint_events
- detection_rules
- alerts
- alert_comments
- incidents
- incident_alerts
- incident_timeline
- incident_tasks
- phishing_scans
- indicators
- audit_logs
- reports
- ai_analyses

No “temporary open policy” is acceptable in the final state.

---

## GAP-17 — Validation is too weak

Current Express routes destructure request bodies and manually check only a few fields.

### Required outcome

Introduce a single schema-validation layer for incoming API requests and agent payloads.

Validation must enforce types, enums, lengths, bounds, required fields, nested structures, and safe values.

---

## GAP-18 — HTTP security middleware is incomplete

Current package/runtime does not show a production security baseline such as Helmet/rate limiting/CORS policy enforcement.

### Required outcome

Add a minimal, real production security baseline:

- secure headers
- strict CORS allowlist
- body-size limits
- rate limiting on authentication and agent enrollment endpoints
- sensible request timeouts
- safe error responses
- production logging without secret leakage

Do not add arbitrary middleware that creates unnecessary complexity.

---

## GAP-19 — Realtime SSE contract mismatch exists

Frontend:

```text
/api/sse/stream
```

Backend:

```text
/api/events/stream
```

### Required outcome

Make the existing live dashboard/realtime experience work reliably and tenant-safely.

Implement reconnect behavior and cleanup while preserving the current UI behavior.

---

## GAP-20 — API and UI data contracts need reconciliation

The frontend types, backend local types, Supabase schema, and API responses are not guaranteed to be identical.

### Required outcome

Establish one canonical domain contract and map database rows to application DTOs consistently.

Do not force the UI to consume raw database column names if the existing UI already expects camelCase objects.

---

## GAP-21 — Error handling is not centralized

Current routes return many direct `res.status(...).json(...)` responses with ad-hoc messages.

### Required outcome

Use consistent error types, status codes, structured error responses, and server-side logging while keeping frontend-visible messages understandable.

---

## GAP-22 — Audit logging is present but must become trustworthy

Audit log support exists and is used for many operations.

### Required outcome

Ensure security-relevant actions are logged from the server with:

- authenticated actor
- organization
- action
- target
- timestamp
- source IP where applicable
- relevant non-secret details

Do not allow clients to forge actor identity or organization scope.

---

## GAP-23 — Detection engine must be production-backed by persistent rules/events

A detection engine already exists and evaluates telemetry against rules.

### Required outcome

Keep the current detection concepts and rule content, but make evaluation consistent, deterministic, tenant-aware, testable, and backed by PostgreSQL data.

Do not invent an unrelated detection product.

---

## GAP-24 — Alert/incident consistency needs strengthening

Alerts and incidents exist as separate entities but the relationship/timeline/task/comment behavior must be persisted consistently.

### Required outcome

Guarantee:

- valid organization ownership
- valid agent references
- valid rule references
- safe status transitions
- linked alerts remain tenant-safe
- comments/tasks/timeline are persisted properly
- assignment references valid users
- audit entries are produced for sensitive changes

---

## GAP-25 — PhishGuard must be persistent and deterministic

PhishGuard already has feature extraction/classification logic.

### Required outcome

Keep the existing scanner behavior and UI. Persist scans in PostgreSQL, validate URLs safely, preserve reasons/features, and preserve promotion-to-alert behavior.

Do not turn this into a new external intelligence product.

---

## GAP-26 — AI paths need security and reliability hardening

AI features already exist for alert analysis and chat.

### Required outcome

Keep the existing AI functionality but add:

- strict input limits
- tenant-scoped context
- explicit evidence-vs-inference behavior already represented in the UI
- no secret leakage
- provider failure handling
- timeout/error handling
- persistence of generated analyses where the schema already supports it

The AI must not bypass authorization.

---

## GAP-27 — Reports need durable generation behavior

Reports already exist as a product area.

### Required outcome

Persist generated report metadata/content in PostgreSQL and ensure report generation is deterministic enough for repeatable testing and safe under authorization.

---

## GAP-28 — Retention policy exists but enforcement is incomplete

Organizations have `retentionDays`.

### Required outcome

Implement the existing retention concept for telemetry/audit or other applicable records without inventing new user-facing retention features.

Use a controlled server-side cleanup process and preserve required audit history according to the existing product intent.

---

## GAP-29 — Production configuration/deployment is incomplete

The current README is a generic AI Studio app README and does not describe the actual SaaS deployment architecture.

### Required outcome

Document and configure:

- frontend/build
- Express server
- Supabase
- Gemini key
- auth config
- agent server URL
- production environment variables
- local/LAN deployment
- production deployment
- health checks
- secrets handling

Do not expose server-only secrets to Vite/client code.

---

# 5. Target Architecture — Keep It Simple

The target architecture is:

```text
                       VRSOC SaaS

          ┌──────────────────────────────┐
          │ React + Vite Frontend        │
          │ Existing UI / Existing Views │
          └──────────────┬───────────────┘
                         │ HTTPS
                         ▼
          ┌──────────────────────────────┐
          │ Express API / Application    │
          │ Auth / RBAC / Validation     │
          │ SOC Business Logic            │
          │ Detection / AI / SSE         │
          └──────────────┬───────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
     ┌────────────────┐    ┌─────────────────┐
     │ Supabase Auth  │    │ Supabase        │
     │ Identity/MFA   │    │ PostgreSQL/RLS  │
     └────────────────┘    └─────────────────┘

        Endpoint side

     ┌──────────┐   ┌──────────┐   ┌──────────┐
     │ PC-01    │   │ PC-02    │   │ PC-10    │
     │ VRSOC    │   │ VRSOC    │   │ VRSOC    │
     │ Agent    │   │ Agent    │   │ Agent    │
     └────┬─────┘   └────┬─────┘   └────┬─────┘
          │              │              │
          └──────────────┼──────────────┘
                         │ LAN / HTTPS
                         ▼
                 ┌─────────────────┐
                 │ Main SOC Server │
                 │ Express API     │
                 │ PostgreSQL      │
                 │ Realtime/SSE    │
                 └─────────────────┘
```

### LAN scenario

The current operational scenario is valid:

- one Main SOC PC/server
- up to 10 endpoint PCs
- all endpoints connected through the same router/switch/LAN
- agent installed on each endpoint
- agent auto-starts on boot
- agents send telemetry/heartbeat to the Main SOC server
- SOC dashboard reads centralized data

Internet access is not inherently required for endpoint-to-SOC communication when all systems are on the same LAN, but it is required for cloud services such as Supabase/Gemini when those services are used remotely.

---

# 6. Agent Communication Model

## Enrollment

```text
Admin gets existing VRSOC Security Key
        ↓
Agent installation/configuration
        ↓
Agent → /api/agent/enroll
        ↓
Server validates org enrollment credential
        ↓
Server creates/returns endpoint identity credential
        ↓
Agent stores credential securely
```

## Heartbeat

```text
Agent → heartbeat
        ↓
Server authenticates agent
        ↓
Update last_seen + current health metrics
        ↓
Dashboard/SSE receives updated state
```

## Telemetry

```text
Agent → telemetry event
        ↓
Authenticate agent
        ↓
Derive organization from agent record
        ↓
Validate event schema
        ↓
Persist event
        ↓
Run detection engine
        ↓
Create alert when rule matches
        ↓
Broadcast realtime event
        ↓
Dashboard updates
```

### Important security boundary

The endpoint agent must never be trusted merely because it sends an `organizationId` or similar field.

The server must derive organization identity from the authenticated agent credential.

---

# 7. Current Feature Boundary Regarding Remote Commands

The current supplied frontend does **not** expose a complete remote-command execution product. It exposes telemetry, detection, alerts, remediation recommendations, and training simulations.

Therefore:

- Do NOT invent a new arbitrary remote command execution UI.
- Do NOT add a new command-execution subsystem just because it might be useful.
- Do NOT allow the agent to execute arbitrary commands from the server as a hidden feature.

Only implement remote endpoint actions if a corresponding existing frontend/backend contract already exists in the codebase and is required to make the current product functional.

If a future phase prompt explicitly introduces an existing coded contract discovered during audit, follow that exact contract and keep the security model strict.

---

# 8. Canonical Data Domains

The current schema/types imply these domains:

```text
Identity
├── profiles
├── organization_members
└── authentication/session mapping

Organization
└── organizations

Endpoint
├── agents
├── agent_heartbeats
└── endpoint_events

Detection
└── detection_rules

Alerting
├── alerts
└── alert_comments

Case Management
├── incidents
├── incident_alerts
├── incident_timeline
└── incident_tasks

Threat/Phish
├── phishing_scans
└── indicators

Governance
├── audit_logs
└── reports

AI
└── ai_analyses
```

Existing supporting schema tables such as `teams`/`team_members` may remain where already present, but no new team-management UI or unrelated feature should be invented.

---

# 9. SaaS Requirements

The product is considered properly SaaS only when these are true:

### Tenant isolation

- Every organization sees only its own data.
- Every organization-owned table is tenant-scoped.
- Server-side authorization prevents cross-tenant access.
- Database RLS backs the application checks.

### User identity

- Supabase Auth is authoritative.
- Application profile is linked to authenticated Supabase user ID.
- Roles are stored and enforced server-side.

### Data persistence

- No production use of JSON file storage.
- PostgreSQL is authoritative.
- Database constraints and indexes are real.

### Security

- No hard-coded credentials.
- No static MFA secret.
- No OTPs returned in production API responses.
- Agent credentials are protected.
- Secrets are server-side only.
- Authentication endpoints are rate-limited.
- Agent enrollment is protected from brute force.

### Reliability

- Agent reconnects after network loss.
- Main SOC survives endpoint disconnects.
- SSE reconnects after connection loss.
- Backend does not lose data on process restart.

### Auditability

- security-relevant mutations create audit records.
- actor and tenant are server-derived.

---

# 10. Implementation Phases — 37 Small Prompts

**Total planned implementation prompts: 37.**

Each phase is intentionally small so the coding agent can finish, verify, and commit one coherent unit before moving forward.

Do not combine unrelated phases just to reduce the number of prompts.

---

## Phase 00 — Baseline Freeze & Repository Audit

### Goal
Freeze the existing product surface and record current build/runtime behavior before changing code.

### Tasks

- Inspect the complete repository.
- Identify all frontend routes/views/components.
- Identify all API routes.
- Identify all DB entities and migration tables.
- Identify all current auth flows.
- Identify current agent flows.
- Run baseline build/typecheck where possible.
- Record known failures.

### Must not change

No feature/UI behavior changes.

### Exit criteria

- Baseline is documented.
- Existing scope is frozen.
- Known failures are explicit.

---

## Phase 01 — Dependency, Runtime & Project Hygiene

### Goal
Make the existing project reproducible and internally consistent.

### Tasks

- Reconcile package scripts.
- Verify TypeScript/esbuild/Vite/Express runtime.
- Remove obsolete generic README/config assumptions.
- Keep dependencies only when actually used.
- Ensure `.env.example` matches real runtime requirements.
- Establish development and production start/build paths.

### Exit criteria

- clean install path
- predictable build
- predictable server start
- no broken script references

---

## Phase 02 — Canonical Domain Contract

### Goal
Create one canonical application domain model mapping DB rows ↔ backend objects ↔ frontend DTOs.

### Tasks

- Reconcile `src/types.ts`, `server/db.ts`, and Supabase schema.
- Define canonical enums/statuses.
- Define DTO mapping conventions.
- Resolve naming mismatches.
- Prevent database-specific shapes from leaking into frontend code.

### Exit criteria

Frontend and backend use consistent contracts.

---

## Phase 03 — Supabase PostgreSQL Foundation

### Goal
Make the existing Supabase migration the real database foundation.

### Tasks

- Reconcile schema with canonical domain model.
- Add required constraints/indexes only for existing domains.
- Add timestamp/update handling where needed.
- Ensure foreign keys are correct.
- Add safe uniqueness constraints.
- Add required database helper functions.

### Exit criteria

All current product entities have production-ready database structures.

---

## Phase 04 — Repository/Data Access Layer

### Goal
Replace direct JSON persistence with a real database access layer.

### Tasks

- Introduce repositories/data services for each domain.
- Keep business logic separate from SQL/database calls.
- Replace `db.*` JSON calls in production paths.
- Maintain API response compatibility.

### Exit criteria

Application reads/writes PostgreSQL for real operations.

---

## Phase 05 — Seed/Data Migration & Demo Sanitization

### Goal
Remove production dependence on demo JSON data and hard-coded credentials.

### Tasks

- Remove production use of `data/vrsoc.db.json`.
- Remove seeded secrets/credentials from runtime.
- Remove hard-coded demo login shortcut from production build.
- Preserve existing Training Lab behavior through explicit training data generation rather than secret-bearing seed data.
- Ensure first deployment starts cleanly.

### Exit criteria

No demo password/session/MFA secret is required to operate production.

---

## Phase 06 — Supabase Auth as Single Identity Authority

### Goal
Unify authentication around Supabase Auth.

### Tasks

- Make Supabase user ID authoritative.
- Link/create application profile correctly.
- Remove production local-password auth fallback.
- Ensure login/logout/session refresh are coherent.
- Preserve existing auth UI.

### Exit criteria

One authoritative login/session model.

---

## Phase 07 — Secure Browser Session Handling

### Goal
Remove unsafe token duplication.

### Tasks

- Eliminate unnecessary application session token storage in `localStorage`.
- Use the chosen secure session mechanism consistently.
- Keep authenticated API calls working.
- Verify logout invalidates the active session.

### Exit criteria

No long-lived auth token is unnecessarily stored in browser localStorage.

---

## Phase 08 — Email Verification Flow

### Goal
Make the existing email verification UI production-backed.

### Tasks

- Use Supabase verification.
- Remove response-level OTP leakage.
- Handle expiry and invalid tokens.
- Handle resend safely/rate-limited.
- Keep existing UI.

### Exit criteria

Real email verification works without exposing OTP values to the client.

---

## Phase 09 — Phone Verification Flow

### Goal
Make the existing phone verification UI production-backed.

### Tasks

- Use Supabase phone auth/native SMS/provider already represented by current config.
- Keep E.164 formatting behavior correct.
- Rate-limit resend.
- Remove test OTP disclosure.
- Handle expiry/errors.

### Exit criteria

Real phone verification works securely.

---

## Phase 10 — Real MFA/TOTP

### Goal
Make MFA use actual Supabase factors.

### Tasks

- Remove static MFA secret.
- Remove fallback secret from UI.
- Enroll the current user factor.
- Verify/challenge the actual factor.
- Persist only the data necessary for application state.

### Exit criteria

Each user gets their own real MFA factor.

---

## Phase 11 — Organization Onboarding & VRSOC Key

### Goal
Make organization creation and key rotation production-safe.

### Tasks

- Create organization transactionally.
- Create/link organization membership.
- Generate secure 14-char hexadecimal VRSOC key as existing UX requires.
- Harden key lookup and rate limiting.
- Secure key rotation.
- Audit creation and rotation.

### Exit criteria

Organization onboarding works end-to-end with no demo fallback.

---

## Phase 12 — Centralized RBAC Policy Engine

### Goal
Enforce the existing roles consistently on the server.

### Tasks

- Create permission definitions for existing roles.
- Centralize permission checks.
- Attach permissions to current endpoints.
- Default deny unknown operations.
- Keep UI labels unchanged.

### Exit criteria

Every protected operation has an explicit authorization rule.

---

## Phase 13 — Tenant Isolation & Membership Validation

### Goal
Make multi-tenant SaaS isolation real.

### Tasks

- Derive organization from authenticated membership.
- Never trust organization IDs from client input.
- Validate target objects belong to active organization.
- Reject cross-tenant reads/writes.
- Handle suspended organizations safely.

### Exit criteria

Cross-tenant access tests fail closed.

---

## Phase 14 — Supabase RLS Hardening

### Goal
Make database-level tenant isolation trustworthy.

### Tasks

- Review every existing RLS policy.
- Add missing policies.
- Separate read/write behavior where appropriate.
- Protect profiles/memberships from unauthorized mutation.
- Ensure service-role usage is server-only.
- Add RLS tests for tenant boundaries.

### Exit criteria

Direct database access cannot bypass tenant isolation through normal client credentials.

---

## Phase 15 — API Validation Layer

### Goal
Strictly validate all public API inputs.

### Tasks

- Introduce a single validation library/pattern.
- Validate auth bodies.
- Validate agent enrollment/heartbeat/telemetry.
- Validate rules, alerts, incidents, phishing scans, indicators, reports, AI inputs.
- Enforce enum/range/string limits.

### Exit criteria

Invalid input is rejected before business logic executes.

---

## Phase 16 — HTTP Security Baseline

### Goal
Harden the Express server without overengineering.

### Tasks

- Add secure HTTP headers.
- Restrict CORS.
- Set JSON body limits.
- Add rate limiting to sensitive routes.
- Add request timeout protection where appropriate.
- Return safe errors.
- Prevent secret logging.

### Exit criteria

A basic production security test suite passes.

---

## Phase 17 — Agent Enrollment Security

### Goal
Make endpoint enrollment safe and durable.

### Tasks

- Validate enrollment credential strictly.
- Bind new agent to organization server-side.
- prevent brute-force abuse.
- Handle duplicate hostname/re-enrollment predictably.
- Protect agent token issuance.
- Add audit events.

### Exit criteria

Only authorized endpoint agents can enroll.

---

## Phase 18 — Agent Credential Lifecycle

### Goal
Harden agent authentication.

### Tasks

- Protect agent credential verification material.
- Support revocation.
- Handle credential rotation/re-enrollment safely.
- Reject revoked agents immediately.
- Do not log raw agent credentials.

### Exit criteria

Compromised/revoked agent credentials can be invalidated without affecting other endpoints.

---

## Phase 19 — Real Endpoint Agent System Data

### Goal
Remove fake agent metrics.

### Tasks

- Collect actual CPU information.
- Collect actual RAM usage.
- Collect actual disk usage.
- Collect actual process count.
- Collect actual network connection count where already represented.
- Detect host OS/architecture reliably.
- Keep the existing telemetry shape.

### Exit criteria

Agent telemetry reflects actual endpoint state.

---

## Phase 20 — Agent Auto-Start & Reconnect Lifecycle

### Goal
Make the agent operational on endpoint machines.

### Tasks

- Provide supported automatic startup mechanism.
- Persist agent configuration/identity securely.
- Start after reboot.
- Reconnect after network loss.
- Handle server unavailable state without busy-looping.
- Exit cleanly.
- Preserve agent enrollment identity.

### Exit criteria

A rebooted endpoint reconnects automatically without manual re-enrollment.

---

## Phase 21 — Heartbeat & Health Lifecycle

### Goal
Make endpoint online/offline state trustworthy.

### Tasks

- Persist heartbeat records.
- Update `last_seen`.
- Determine offline state based on server-controlled timeout.
- Update health status.
- Avoid false online states.
- Surface the state through existing dashboard/agent views.

### Exit criteria

Disconnect/reconnect behavior is observable and accurate.

---

## Phase 22 — Telemetry Ingestion Pipeline

### Goal
Make telemetry ingestion durable and safe.

### Tasks

- Authenticate agent.
- Validate payload.
- Derive tenant/agent server-side.
- Persist event.
- protect against oversized payloads.
- add duplicate/idempotency handling where needed.
- maintain event timestamps correctly.

### Exit criteria

Telemetry survives backend restart and invalid input is rejected.

---

## Phase 23 — Detection Engine Production Integration

### Goal
Connect persistent telemetry and persistent detection rules to the existing detection engine.

### Tasks

- Load rules from PostgreSQL.
- Evaluate incoming telemetry.
- Preserve current existing rule semantics.
- Ensure environment filtering remains correct.
- Make detection deterministic.
- Write tests for current signatures.

### Exit criteria

Known training scenarios produce expected alerts from real stored telemetry.

---

## Phase 24 — Alert Lifecycle Completion

### Goal
Make the current alert queue production-safe.

### Tasks

- Persist alert creation/update.
- Validate status transitions.
- Validate rule/agent/org relationships.
- Persist evidence/trigger events.
- Persist comments.
- Persist assignment where already represented.
- Audit sensitive changes.

### Exit criteria

Alert lifecycle works across restart and respects RBAC/tenant boundaries.

---

## Phase 25 — Incident/Case Lifecycle Completion

### Goal
Make existing incident workflows transactional and durable.

### Tasks

- Create/update incidents safely.
- Link alerts safely.
- Persist timeline entries.
- Persist tasks.
- Persist notes.
- Validate lead investigator.
- Preserve current statuses/priorities.
- Audit major state changes.

### Exit criteria

Incident workflow survives restart and cross-tenant access is impossible.

---

## Phase 26 — PhishGuard Production Integration

### Goal
Persist and secure existing PhishGuard behavior.

### Tasks

- Validate/normalize URLs.
- Persist scans.
- Preserve feature extraction/classification behavior.
- Persist reasons/risk score.
- Preserve promote-to-alert behavior.
- enforce organization/user scope.

### Exit criteria

PhishGuard UI functions against real database data.

---

## Phase 27 — Threat Indicators / IOC Completion

### Goal
Make the existing indicator feature persistent and safe.

### Tasks

- Validate indicator types.
- Normalize values where already appropriate.
- Persist indicators.
- enforce confidence bounds.
- enforce tenant ownership.
- audit creation.

### Exit criteria

Indicator list/create operations are durable and authorized.

---

## Phase 28 — AI Assistant & Alert Analysis Hardening

### Goal
Make existing AI capabilities safe and reliable.

### Tasks

- Keep current AI features.
- Bound prompt/input size.
- Limit context to authorized tenant records.
- Preserve evidence/inference separation.
- Persist AI analysis in existing schema.
- Handle provider failure/timeouts.
- Never include secrets in model context.

### Exit criteria

AI works against real data without bypassing authorization.

---

## Phase 29 — Reports Completion

### Goal
Make existing reports durable.

### Tasks

- Generate current supported report types.
- Persist reports.
- Preserve existing report UI fields.
- enforce target ownership.
- audit generation.

### Exit criteria

Reports remain available after server restart.

---

## Phase 30 — Realtime SSE Completion

### Goal
Make the existing realtime dashboard trustworthy.

### Tasks

- Fix the frontend/backend SSE path mismatch.
- Add tenant-safe event routing.
- Add reconnect/backoff.
- Clean up disconnected clients.
- Handle heartbeat/reload events.
- Prevent cross-organization event leakage.

### Exit criteria

Live telemetry/agent/alert updates arrive reliably in the current UI.

---

## Phase 31 — Frontend API/Auth Contract Cleanup

### Goal
Make the current frontend use the finished backend cleanly.

### Tasks

- Reconcile `src/api.ts` with final API responses.
- Remove obsolete local-auth assumptions.
- remove development-only response fields.
- Preserve existing UI flows.
- Ensure 401/403/422/429/500 cases are handled.

### Exit criteria

No frontend screen depends on prototype-only backend behavior.

---

## Phase 32 — Observability & Operational Error Handling

### Goal
Make the system diagnosable in production.

### Tasks

- Structured server logging.
- Request correlation IDs.
- Safe error logs.
- Agent connection diagnostics.
- Health endpoint/check if needed by existing deployment requirements.
- Avoid noisy logs for normal heartbeats.

### Exit criteria

A deployment operator can determine why auth, database, agent, or AI requests failed without reading source code.

---

## Phase 33 — Retention & Data Lifecycle

### Goal
Enforce the existing organization retention setting.

### Tasks

- Apply `retentionDays` to applicable event/history data.
- Implement safe scheduled cleanup.
- Preserve necessary audit/governance history according to product intent.
- Never delete data across tenants.
- Log lifecycle jobs.

### Exit criteria

Retention is actually enforced rather than stored as a dead setting.

---

## Phase 34 — Production Configuration & Deployment

### Goal
Make the app deployable as a real SaaS.

### Tasks

- Separate client-safe and server-only environment variables.
- Configure Supabase.
- Configure Gemini securely.
- Configure application base URL.
- Configure agent server URL.
- document local/LAN deployment.
- document production deployment.
- add production build/run instructions.
- remove AI Studio-specific assumptions.

### Exit criteria

A fresh environment can be configured without source-code edits.

---

## Phase 35 — LAN / 10-PC End-to-End Validation

### Goal
Validate the actual intended deployment scenario.

### Scenario

```text
1 Main SOC PC
10 endpoint PCs
1 shared LAN / router / switch
1 agent per endpoint
```

### Tests

- Install agent on PC-01.
- Enroll it.
- Reboot it.
- Confirm automatic startup.
- Confirm heartbeat.
- Confirm telemetry.
- Repeat for multiple endpoints.
- Verify simultaneous agents remain isolated by identity.
- Disconnect one endpoint and verify offline state.
- Reconnect it and verify recovery.
- Trigger existing training telemetry.
- Confirm detection/alert creation.
- Confirm realtime dashboard updates.

### Exit criteria

The complete LAN workflow works without manual intervention after initial agent installation/configuration.

---

## Phase 36 — Final Production Audit & Scope Verification

### Goal
Final gate: verify that the project is complete and no unintended features were added.

### Audit checklist

- Existing frontend UI preserved.
- Existing routes preserved.
- Existing features work.
- PostgreSQL is authoritative.
- Supabase Auth is authoritative.
- RLS is enforced.
- RBAC is enforced.
- No cross-tenant access.
- No local JSON production path.
- No hard-coded passwords.
- No static MFA secret.
- No OTP returned in production.
- No unnecessary browser-stored auth token.
- Agent authentication is secure.
- Agent auto-start/reconnect works.
- Telemetry is real rather than fake.
- Detection rules still work.
- Alerts work.
- Incidents work.
- PhishGuard works.
- Indicators work.
- AI works.
- Reports work.
- Audit logs work.
- SSE works.
- Retention works.
- Deployment works.
- Build/typecheck/tests pass.

### Final scope test

Compare the final application against the original supplied frontend code.

Anything added that is not required to support an existing feature must be removed unless it is strictly necessary infrastructure/security plumbing.

---

# 11. Prompt Execution Rules For Every Phase

Every phase prompt must begin with an instruction equivalent to:

> Read `VR_SOC.md` fully enough to understand the scope lock, current architecture, current feature surface, dependencies, and the specific phase. Work only on the current phase. Do not redesign the frontend or add new product features.

Then the prompt must include:

1. Exact phase number/name.
2. Exact files/modules expected to be inspected.
3. Concrete implementation tasks.
4. Explicit “do not” constraints.
5. Validation commands/tests.
6. Completion criteria.
7. A requirement to report any discovered scope conflict instead of silently inventing behavior.

### Phase discipline

- Do not execute multiple unrelated phases in one prompt.
- Do not skip validation.
- Do not mark a phase complete because code was written; verify behavior.
- Fix regressions created by the current phase before moving on.
- Preserve existing working behavior.
- Update documentation only when the current phase requires it.

---

# 12. Definition Of Done — Entire Product

The project is complete only when all of the following are true:

### Product

The supplied frontend remains the same product and all existing user-facing capabilities work.

### SaaS

Multiple organizations can use the same application securely with strict tenant isolation.

### Backend

The existing Express backend is production-backed by Supabase PostgreSQL and has validated, authorized, auditable APIs.

### Authentication

Supabase Auth is authoritative, MFA is real, and verification flows are real.

### Endpoint

Agents can be installed on endpoint PCs, start automatically, authenticate, send telemetry, reconnect, and become offline/online correctly.

### SOC

Telemetry → detection → alert → incident/case → audit/report/realtime flow works end-to-end.

### Security

Secrets, sessions, tenant boundaries, agent credentials, and sensitive operations are protected.

### Operations

The application can be configured, deployed, restarted, observed, and recovered without relying on demo-only behavior.

### Scope

No unrelated product features were added.

---

# 13. Important Engineering Notes

## Preserve current frontend contracts

The current frontend is the reference for user-facing behavior. Backend work should adapt to the frontend rather than forcing a redesign.

## Prefer incremental migration

Where the local JSON database currently contains business logic, extract the business logic into services and swap persistence beneath it rather than rewriting everything at once.

## Do not duplicate authorization

UI visibility can be improved, but authorization must be enforced in the backend and database.

## Do not trust agent-provided tenant identity

Agent identity authenticates the endpoint. Organization ownership comes from the server-side agent record.

## Do not expose service-role secrets

The Supabase service role key and Gemini server credentials must never reach browser bundles or endpoint agents.

## Keep training isolated

The current product explicitly contains a Training Lab environment. Maintain production vs training separation in storage/querying/events.

## Do not confuse remediation text with command execution

Current remediation steps are recommendations/instructions represented in the UI. They are not permission to create an arbitrary remote-command engine.

---

# 14. Known Existing Contract Bug To Resolve Early

### SSE mismatch

Current frontend:

```text
/api/sse/stream
```

Current backend:

```text
/api/events/stream
```

This must be fixed as part of realtime completion. Do not introduce a second parallel realtime protocol.

---

# 15. Recommended Validation Matrix

Every finished phase should be checked against the applicable layers:

```text
Build / Typecheck
       ↓
Unit / Service tests
       ↓
API tests
       ↓
Database / RLS tests
       ↓
Frontend integration
       ↓
Agent integration
       ↓
End-to-end workflow
```

Security-sensitive phases must include negative tests, not only success tests.

Examples:

- invalid auth token
- expired session
- revoked agent
- wrong organization
- missing permission
- malformed telemetry
- oversized payload
- duplicate event
- expired OTP
- invalid MFA code
- unauthenticated SSE
- unauthorized report access

---

# 16. Final Instruction To The Coding Agent

**This document is the scope constitution for the current VRSOC project.**

You are not being asked to invent VRSOC 2.0.

You are being asked to finish and productionize the VRSOC application that already exists in the supplied codebase.

Preserve the frontend product. Preserve existing workflows. Reuse existing code where valid. Replace only what is necessary to make the current functionality real, secure, persistent, multi-tenant, testable, and deployable.

When a requirement is missing, infer only from the existing code, current API contracts, current types, current database schema, and current UI behavior. Do not invent unrelated product scope.

**Target state:** the same VRSOC product, but actually functioning as a secure SaaS platform with real Supabase persistence/authentication, real endpoint agents, real telemetry ingestion, real detection/alert/incident workflows, real realtime updates, and production-grade operational behavior.
