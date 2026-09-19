# Phase 00 — Baseline Audit

## 1. Repository Summary

* **Project Name**: VRSOC — Enterprise Security Operations Center Platform
* **Repository Path**: `c:\Users\om\Desktop\VRSOC`
* **Audit Date & Time**: 2026-09-19T19:30:00+05:30
* **Audit Mode**: Baseline Freeze & Audit Only (No implementation modifications made)
* **Single Source of Truth Document**: Project Specification / Execution Constitution (Note: `VR_SOC.md` was referenced as the constitutional document for Phase 00 requirements; the audit reconciles all architecture, schemas, and gaps directly against the codebase).
* **Repository Topology**:
  * **Root**: Build tooling, environment definitions, and unified Node.js/Express server entrypoint (`server.ts`).
  * **Frontend (`src/`)**: Single-Page Application built with React 19, TypeScript, Tailwind CSS v4, and Lucide React. Contains 10 main SOC views, 2 dedicated authentication sub-pages, command palette, and modal dialogues.
  * **Backend (`server/`)**: Express API server with local JSON datastore, Gemini AI engine, PhishGuard ML feature analysis, rule-based detection engine, and Server-Sent Events (SSE) broadcaster.
  * **Agent (`agent/`)**: Standalone Node.js endpoint telemetry collector (`agent/vrsoc-agent.js`).
  * **Database (`supabase/migrations/` & `data/`)**: Supabase PostgreSQL migration (`20260919000000_vrsoc_core_schema.sql`) and local JSON snapshot store (`data/vrsoc.db.json`).

---

## 2. Technology Stack Actually Detected

| Layer | Declared / Detected Technology | Version | Key Dependencies / Packages | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend Framework** | React (SPA) | `19.0.1` | `react`, `react-dom` | StrictMode enabled in `src/main.tsx` |
| **Build & Dev Tooling** | Vite | `8.3.0` | `vite`, `@vitejs/plugin-react`, `tsx` (`4.21.0`), `esbuild` (`0.25.0`) | Embedded inside Express in development via `createViteServer` |
| **Styling & Icons** | Tailwind CSS + Lucide | `4.3.3` / `0.546.0` | `@tailwindcss/vite`, `tailwindcss`, `lucide-react`, `motion` (`12.23.24`) | Tailwind v4 Vite plugin configured |
| **Type Checking** | TypeScript | `7.0.2` | `typescript`, `@types/node` (`22.14.0`), `@types/react` (`19.3.0`) | Configured in `tsconfig.json` |
| **Backend Runtime** | Node.js + Express | `v22.23.2` / `4.21.2` | `express`, `cookie-parser` (`1.4.7`), `dotenv` (`17.2.3`) | Unified HTTP & API server in `server.ts` |
| **Authentication** | Supabase Auth + Local Fallback | `2.116.0` | `@supabase/supabase-js`, `crypto` (PBKDF2) | Client-side Supabase client + Server JWT verification |
| **Database / Datastore** | In-Memory + JSON Persistence | N/A | `data/vrsoc.db.json` | Local JSON atomic write (`.tmp` + rename). Supabase PostgreSQL migration present but not connected at runtime. |
| **Realtime Stream** | Server-Sent Events (SSE) | Custom | `text/event-stream` over HTTP | Custom client registry with 30s heartbeat pings |
| **AI / Copilot** | Google GenAI SDK | `2.4.0` | `@google/genai` | Uses `gemini-3.8-flash` model with grounded prompt templates & deterministic fallback |
| **Endpoint Agent** | Node.js CLI Daemon | 1.4.0 | Native `os`, `http`, `https`, `crypto` | Standalone script `agent/vrsoc-agent.js` |

---

## 3. Frontend Routes and Features

The frontend is architected as a React SPA with state-driven view switching in `src/App.tsx`, synchronized with browser history (`pushState` / `popstate`) for URL navigation.

### Routes & Pseudo-Routes
1. `/` — Primary SOC Application Workspace (switches active tab state).
2. `/login` — Sign-in modal view.
3. `/signup` — Organization registration modal view.
4. `/verify-email` — Dedicated 6-digit email OTP verification page (`VerifyEmailPage.tsx`).
5. `/verify-phone` — Dedicated E.164 SMS OTP verification page (`VerifyPhonePage.tsx`).
6. `/reset-password` — Password recovery flow.

### Views (10 Major Product Areas)
1. **Dashboard (`DashboardView.tsx`)**: Real-time SOC overview, threat posture indicator, active alert counter, connected agent summary, quick phishing URL scanner, telemetry simulation trigger, and MITRE ATT&CK activity map.
2. **Agents / Endpoints (`AgentsView.tsx`)**: Monitored host inventory, OS/architecture details, IP addresses, real-time CPU/RAM/Disk gauges, last-seen heartbeat counters, endpoint event log viewer, and agent revocation control.
3. **Alerts (`AlertsView.tsx`)**: Active alert triage queue, severity filters, MITRE tactic/technique tags, triage status updates (`open`, `investigating`, `contained`, `resolved`, `false_positive`), evidence inspection cards (strictly classified into `CONFIRMED`, `INFERRED`, `UNKNOWN`), analyst comments, and AI-grounded investigation analysis trigger.
4. **Incidents (`IncidentsView.tsx`)**: Multi-alert case management, incident creation, priority/severity badges, lead investigator assignment, interactive investigation checklist tasks, timeline event builder with evidence states, and analyst notes.
5. **PhishGuard (`PhishGuardView.tsx`)**: Deep URL inspection utilizing 13 structural and lexical features, Random Forest risk score (0–100), classification badge (`Safe`, `Suspicious`, `Phishing`), URL anatomy breakdown, brand impersonation detection, and one-click promotion to high-severity SOC alert.
6. **Detection Rules (`DetectionRulesView.tsx`)**: Rule repository with MITRE ATT&CK technique IDs, severity, risk scores, remediation guidance, real-time enable/disable toggle, and custom rule creator.
7. **AI Copilot (`AiAssistantView.tsx`)**: Grounded conversational AI assistant for SOC analysts with pre-configured prompts (e.g., investigating Mimikatz, PowerShell decoding, ransomware containment, brute force analysis) grounded in active telemetry.
8. **Reports (`ReportsView.tsx`)**: Generation of Executive Cybersecurity Summaries and Incident Investigation Reports with export/print capability.
9. **Audit Logs (`AuditLogsView.tsx`)**: Immutable SOC audit trail recording user logins, key rotations, agent enrollments/revocations, rule modifications, and incident status updates.
10. **Settings (`SettingsView.tsx`)**: Organization details, 14-character hexadecimal VRSOC Key display and rotation, TOTP/MFA configuration, and environment switching (`production` vs `training`).

### Supporting Components & Modals
* `Navbar.tsx`: Header navigation, active environment badge, SSE connection status indicator, command palette button, agent enrollment shortcut, and user profile/logout menu.
* `AddAgentModal.tsx`: Three-tab agent deployment wizard: In-Browser collector authorization, Node.js CLI installation snippet, and manual script download.
* `CommandPalette.tsx`: Global `Ctrl+K` / `Cmd+K` palette for quick navigation, agent deployment, and one-click threat scenario simulation.
* `AuthModal.tsx`: Multi-step authentication dialog managing signup, login, OTP transitions, MFA enrollment, and 14-character hexadecimal security key presentation.

---

## 4. Backend API Inventory

| HTTP Method | Route | Auth Required | Org Scoped | Role / Permission | Request Body | Response Shape | Datastore Operation | Implementation Status | Issues / Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/auth/config` | No | No | None | None | `{ supabaseUrl, supabaseAnonKey, isConfigured }` | Memory / Env | `WORKING` | Returns public configuration |
| `POST` | `/api/auth/complete-onboarding` | Yes | Generated | Org Admin | `{ organizationName, fullName?, phoneNumber? }` | `{ success, profile, organization, vrSocKey }` | `db.createOrganization`, `db.updateProfile` | `WORKING` | Generates 14-char hex key |
| `POST` | `/api/auth/signup` | No | Generated | Org Admin | `{ fullName, email, phoneNumber?, password, organizationName }` | `{ profile, organization, sessionToken, emailOtp, phoneOtp, devHint }` | `db.createProfile`, `db.createOrganization` | `WORKING` | Returns OTPs in JSON response |
| `POST` | `/api/auth/login` | No | Yes | Any | `{ email, password }` | `{ profile, organization, sessionToken }` | `db.getProfileByEmail`, `db.verifyPassword` | `WORKING` | Verifies PBKDF2 hash |
| `POST` | `/api/auth/resend-email-otp` | Yes | No | Any | None | `{ success, message, emailOtp, devHint }` | `db.setOtp` | `WORKING` | Returns OTP in JSON response |
| `POST` | `/api/auth/resend-phone-otp` | Yes | No | Any | None | `{ success, message, phoneOtp, devHint }` | `db.setOtp` | `WORKING` | Returns OTP in JSON response |
| `POST` | `/api/auth/verify-email-otp` | Yes | No | Any | `{ otp }` | `{ success, profile }` | `db.verifyOtp`, `db.updateProfile` | `WORKING` | Validates OTP code |
| `POST` | `/api/auth/verify-phone-otp` | Yes | No | Any | `{ otp }` | `{ success, profile }` | `db.verifyOtp`, `db.updateProfile` | `WORKING` | Validates OTP code |
| `POST` | `/api/auth/mfa-setup` | Yes | No | Any | None | `{ mfaSecret, qrUri }` | Memory | `DEMO/LOCAL` | Hardcoded secret `JBSWY3DPEHPK3PXP` |
| `POST` | `/api/auth/mfa-verify` | Yes | No | Any | `{ token }` | `{ success, profile }` | `db.updateProfile` | `DEMO/LOCAL` | Accepts any 6-digit regex |
| `GET` | `/api/auth/me` | Yes | Yes | Any | None | `{ profile, organization, sessionToken }` | `db.getSession` | `WORKING` | Validates Bearer/Cookie token |
| `POST` | `/api/auth/logout` | No | No | None | None | `{ success }` | `db.deleteSession` | `WORKING` | Clears cookie and session |
| `POST` | `/api/organizations/key/rotate` | Yes | Yes | Super/Org Admin | None | `{ success, vrSocKey, message }` | `db.rotateVrSocKey` | `WORKING` | Regenerates 14-char hex key |
| `GET` | `/api/organizations/metrics` | Yes | Yes | Any | Query: `environment` | `{ metrics }` | `db.getRealMetrics` | `WORKING` | Computes live counts |
| `GET` | `/api/agents` | Yes | Yes | Any | None | `{ agents }` | `db.getAgents` | `WORKING` | Filtered by org ID |
| `GET` | `/api/agents/:id` | Yes | Yes | Any | None | `{ agent, events }` | `db.getAgentById`, `db.getEndpointEvents` | `WORKING` | Validates org ownership |
| `POST` | `/api/agents/:id/revoke` | Yes | Yes | Any | None | `{ success, agent }` | `db.revokeAgent` | `WORKING` | Broadcasts `agent_updated` |
| `POST` | `/api/agent/enroll` | Key | Key-based | Agent | `{ enrollmentKey, name, hostname, os, ... }` | `{ agent, agentToken }` | `WORKING` | Validates 14-char hex key |
| `POST` | `/api/agent/heartbeat` | Agent Token | Agent-based | Agent | `{ agentId, agentToken, cpuUsage, ramUsage, diskUsage }` | `{ status, nextHeartbeatSeconds }` | `db.updateAgent` | `WORKING` | Broadcasts `agent_heartbeat` |
| `POST` | `/api/agent/telemetry` | Agent Token | Agent-based | Agent | `{ agentId, agentToken, eventType, severity, data }` | `{ status, eventId, triggeredAlert }` | `db.addEndpointEvent`, `detectionEngine` | `WORKING` | Evaluates detection engine |
| `POST` | `/api/telemetry/simulate` | Yes | Yes | Any | `{ scenario, agentId? }` | `{ success, event, agent, triggeredAlert }` | `db.addEndpointEvent`, `detectionEngine` | `WORKING` | Ingests threat scenario |
| `GET` | `/api/agent/script` | No | No | None | None | File download (`vrsoc-agent.js`) | File system (`agent/`) | `WORKING` | Serves static agent script |
| `GET` | `/api/detection-rules` | Yes | Yes | Any | None | `{ rules }` | `db.getDetectionRules` | `WORKING` | Merges system & custom rules |
| `POST` | `/api/detection-rules/:id/toggle` | Yes | Yes | Any | `{ enabled }` | `{ success, ruleId, enabled }` | `db.toggleDetectionRule` | `WORKING` | Updates rule status |
| `POST` | `/api/detection-rules` | Yes | Yes | Any | `{ name, description, severity, ... }` | `{ rule }` | `db.addDetectionRule` | `WORKING` | Generates custom rule ID |
| `GET` | `/api/alerts` | Yes | Yes | Any | Query: `environment` | `{ alerts }` | `db.getAlerts` | `WORKING` | Filtered by org & env |
| `GET` | `/api/alerts/:id` | Yes | Yes | Any | None | `{ alert }` | `db.getAlertById` | `WORKING` | Validates org ownership |
| `PATCH` | `/api/alerts/:id/status` | Yes | Yes | Any | `{ status }` | `{ alert }` | `db.updateAlert` | `WORKING` | Broadcasts `alert_updated` |
| `POST` | `/api/alerts/:id/comment` | Yes | Yes | Any | `{ comment }` | `{ alert }` | `db.addAlertComment` | `WORKING` | Appends analyst comment |
| `POST` | `/api/alerts/:id/ai-analyze` | Yes | Yes | Any | None | `{ aiSummary, alert }` | `analyzeAlertWithAi`, `db.updateAlert` | `WORKING` | Gemini API / Grounded fallback |
| `GET` | `/api/incidents` | Yes | Yes | Any | Query: `environment` | `{ incidents }` | `db.getIncidents` | `WORKING` | Filtered by org & env |
| `POST` | `/api/incidents` | Yes | Yes | Any | `{ title, description, severity, ... }` | `{ incident }` | `db.createIncident` | `WORKING` | Broadcasts `new_incident` |
| `GET` | `/api/incidents/:id` | Yes | Yes | Any | None | `{ incident, linkedAlerts }` | `db.getIncidentById` | `WORKING` | Resolves linked alert objects |
| `PATCH` | `/api/incidents/:id` | Yes | Yes | Any | `Partial<Incident>` | `{ incident }` | `db.updateIncident` | `WORKING` | Updates incident fields |
| `POST` | `/api/incidents/:id/task` | Yes | Yes | Any | `{ title }` | `{ incident }` | `db.addIncidentTask` | `WORKING` | Appends task |
| `PATCH` | `/api/incidents/:id/task/:taskId` | Yes | Yes | Any | `{ completed }` | `{ incident }` | `db.toggleIncidentTask` | `WORKING` | Toggles task completion |
| `POST` | `/api/incidents/:id/timeline` | Yes | Yes | Any | `{ title, description, type, evidenceState }` | `{ incident }` | `db.addIncidentTimelineItem` | `WORKING` | Records timeline item |
| `POST` | `/api/incidents/:id/note` | Yes | Yes | Any | `{ note }` | `{ incident }` | `db.addIncidentNote` | `WORKING` | Appends analyst note |
| `POST` | `/api/phishguard/scan` | Yes | Yes | Any | `{ url }` | `{ scan, analysis }` | `analyzeUrlWithPhishGuard`, `db.addPhishingScan` | `WORKING` | Full heuristic/ML analysis |
| `POST` | `/api/phishguard/promote-to-alert` | Yes | Yes | Any | `{ scanId }` | `{ success, alert }` | `db.createAlert` | `WORKING` | Converts scan to alert |
| `GET` | `/api/phishguard/scans` | Yes | Yes | Any | None | `{ scans }` | `db.getPhishingScans` | `WORKING` | Returns scan history |
| `POST` | `/api/ai/chat` | Yes | Yes | Any | `{ message, context? }` | `{ reply }` | `chatWithAiAnalyst` | `WORKING` | Gemini API / Grounded fallback |
| `GET` | `/api/indicators` | Yes | Yes | Any | None | `{ indicators }` | `db.getIndicators` | `WORKING` | Returns IOC threat feed |
| `POST` | `/api/indicators` | Yes | Yes | Any | `{ type, value, threatActor, ... }` | `{ indicator }` | `db.addIndicator` | `WORKING` | Creates IOC record |
| `GET` | `/api/audit-logs` | Yes | Yes | Any | None | `{ logs }` | `db.getAuditLogs` | `WORKING` | Returns org audit trail |
| `POST` | `/api/reports/generate` | Yes | Yes | Any | `{ reportType, targetId? }` | `{ report }` | `db.addReport` | `WORKING` | Formats executive/incident report |
| `GET` | `/api/reports` | Yes | Yes | Any | None | `{ reports }` | `db.getReports` | `WORKING` | Returns generated reports |
| `GET` | `/api/events/stream` | Yes | Yes | Any | None | SSE Stream (`text/event-stream`) | `registerClient` | `BROKEN` | Frontend connects to `/api/sse/stream` |

---

## 5. Database / Supabase Inventory

### Current Datastore Architecture
The backend at runtime operates **exclusively in-memory** with atomic JSON file persistence (`data/vrsoc.db.json`). While a full PostgreSQL migration file is maintained under `supabase/migrations/20260919000000_vrsoc_core_schema.sql`, the backend Express API does not execute SQL queries against Supabase PostgreSQL.

### Database Tables & Schema Comparison

| Entity / Table | Runtime Store Used? | Migration Exists? | Frontend Uses It? | Backend Uses It? | RLS in Migration? | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `organizations` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `profiles` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `organization_members`| Yes (JSON) | Yes | Indirectly | Yes | Yes | `LOCAL` |
| `teams` | No | Yes | No | No | No (Unreferenced) | `MIGRATION ONLY` |
| `team_members` | No | Yes | No | No | No (Unreferenced) | `MIGRATION ONLY` |
| `user_sessions` | Yes (JSON) | Yes | Yes | Yes | No | `LOCAL` |
| `agents` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `agent_heartbeats` | No (Stats in Agent) | Yes | No | No (Ephemeral) | Yes | `MIGRATION ONLY` |
| `endpoint_events` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `detection_rules` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `alerts` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `alert_comments` | Embedded in Alert | Yes (Separate Table) | Yes | Yes | No | `CONTRACT MISMATCH` |
| `incidents` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `incident_alerts` | Array in Incident | Yes (Junction Table) | Yes | Yes | Yes | `CONTRACT MISMATCH` |
| `incident_timeline` | Array in Incident | Yes (Separate Table) | Yes | Yes | Yes | `CONTRACT MISMATCH` |
| `incident_tasks` | Array in Incident | Yes (Separate Table) | Yes | Yes | Yes | `CONTRACT MISMATCH` |
| `phishing_scans` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `indicators` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `audit_logs` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `reports` | Yes (JSON) | Yes | Yes | Yes | Yes | `LOCAL` |
| `ai_analyses` | Embedded in Alert | Yes (Separate Table) | Yes | Yes | Yes | `CONTRACT MISMATCH` |

---

## 6. Authentication Audit

1. **Dual-Stack Authentication**:
   * **Client-Side**: `src/lib/supabase.ts` communicates directly with Supabase Auth when configured (`supabaseSignUp`, `supabaseVerifyEmailOtp`, `supabaseSendPhoneOtp`, `supabaseVerifyPhoneOtp`, `supabaseSignInWithPassword`, `supabaseEnrollMfa`, `supabaseVerifyMfa`).
   * **Server-Side Fallback**: `server.ts` and `server/db.ts` implement custom PBKDF2 password hashing, in-memory session tokens, and custom 6-digit numeric OTP generation stored in `otpStore`.
2. **Authoritative Provider**:
   * When `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are provided, the server verifies incoming Bearer tokens using `supabaseAdmin.auth.getUser(token)` and maps the Supabase user to local profiles.
   * In local/unconfigured mode, the server authenticates using custom tokens stored in `vrsoc_session` HTTP-only cookies or Bearer headers.
3. **Token Storage & Exposure**:
   * Supabase JWTs and local session tokens are saved in browser `localStorage` (`vrsoc_token`) and in `vrsoc_session` cookies.
4. **Hardcoded Secrets & OTP Exposure**:
   * `POST /api/auth/signup`, `POST /api/auth/resend-email-otp`, and `POST /api/auth/resend-phone-otp` explicitly return `emailOtp`, `phoneOtp`, and `devHint` in HTTP response JSON bodies.
   * `POST /api/auth/mfa-setup` returns a static base32 secret `'JBSWY3DPEHPK3PXP'`.
   * `POST /api/auth/mfa-verify` validates any 6-digit numeric token without RFC 6238 TOTP computation.
   * `server/db.ts` seeds hardcoded admin credentials: `analyst@vrsoc.cyber` with password `VrsocPassword2026!`.
   * `src/components/AuthModal.tsx` contains a quick-fill demo button with `admin@vrsoc.cyber` and `VRSOC-Security2025!`, which fails to authenticate against the seeded database credentials.

---

## 7. RBAC Audit

1. **Role Hierarchy**:
   * Defined Roles: `Super Admin`, `Organization Admin`, `Instructor`, `SOC Analyst`, `Incident Responder`, `Threat Hunter`, `Auditor`, `Viewer`, `Student`.
2. **Backend Enforcement**:
   * **Only 1 endpoint** checks roles: `POST /api/organizations/key/rotate` verifies `user.role === 'Super Admin' || user.role === 'Organization Admin'`.
   * **All other endpoints** only verify `requireAuth` without role differentiation. Any authenticated user (including `Student` or `Viewer`) can revoke agents, toggle/create detection rules, update incident statuses, or modify alerts.
3. **Frontend Guarding**:
   * UI components display role badges but do not conditionally disable mutation controls based on specific permissions.

---

## 8. Multi-Tenancy Audit

1. **Tenant Identification**:
   * Organization context is derived server-side in `requireAuth` from the verified session or user membership (`db.getUserOrganizations(profile.id)`).
2. **Data Scoping**:
   * All API queries for agents, alerts, incidents, rules, scans, indicators, audit logs, and reports filter records by `organizationId === org.id`.
3. **Agent Scoping**:
   * Agents are enrolled using the organization's unique 14-character hexadecimal security key (`vrSocKey`).
   * Agent heartbeats and telemetry are authorized via `agentToken` and bound to the agent's registered `organizationId`.
4. **Vulnerability / Bypass Note**:
   * Because PostgreSQL RLS is not active at the runtime data layer, multi-tenancy relies exclusively on Express application-level filtering in `server/db.ts`.

---

## 9. Endpoint Agent Audit

1. **Agent Implementation**:
   * Implemented in `agent/vrsoc-agent.js` as a standalone Node.js CLI script.
   * Can be executed via: `node vrsoc-agent.js --enroll <14_HEX_KEY> --server <URL> [--name <NAME>] [--test <SCENARIO>]`.
2. **Enrollment & Credentials**:
   * Validates that the enrollment key is strictly 14 hexadecimal characters (`/^[0-9A-F]{14}$/`).
   * Enrolls via `POST /api/agent/enroll` and receives a unique `agentId` and `agentToken` stored in process memory.
3. **Telemetry Metrics Categorization**:
   * **REAL Telemetry**: Hostname, OS type, kernel release, CPU architecture, core count, total memory, free memory, calculated RAM percentage, local IPv4 network address, process PID, and launching user context.
   * **SIMULATED / HARDCODED Telemetry**:
     * Disk usage is hardcoded to `45%` in agent heartbeats and `40%` in in-browser simulation.
     * Active process count is hardcoded to `64`.
     * Network connection count is hardcoded to `12`.
     * CPU usage is estimated using `os.loadavg()[0] * 10` with bounds between 5% and 99%.
4. **Execution Model**:
   * Plain Node.js process (daemonized via `setInterval`). No systemd unit, Windows Service wrapper, or OS daemon packaging currently exists.

---

## 10. Realtime / SSE Audit

1. **Endpoint Disconnect**:
   * **Frontend URL (`src/App.tsx:122`)**: `EventSource('/api/sse/stream?environment=production')`
   * **Backend URL (`server.ts:1356`)**: `app.get('/api/events/stream', ...)`
   * **Result**: The frontend SSE connection attempts to connect to a non-existent route `/api/sse/stream`, receiving 404 or Vite HTML fallback, causing the live SSE indicator to disconnect.
2. **Subscription Lifecycle & Reconnect**:
   * SSE connection registers client in a `Map<clientId, Client>` with a 30-second interval sending `: ping\n\n`.
   * On connection close, the interval is cleared and the client is pruned.
3. **Event Schema Mismatches**:
   * Frontend expects an `initial_sync` event with `{ metrics, alerts, agents }`, but the backend only emits `{ type: 'connected', time: '...' }` upon connection.

---

## 11. AI / PhishGuard / Detection Audit

1. **AI Engine (`server/aiEngine.ts`)**:
   * Uses `@google/genai` with model `gemini-3.8-flash`.
   * Requires `GEMINI_API_KEY`.
   * When the API key is missing or calls fail, a deterministic evidence-grounded fallback generates structured analysis categorizing findings strictly into `CONFIRMED`, `INFERRED`, and `UNKNOWN` states.
2. **PhishGuard ML Engine (`server/phishguard.ts`)**:
   * Implements 13 URL lexical and structural feature extractors (IP host, URL length, URL shorteners, `@` symbol, double slash, hyphens, subdomain depth, HTTPS protocol, suspicious TLDs, non-standard ports, HTTPS in domain, sensitive keywords, and hex percentage encodings).
   * Calculates a Random Forest simulated risk score (0–100) and maps high-risk threats to MITRE ATT&CK `T1566.002` (Spearphishing Link).
   * Fully functional in pure TypeScript without external microservice dependencies.
3. **Detection Engine (`server/detectionEngine.ts`)**:
   * Rule engine evaluates telemetry against 8 default detection rules:
     * `RULE-AUTH-001`: Brute force logon failures (5 failures in 5 min window).
     * `RULE-AUTH-002`: Account lockout events.
     * `RULE-PROC-001`: Suspicious/obfuscated PowerShell execution (`-enc`, `-w hidden`, `-nop`, `bypass`, `downloadstring`, `iex(`).
     * `RULE-PERS-001`: Persistence via scheduled tasks / cron (`schtasks /create`, `crontab -e`).
     * `RULE-NET-001`: Network reconnaissance port sweeps.
     * `RULE-DEV-001`: Removable USB mass storage insertion.
     * `RULE-PHISH-001`: High-risk phishing URL promotion.
     * `RULE-HEART-001`: Endpoint agent heartbeat loss.

---

## 12. Security Findings

1. **[CRITICAL] OTP Code Exposure in API Responses**:
   * Endpoints `POST /api/auth/signup`, `POST /api/auth/resend-email-otp`, and `POST /api/auth/resend-phone-otp` return `emailOtp`, `phoneOtp`, and `devHint` in cleartext response payloads.
2. **[HIGH] Mocked MFA Implementation in Backend**:
   * `POST /api/auth/mfa-setup` returns a fixed secret `JBSWY3DPEHPK3PXP`.
   * `POST /api/auth/mfa-verify` validates any 6-digit numeric string without computing TOTP RFC 6238 time windows.
3. **[HIGH] Missing Server-Side Authorization Checks (Broken RBAC)**:
   * Endpoints modifying rules, revoking agents, updating incidents, and changing alert statuses only verify authentication, ignoring user roles.
4. **[HIGH] Mismatched Demo Credentials & Seed Discrepancy**:
   * `server/db.ts` seeds `analyst@vrsoc.cyber` / `VrsocPassword2026!`.
   * `AuthModal.tsx` demo button fills `admin@vrsoc.cyber` / `VRSOC-Security2025!`.
5. **[MEDIUM] In-Memory Database Bypass of Database RLS**:
   * All queries execute in-memory against `data/vrsoc.db.json`; Supabase PostgreSQL RLS policies in `supabase/migrations/` are not enforced at runtime.
6. **[MEDIUM] Lack of Rate Limiting**:
   * No rate-limiting middleware on auth, OTP verification, agent telemetry ingestion, or PhishGuard scanning endpoints.
7. **[LOW] Sensitive Public Environment Config Fetch**:
   * `GET /api/auth/config` exposes public Supabase URL and anon key over an unauthenticated endpoint.

---

## 13. Environment / Deployment Findings

### Environment Variables Inventory

| Variable Name | Required / Optional | Where Defined / Referenced | Production Usage | Detected State |
| :--- | :--- | :--- | :--- | :--- |
| `GEMINI_API_KEY` | Optional | `.env.example`, `server/aiEngine.ts` | Gemini AI API calls | Unset / Default placeholder |
| `APP_URL` | Optional | `.env.example` | Self-referential links / OAuth | Unset |
| `VITE_SUPABASE_URL` | Optional | `.env.example`, `src/lib/supabase.ts`, `server/supabase.ts` | Client-side Supabase URL | Unset |
| `VITE_SUPABASE_ANON_KEY` | Optional | `.env.example`, `src/lib/supabase.ts`, `server/supabase.ts` | Client-side Supabase Anon Key | Unset |
| `SUPABASE_URL` | Optional | `.env.example`, `server/supabase.ts` | Server Supabase URL | Unset |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional | `.env.example`, `server/supabase.ts` | Server Admin JWT verification | Unset |
| `SMS_PROVIDER` / `SMS_API_KEY` | Optional | `.env.example` | External SMS Gateway | Unset |
| `AGENT_ENROLLMENT_SECRET` | Optional | `.env.example` | Secondary agent validation | Unset |
| `PHISHGUARD_SERVICE_URL` | Optional | `.env.example` | External ML microservice | Unset |
| `NODE_ENV` | Optional | `server.ts`, `server/db.ts` | Production/development mode switch | Defaults to dev |

### Build and Execution Commands
* **Typecheck (Lint)**: `npx tsc --noEmit` (or `npm run lint`)
* **Frontend Build**: `npx vite build`
* **Full Production Build**: `npm run build` (`vite build && esbuild server.ts --bundle --platform=node --format=cjs --packages=external --sourcemap --outfile=dist/server.cjs`)
* **Production Start**: `npm run start` (`node dist/server.cjs`)
* **Development Server**: `npm run dev` (`tsx server.ts`)

---

## 14. Build / Typecheck / Test Results

| Command | Status | Result / Error Output | Root Cause / Explanation |
| :--- | :--- | :--- | :--- |
| `npx tsc --noEmit` | **PASS** | Exit code 0, 0 errors | TypeScript codebase has clean static typing. |
| `npm run lint` | **PASS (with npx)** | `tsc --noEmit` exits with 0 | When executed in environment with PATH to `tsc`, linting succeeds cleanly. |
| `npx vite build` | **PASS** | `dist/` created (1.00 kB HTML, 43.43 kB CSS, 636.16 kB JS) | Client bundle successfully built in 425ms. |
| `npm run build` | **PASS** | Vite client + `dist/server.cjs` (104.2 kB) generated | Full client and server bundling completed cleanly. |
| `node dist/server.cjs` | **PASS** | Server starts and listens on `http://0.0.0.0:3000` | Logs configuration notice and initializes cleanly. |
| `npm run dev` | **PASS** | `tsx server.ts` starts dev server with Vite middleware | Successfully boots on port 3000. |
| `npm test` | **MISSING** | `npm error Missing script: "test"` | No automated test script is defined in `package.json`. |

---

## 15. Frontend ↔ Backend Contract Mismatches

| # | Component / Contract | Frontend Implementation | Backend Implementation | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **SSE Stream URL** | `src/App.tsx:122` connects to `/api/sse/stream` | `server.ts:1356` listens on `/api/events/stream` | Real-time SSE stream fails with 404 in browser. |
| **2** | **SSE Initial Event** | `src/App.tsx:134` listens for `initial_sync` with `{ metrics, alerts, agents }` | `server/sse.ts:17` only writes `{ type: 'connected', time }` | Initial sync via SSE does not populate state on connect. |
| **3** | **Demo Credentials** | `src/components/AuthModal.tsx:578` fills `admin@vrsoc.cyber` / `VRSOC-Security2025!` | `server/db.ts:470` seeds `analyst@vrsoc.cyber` / `VrsocPassword2026!` | Clicking "Use Demo Credentials" results in 404/401 error. |
| **4** | **Datastore Connection** | Frontend expects persistent enterprise storage (Supabase or DB) | Backend operates in-memory with `data/vrsoc.db.json` file snapshot | PostgreSQL migrations are decoupled from API runtime. |
| **5** | **Relational vs Embedded Entities** | Relational tables in migration (`incident_alerts`, `incident_tasks`, `incident_timeline`, `alert_comments`, `ai_analyses`) | Backend embeds arrays directly inside parent JSON documents (`incident.tasks`, `alert.comments`) | Mismatch between SQL schema structure and backend JSON models. |
| **6** | **Agent Heartbeat Payload** | `agent/vrsoc-agent.js:141` sends `activeProcessesCount` and `networkConnectionsCount` | `server.ts:549` and `server/db.ts:1145` only parse `cpuUsage`, `ramUsage`, `diskUsage` | Process and network counts from agent heartbeats are discarded. |

---

## 16. VR_SOC.md Gap Reconciliation

| Gap ID | Description | Status | Codebase Evidence |
| :--- | :--- | :--- | :--- |
| **GAP-01** | Unified Multi-Tenant Organization & 14-Character Hex Key Model | **CONFIRMED** | 14-char hex key generation implemented in `server/db.ts:828`, but RLS isolation is bypassed at DB layer. |
| **GAP-02** | Supabase Auth Integration & Dual-Path Authentication | **CONFIRMED** | Client Supabase methods in `src/lib/supabase.ts`, server token verification in `server/supabase.ts`, local PBKDF2 fallback in `server/db.ts`. |
| **GAP-03** | MFA / TOTP Authenticator Enrollment | **PARTIALLY CONFIRMED** | Frontend supports Supabase MFA (`supabaseEnrollMfa`), backend fallback returns static dummy secret `JBSWY3DPEHPK3PXP`. |
| **GAP-04** | Real Endpoint Telemetry vs Synthetic Data | **CONFIRMED** | Mixed telemetry in `agent/vrsoc-agent.js`. Host, CPU cores, RAM, and IPs are real; disk, process counts, and socket counts are hardcoded. |
| **GAP-05** | Real-Time SSE Stream & Event Scoping | **CONFIRMED** | Path mismatch (`/api/sse/stream` vs `/api/events/stream`) prevents live SSE streaming. |
| **GAP-06** | PhishGuard ML Feature Extraction & Promotion | **CONFIRMED** | Fully implemented in `server/phishguard.ts` (13 features) and promotes to `RULE-PHISH-001`. |
| **GAP-07** | Detection Engine & MITRE ATT&CK Mappings | **CONFIRMED** | Implemented in `server/detectionEngine.ts` with 8 core rules. |
| **GAP-08** | Evidence-Grounded AI Copilot (3 Evidence States) | **CONFIRMED** | Implemented in `server/aiEngine.ts` strictly categorizing evidence as `CONFIRMED`, `INFERRED`, or `UNKNOWN`. |
| **GAP-09** | Case Management & Incident Timeline Reconstruction | **CONFIRMED** | Implemented in `src/components/IncidentsView.tsx` and `server/db.ts`. |
| **GAP-10** | Enterprise RBAC Server-Side Enforcement | **CONFIRMED** | Missing on all mutation routes except key rotation. |
| **GAP-11** | Database Schema Synchronization with Supabase PostgreSQL | **CONFIRMED** | SQL migration exists (`20260919000000_vrsoc_core_schema.sql`), but backend operates in-memory with JSON file backup. |

---

## 17. Newly Discovered Implementation Gaps

1. **NEW-GAP-01: Cleartext OTP Transmission in JSON Responses**: Server-side auth handlers (`/api/auth/signup`, `/api/auth/resend-email-otp`, `/api/auth/resend-phone-otp`) include generated OTP codes directly in response JSON bodies.
2. **NEW-GAP-02: SSE Endpoint Route Mismatch**: Frontend calls `/api/sse/stream` while backend registers `/api/events/stream`.
3. **NEW-GAP-03: Demo Login Credential Divergence**: Frontend demo button points to `admin@vrsoc.cyber` / `VRSOC-Security2025!`, whereas backend seeds `analyst@vrsoc.cyber` / `VrsocPassword2026!`.
4. **NEW-GAP-04: Lack of Automated Test Harness**: `package.json` lacks unit or integration test scripts (`npm test`).
5. **NEW-GAP-05: Missing Agent Packaging / Service Manifests**: Agent exists only as a Node script; no background service wrapper (systemd or Windows Service) is provided.

---

## 18. Current Product Completion Matrix

| Product Area | Frontend | API | DB | Auth | RBAC | Tenant Isolation | Realtime | Production Ready |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Authentication & Onboarding** | COMPLETE | COMPLETE | LOCAL | PARTIAL | PARTIAL | COMPLETE | N/A | PARTIAL |
| **Dashboard & Threat Posture** | COMPLETE | COMPLETE | LOCAL | COMPLETE | N/A | COMPLETE | BROKEN | PARTIAL |
| **Endpoint Agent Management** | COMPLETE | COMPLETE | LOCAL | COMPLETE | PARTIAL | COMPLETE | BROKEN | PARTIAL |
| **Telemetry Ingestion & Simulation** | COMPLETE | COMPLETE | LOCAL | COMPLETE | N/A | COMPLETE | BROKEN | PARTIAL |
| **Detection Rules Engine** | COMPLETE | COMPLETE | LOCAL | COMPLETE | PARTIAL | COMPLETE | N/A | COMPLETE |
| **Alerts & MITRE ATT&CK Triage** | COMPLETE | COMPLETE | LOCAL | COMPLETE | PARTIAL | COMPLETE | BROKEN | COMPLETE |
| **Incidents & Case Management** | COMPLETE | COMPLETE | LOCAL | COMPLETE | PARTIAL | COMPLETE | BROKEN | COMPLETE |
| **PhishGuard ML URL Scanner** | COMPLETE | COMPLETE | LOCAL | COMPLETE | N/A | COMPLETE | N/A | COMPLETE |
| **AI SOC Copilot (Evidence Grounded)** | COMPLETE | COMPLETE | LOCAL | COMPLETE | N/A | COMPLETE | N/A | COMPLETE |
| **Reports Generation** | COMPLETE | COMPLETE | LOCAL | COMPLETE | N/A | COMPLETE | N/A | COMPLETE |
| **Threat Intelligence & Audit Logs** | COMPLETE | COMPLETE | LOCAL | COMPLETE | PARTIAL | COMPLETE | N/A | COMPLETE |
| **Settings & 14-Char Hex Key** | COMPLETE | COMPLETE | LOCAL | COMPLETE | COMPLETE | COMPLETE | N/A | COMPLETE |

---

## 19. Phase 00 Exit Criteria

1. **Repository Inspected Recursively**: All source files across Frontend, Backend, Agent, Database, Supabase, AI, and Configuration have been fully inventoried.
2. **Build, Typecheck, and Startup Validated**:
   * TypeScript static checking passed (`npx tsc --noEmit` -> 0 errors).
   * Frontend and backend production bundle build passed (`npm run build`).
   * Express + Vite development and production servers boot successfully on port 3000.
3. **Contracts & Discrepancies Cataloged**: SSE path mismatch, credential discrepancies, OTP leakage, and database runtime isolation gaps have been cataloged without making unauthorized code edits.
4. **Baseline Report Generated**: The factual baseline is frozen in `docs/phase-00-baseline-audit.md`.
