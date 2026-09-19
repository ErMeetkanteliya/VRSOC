# Phase 08 — Incident & Case Management

## 1. Implemented Changes
- **Canonical Incident Lifecycle:** Enforced server-authoritative state transitions (`open`, `investigating`, `contained`, `resolved`, `false_positive`) via `isValidIncidentTransition()` in `server/db.ts` and `server.ts`. Invalid jumps are rejected with HTTP 400.
- **Lead Investigator & Assignment Hardening:** Validated target lead investigators against `organization_members` via `db.getMember()`. Cross-tenant assignment is strictly blocked.
- **Alert ↔ Incident Linkage:** Hardened `POST /api/incidents/:id/link-alert` and `POST /api/alerts/:id/link-incident` with same-organization validation and idempotent duplicate link prevention.
- **Timeline Integrity & Validation:** Validated timeline item event types (`alert`, `action`, `observation`, `containment`) and evidence states (`CONFIRMED`, `INFERRED`, `UNKNOWN`). Timeline entries are immutable and append-only.
- **Task Management & Member Scoping:** Hardened task creation (`POST /api/incidents/:id/task`) and completion toggling (`PATCH /api/incidents/:id/task/:taskId`) with same-organization assignee verification.
- **Server-Derived Notes & Comments:** Derived note authors and timestamps strictly from the authenticated session context (`req.user.id`, `req.user.fullName`), preventing author forgery.
- **Multi-Dimensional Incident Filtering & Pagination:** Enhanced `GET /api/incidents` with `incidentFilterQuerySchema` supporting `environment`, `status`, `severity`, `priority`, `leadInvestigator`, `search`, `limit`, and `offset` directly on PostgreSQL with tenant scoping.
- **Realtime SSE Broadcasts:** Emitted `incident_updated` and `new_incident` events scoped strictly to the organization channel on all incident creation, update, task, timeline, and note mutations.
- **Audit Logging:** Generated structured audit entries for `CREATE_INCIDENT`, `UPDATE_INCIDENT`, `LINK_INCIDENT_ALERT`, `ADD_INCIDENT_TASK`, `TOGGLE_INCIDENT_TASK`, `ADD_INCIDENT_TIMELINE`, and `ADD_INCIDENT_NOTE` with zero credentials or tokens exposed.
- **AI Grounding & Report Compatibility:** Grounded deterministic AI fallbacks and prompt assembly in current incident status, priority, lead investigator, tasks, and timeline records.
- **Automated Verification Suite:** Built `scripts/verify-incident-management.ts` testing 35 security, RBAC, tenant isolation, concurrency, and lifecycle scenarios.

---

## 2. Canonical Incident Model
The incident subsystem uses the canonical PostgreSQL schema:
- `id`: Unique formatted identifier (`INC-YYYYMMDD-XXXX` or `INC-<TIMESTAMP>-<RAND>`)
- `organization_id`: UUID strictly bound to tenant boundary
- `title` & `description`: Validated string details
- `severity`: Canonical severity (`low`, `medium`, `high`, `critical`)
- `status`: Canonical status (`open`, `investigating`, `contained`, `resolved`, `false_positive`)
- `priority`: Incident priority (`P1`, `P2`, `P3`, `P4`)
- `lead_investigator`: UUID referencing verified `profiles(id)`
- `linkedAlertIds`: Array of associated alert IDs in `incident_alerts`
- `timeline`: Ordered array of immutable timeline records in `incident_timeline`
- `tasks`: Array of investigation tasks in `incident_tasks`
- `notes`: Embedded structured analyst notes in `summary_report`
- `lessons_learned`: Post-incident review text
- `environment`: Deployment scope (`production`, `training`, `test`)

---

## 3. Incident Lifecycle
State transitions are authoritative on the server and enforced via `db.isValidIncidentTransition()`:
- `open` ➔ `investigating`, `contained`, `resolved`, `false_positive`
- `investigating` ➔ `open`, `contained`, `resolved`, `false_positive`
- `contained` ➔ `open`, `investigating`, `resolved`, `false_positive`
- `resolved` ➔ `open`, `investigating` (Authorized Reopening)
- `false_positive` ➔ `open`, `investigating` (Authorized Reopening)
- Idempotent same-state transitions are permitted. Illegal transitions return HTTP 400.

---

## 4. Assignment
- Lead investigator assignments are validated against `organization_members`.
- Attempting to assign an investigator from outside the organization is rejected with HTTP 400 (`Target lead investigator is not a member of this organization.`).
- Unassignment (`leadInvestigator: null`) cleanly clears the field while preserving history.

---

## 5. Alert Linkage
- Linking an alert to an incident requires both resources to belong to the authenticated organization.
- Upsert conflict handling prevents duplicate rows in `incident_alerts`.
- Linkage automatically appends a correlated event to `incident_timeline` and emits SSE updates.

---

## 6. Timeline
- Timeline items record `title`, `description`, `type` (`alert`, `action`, `observation`, `containment`), and `evidenceState` (`CONFIRMED`, `INFERRED`, `UNKNOWN`).
- Timestamps and organization scoping are server-controlled.
- Cross-tenant timeline additions return HTTP 404.

---

## 7. Tasks
- Tasks support `title`, optional `assignedTo`, and `completed` status.
- Task assignees must belong to the same organization.
- Task toggles (`PATCH /api/incidents/:id/task/:taskId`) verify incident ownership and log audit entries.

---

## 8. Evidence / Notes
- Incident notes are appended with server-derived `userId`, `userName`, and `createdAt` timestamps.
- Client-supplied author IDs or forged metadata are ignored.
- Notes are tenant-isolated and sanitized against secrets.

---

## 9. Resolution / Closure
- Resolving an incident (`status: 'resolved'`) records resolution notes and `lessonsLearned`.
- Historical artifacts (alerts, timeline, tasks, notes) remain fully persisted in PostgreSQL for post-incident review and audit compliance.
- Closed incidents are never physically deleted.

---

## 10. Search / Filter / Pagination
- Query parameters are validated via `incidentFilterQuerySchema`:
  - `status`, `severity`, `priority`, `leadInvestigator`, `search`, `limit`, `offset`
- Limit is capped between 1 and 500 (default: 100).
- All queries remain strictly scoped to `organization_id`.

---

## 11. Audit Trail
- Structured audit logs record all sensitive actions:
  - `CREATE_INCIDENT`
  - `UPDATE_INCIDENT`
  - `LINK_INCIDENT_ALERT`
  - `ADD_INCIDENT_TASK`
  - `TOGGLE_INCIDENT_TASK`
  - `ADD_INCIDENT_TIMELINE`
  - `ADD_INCIDENT_NOTE`
- Zero credentials, tokens, or plaintext secrets are recorded.

---

## 12. SSE / Realtime
- Realtime broadcasts (`new_incident`, `incident_updated`) are delivered exclusively to clients authenticated for the matching `organization_id`.
- Realtime consistency ensures UI updates immediately reflect database state changes.

---

## 13. AI Compatibility
- AI Copilot workspace context and deterministic assistant fallbacks retrieve active incident records, priority, status, lead investigator, and tasks directly from PostgreSQL.
- Cross-tenant incident leakage into AI prompts is strictly prevented.

---

## 14. Report Compatibility
- Report generation via `db.addReport()` and `GET /api/reports` reflects current incident lifecycle state, severity, lead investigator, and timeline artifacts.

---

## 15. Database Integrity
- Relational integrity across `incidents`, `incident_alerts`, `incident_tasks`, and `incident_timeline` is protected.
- RLS policies and server-side tenant scoping prevent cross-tenant access.

---

## 16. Security Regression Tests
The 35 automated tests in `scripts/verify-incident-management.ts` verify:
1. Authorized incident read succeeds (PASS)
2. Unauthenticated incident access returns 401 Unauthorized (PASS)
3. Unauthorized Viewer role blocked on incident mutation (403 Forbidden) (PASS)
4. Cross-tenant incident read is blocked (404 Not Found) (PASS)
5. Cross-tenant incident update is blocked (404 Not Found) (PASS)
6. Incident creation derives identity from authenticated session (PASS)
7. Organization ID payload tampering overridden by session context (PASS)
8. Invalid incident status transition is rejected (400 Bad Request) (PASS)
9. Valid status transition (reopening) succeeds (PASS)
10. Assignment target within same organization succeeds (PASS)
11. Cross-tenant incident assignment blocked (400 Bad Request) (PASS)
12. Cross-tenant alert-to-incident linkage blocked (404 Not Found) (PASS)
13. Valid alert-to-incident linkage succeeds (PASS)
14. Duplicate alert linkage prevented safely (idempotent) (PASS)
15. Incident timeline creation with valid types & evidence state (PASS)
16. Cross-tenant timeline entry creation blocked (404 Not Found) (PASS)
17. Incident task creation and same-tenant assignment succeed (PASS)
18. Cross-tenant task assignment blocked (400 Bad Request) (PASS)
19. Incident task completion toggled and persisted (PASS)
20. Cross-tenant task toggle blocked (404 Not Found) (PASS)
21. Incident note author identity strictly derived from session (PASS)
22. Cross-tenant note creation blocked (404 Not Found) (PASS)
23. Incident resolution and lessons learned recorded cleanly (PASS)
24. Resolved incidents remain fully persisted with all artifacts (PASS)
25. Incident queue multi-dimensional filtering operates on tenant data (PASS)
26. Incident pagination limits and offsets respected (PASS)
27. Dashboard incident metrics reflect strict organization scopes (PASS)
28. SSE incident broadcast dispatched on lifecycle mutations (PASS)
29. AI Copilot context sees current incident lifecycle state (PASS)
30. Report compatibility with incident lifecycle state verified (PASS)
31. Audit trail records incident creation, update, task, timeline & notes (PASS)
32. Audit records contain zero secret credentials or tokens (PASS)
33. Failed incident mutations return error and do not report success (PASS)
34. Concurrent incident updates merge safely without corruption (PASS)
35. Human authorization RBAC on incident management remains enforced (PASS)

---

## 17. Manual End-to-End Verification
- **Incident Creation:** Created an incident linked to an active alert; lead investigator assigned and audit record created.
- **Triage & Evidence:** Inspected linked alert evidence, timeline correlation, and process command lines.
- **Task Workflow:** Added investigation task, assigned to analyst, and toggled completed status in UI.
- **Timeline Addition:** Recorded memory dump artifact with `CONFIRMED` evidence state.
- **Resolution:** Resolved incident with lessons learned; verified persistence, dashboard counters, and AI grounding.

---

## 18. Build / Typecheck Results
- `npx tsc --noEmit`: 0 errors (PASS)
- `npm run build`: Vite client & esbuild server built cleanly in 530ms (PASS)
- `verify:seed`: 100% PASS
- `verify:auth`: 100% PASS (11/11)
- `verify:rbac`: 100% PASS (13/13)
- `verify:security`: 100% PASS (21/21)
- `verify:agent`: 100% PASS (22/22)
- `verify:pipeline`: 100% PASS (22/22)
- `verify:alert`: 100% PASS (28/28)
- `verify:incident`: 100% PASS (35/35)

---

## 19. Remaining Issues
- None.

---

## 20. Files Changed
- `server/validator.ts` — Added `incidentFilterQuerySchema`, `incidentLinkAlertSchema`, and refined incident update/task schemas.
- `server/db.ts` — Added `isValidIncidentTransition()`, multi-dimensional `getIncidents()`, and hardened incident/task/timeline/note methods.
- `server.ts` — Hardened `/api/incidents` route handlers (validation, assignment checks, auditing, SSE).
- `server/aiEngine.ts` — Enhanced deterministic AI context fallback with incident status and lead investigator grounding.
- `src/api.ts` — Added `linkIncidentAlert()`, filter params to `getIncidents()`, and `assignedTo` on `addIncidentTask()`.
- `package.json` — Added `"verify:incident": "tsx scripts/verify-incident-management.ts"`.
- `scripts/verify-incident-management.ts` — 35-test comprehensive verification suite.
- `docs/phase-08-incident-case-management.md` — Final Phase 08 documentation report.

---

## 21. Phase 08 Exit Criteria

- [x] Existing incident model preserved: **PASS**
- [x] Incident creation is authenticated: **PASS**
- [x] Incident creation is authorized: **PASS**
- [x] Tenant isolation is enforced: **PASS**
- [x] Object-level authorization is enforced: **PASS**
- [x] Incident status transitions are validated: **PASS**
- [x] Assignment is authorization protected: **PASS**
- [x] Assignment is same-organization only: **PASS**
- [x] Alert linkage is authorization protected: **PASS**
- [x] Alert linkage is same-organization only: **PASS**
- [x] Duplicate links are controlled: **PASS**
- [x] Timeline entries are authenticated: **PASS**
- [x] Timeline entries are tenant scoped: **PASS**
- [x] Timeline historical integrity is preserved: **PASS**
- [x] Tasks are validated: **PASS**
- [x] Task assignment is tenant scoped: **PASS**
- [x] Task lifecycle is validated: **PASS**
- [x] Evidence references are tenant scoped: **PASS**
- [x] Notes/comments are authenticated: **PASS**
- [x] Resolution/closure is protected: **PASS**
- [x] Closure metadata is trustworthy: **PASS**
- [x] Closed incidents remain persisted: **PASS**
- [x] Incident search is validated: **PASS**
- [x] Incident filters are tenant scoped: **PASS**
- [x] Pagination is bounded: **PASS**
- [x] Dashboard incident metrics are tenant scoped: **PASS**
- [x] Audit trail is complete for meaningful actions: **PASS**
- [x] Audit trail contains no secrets: **PASS**
- [x] SSE events are tenant scoped: **PASS**
- [x] AI incident context is tenant scoped and current: **PASS**
- [x] Reports remain accurate: **PASS**
- [x] Database integrity remains consistent: **PASS**
- [x] Concurrent updates behave safely: **PASS**
- [x] Retry/idempotency behavior is safe: **PASS**
- [x] Seed data continues to work: **PASS**
- [x] Phase 03 authorization remains intact: **PASS**
- [x] Phase 04 API hardening remains intact: **PASS**
- [x] Phase 05 agent security remains intact: **PASS**
- [x] Phase 06 telemetry pipeline remains intact: **PASS**
- [x] Phase 07 alert lifecycle remains intact: **PASS**
- [x] Existing frontend remains intact: **PASS**
- [x] Typecheck passes: **PASS**
- [x] Build passes: **PASS**
- [x] Dev startup passes: **PASS**
- [x] Production startup passes: **PASS**
- [x] Seed verification passes: **PASS**
- [x] RBAC verification passes: **PASS**
- [x] API security verification passes: **PASS**
- [x] Agent security verification passes: **PASS**
- [x] Telemetry pipeline verification passes: **PASS**
- [x] Alert lifecycle verification passes: **PASS**
- [x] Incident management verification passes: **PASS**
- [x] Manual incident end-to-end flow is verified: **PASS**
- [x] No new product features were added: **PASS**
- [x] No unnecessary UI redesign was performed: **PASS**
