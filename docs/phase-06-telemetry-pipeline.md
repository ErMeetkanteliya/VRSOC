# Phase 06 — Telemetry Pipeline & Event Processing

## 1. Implemented Changes
- **Canonical Event Processing Pipeline:** Established an end-to-end, deterministic ingestion pipeline connecting Endpoint Agent → Agent Auth (`agent_token_hash`) → Request Validation → Event Normalization → PostgreSQL Persistence (`endpoint_events`) → Detection Engine Evaluation → Alert Creation & Deduplication → Incident Correlation → Audit Trail → SSE Realtime Broadcast (`new_event`, `new_alert`, `incident_updated`) → Dashboard Aggregates → AI Copilot Grounded Context.
- **Database Migration & Performance Indexing:** Added `supabase/migrations/20260919000003_telemetry_pipeline_hardening.sql` introducing composite performance indexes for telemetry time-window queries (`(organization_id, event_type, event_time DESC)`), alert deduplication (`(organization_id, rule_id, hostname)`), and incident-alert relationship lookups (`incident_alerts`).
- **Telemetry Normalization Layer:** Implemented `db.normalizeEndpointEvent()` in `server/db.ts` to cleanse raw telemetry, clamp event timestamps (prevent future clock spoofing), derive trusted identity (`agentId`, `organizationId`, `environment`), and normalize standard attributes (`hostname`, `username`, `processName`, `commandLine`, `sourceIp`, `destinationIp`, `filePath`, `fileHash`).
- **Detection Engine Hardening:** Extended `server/detectionEngine.ts` to evaluate all active rules (`RULE-AUTH-001`, `RULE-AUTH-002`, `RULE-PROC-001`, `RULE-PERS-001`, `RULE-NET-001`, `RULE-DEV-001`, `RULE-PHISH-001`, `RULE-HEART-001`, plus custom rules) against real normalized telemetry.
- **Alert Creation & Deduplication:** Enforced alert deduplication within a 15-minute sliding window on identical `(ruleId, hostname)` combinations to prevent alert storms during high-frequency telemetry floods.
- **Incident Correlation:** Automated linking of high-severity and critical alerts to active open incidents (`db.linkAlertToIncident()`), updating incident timelines with `ALERT_CORRELATION` audit events.
- **AI Copilot Grounded Context:** Overhauled `server/aiEngine.ts` to pull comprehensive, authorized PostgreSQL datasets (recent alerts, active incidents, fleet state, recent telemetry events, detection rules, threat IOCs) strictly scoped to the user's authenticated organization ID. Structured responses clearly into `CONFIRMED`, `INFERRED`, and `UNKNOWN` evidence states without fabricating synthetic IDs or data.
- **Automated Verification Suite:** Built `scripts/verify-telemetry-pipeline.ts` with 22 automated tests validating the complete pipeline under real runtime conditions.

## 2. Telemetry Contract
- **Payload Schema:**
  - `eventType`: Required enum (`'process' | 'file' | 'network' | 'auth' | 'dns' | 'registry' | 'service' | 'usb'`).
  - `severity`: Optional enum (`'info' | 'low' | 'medium' | 'high' | 'critical'`), defaults to `'info'`.
  - `eventTime`: Optional ISO timestamp (validated against current server time + 5m clock skew window).
  - `data`: Arbitrary structured JSON object containing event-specific metadata (e.g. `processName`, `commandLine`, `sourceIp`, `destinationIp`, `username`).
- **Transport Security:** Authenticated via `Authorization: Bearer <agent_token>` or `x-agent-token` header, verified against `agents.agent_token_hash`.

## 3. Event Normalization
- Handled through `db.normalizeEndpointEvent()`.
- Missing values remain `null` or schema-safe representation (no fabricated entities).
- Hostname defaults to the authenticated agent's registered hostname.
- Source IP defaults to the authenticated agent's known IP address when not explicitly present in event telemetry.

## 4. PostgreSQL Persistence
- Events are persisted directly to the `endpoint_events` table using PostgreSQL runtime established in Phase 01.
- No local file or in-memory fallback is used.
- Persistence failure throws an immediate 500 error and never returns a false 201 success code.

## 5. Detection Engine Integration
- `server/detectionEngine.ts` processes persisted events asynchronously after database insertion.
- Detection queries load enabled detection rules strictly belonging to the event's `organization_id` or global system rules.
- Real-time matches generate structured `Alert` records referencing triggering event IDs (`triggerEventIds`) and MITRE ATT&CK mappings.

## 6. Alert Creation / Deduplication
- Alerts created via `db.createAlert()` populate `mitreTactic`, `mitreTechnique`, `mitreId`, `evidence` (with `state: 'CONFIRMED'`), and `triggerEventIds`.
- Deduplication inspects open alerts in the same tenant for `(ruleId, hostname)` created in the last 15 minutes.
- If duplicate is identified, the existing alert ID is acknowledged and returned without creating redundant duplicate rows in PostgreSQL.

## 7. Incident Correlation
- When critical/high-severity alerts trigger (`severity === 'critical'` or `riskScore >= 85`), the correlation engine checks for open incidents matching the host or environment.
- If an open incident exists: links the alert via `db.linkAlertToIncident()` and appends a confirmed correlation entry to `incident_timeline`.
- If no incident exists for a critical alert: auto-creates a new incident investigation case linking the alert.

## 8. Audit Trail
- Pipeline actions recorded in `audit_logs`:
  - `ALERT_GENERATED`: (ruleId, severity, riskScore, hostname)
  - `SIMULATE_THREAT_SCENARIO`: (scenario, agent, triggeredAlertId)
- All audit log details are sanitized and contain zero secrets, tokens, or hashes.

## 9. SSE / Realtime Flow
- Ingestion pipeline emits:
  - `new_telemetry` / `new_event`: Sanitized normalized telemetry payload.
  - `new_alert`: Created alert record with evidence details.
  - `incident_updated` / `new_incident`: Realtime case updates.
- All broadcasts are strictly routed to the tenant's dedicated channel: `broadcastEvent(orgId, ...)`.

## 10. Dashboard Data Flow
- Dashboard metrics and aggregate views (`/api/organizations/metrics`, `/api/dashboard/stats`) derive stats dynamically from real PostgreSQL records (`agents`, `alerts`, `incidents`, `endpoint_events`).
- AlertsView and IncidentsView consume actual records created through detection evaluation.

## 11. AI Copilot Grounding Context
- `server/aiEngine.ts` fetches authorized PostgreSQL data scoped to `orgId`.
- Grounding context includes:
  - Targeted Alert / Incident / Agent details if context parameters are provided.
  - Recent alerts, active incidents, enrolled agent states, recent telemetry events, enabled detection rules, phishing scans, and threat IOCs for general queries.
- Strict 3-state output formatting:
  - **CONFIRMED**: Real database records with verified IDs, timestamps, and detection rules.
  - **INFERRED**: Risk scores, potential attack paths.
  - **UNKNOWN**: External actor identity, uncaptured network parameters, lateral movement extent.
- Missing data is explicitly marked `UNKNOWN` rather than fabricated.

## 12. Error / Failure Isolation
- Ingestion pipeline is isolated in distinct error domains:
  - Event persistence failure halts with 500 error (cannot report false success).
  - Detection engine failure or SSE broadcast failure is caught and logged safely without rolling back or deleting already-persisted telemetry.
  - Malformed single event JSON returns 400 Bad Request without crashing the Express server.

## 13. Idempotency / Retry Behavior
- Deduplication prevents repeated alert generation on rapid telemetry retries.
- Agent reconnection buffers up to 50 events in memory and flushes sequentially upon reconnection.

## 14. Performance / Index Findings
- Applied migration `20260919000003_telemetry_pipeline_hardening.sql` adding:
  - `idx_events_org_type_time` on `endpoint_events(organization_id, event_type, event_time DESC)`
  - `idx_events_org_time` on `endpoint_events(organization_id, event_time DESC)`
  - `idx_alerts_org_rule_host` on `alerts(organization_id, rule_id, hostname)`
  - `idx_incident_alerts_alert` on `incident_alerts(alert_id)`
  - `idx_incident_alerts_incident` on `incident_alerts(incident_id)`

## 15. Automated Verification
- Full test suite `scripts/verify-telemetry-pipeline.ts` executed with 22/22 passing tests:
  1. [PASS] Valid agent telemetry ingestion accepted (201 Created).
  2. [PASS] Telemetry persisted in PostgreSQL database.
  3. [PASS] Persisted telemetry has correct trusted Agent ID.
  4. [PASS] Persisted telemetry has correct Organization ID.
  5. [PASS] Invalid telemetry schema rejected (400 Bad Request).
  6. [PASS] Event normalization layer cleanses inputs and binds metadata.
  7. [PASS] Detection engine evaluates active detection rules.
  8. [PASS] Matching telemetry triggers expected alert (RULE-PROC-001).
  9. [PASS] Alert references triggering telemetry event.
  10. [PASS] Alert references correct rule ID and MITRE technique.
  11. [PASS] Alert belongs strictly to enrolled organization.
  12. [PASS] Cross-tenant telemetry cannot create another tenant alert (403 Forbidden).
  13. [PASS] Alert deduplication prevents redundant alert storms.
  14. [PASS] Incident correlation links critical alert to incident case.
  15. [PASS] Relevant SSE events emitted for pipeline changes.
  16. [PASS] SSE data remains strictly organization-scoped.
  17. [PASS] Dashboard metrics reflect stored records.
  18. [PASS] AI context retrieval can access detailed underlying records.
  19. [PASS] AI context does NOT include another organization records.
  20. [PASS] AI evidence separation into CONFIRMED, INFERRED, and UNKNOWN.
  21. [PASS] Single event ingestion failure does not crash server.
  22. [PASS] No secret credentials or tokens leaked in pipeline responses.

## 16. Manual End-to-End Verification
- Verified end-to-end pipeline:
  - Agent starts → Ingests real telemetry → Normalized & Stored in PostgreSQL → Detection engine matches `RULE-PROC-001` → Alert created in AlertsView → Critical incident correlated in IncidentsView → SSE broadcasts update → AI Copilot answers questions grounded in the newly created alert record.

## 17. Build / Typecheck Results
- `npm run lint` (`tsc --noEmit`): PASS (0 errors)
- `npm run build` (`vite build && esbuild server.ts`): PASS
- `npm run verify:seed`: PASS
- `npm run verify:auth`: PASS (11/11 tests passed)
- `npm run verify:rbac`: PASS (13/13 tests passed)
- `npm run verify:security`: PASS (21/21 tests passed)
- `npm run verify:agent`: PASS (22/22 tests passed)
- `npm run verify:pipeline`: PASS (22/22 tests passed)

## 18. Remaining Issues
- None. All Phase 06 exit criteria are met.

## 19. Files Changed
- `supabase/migrations/20260919000003_telemetry_pipeline_hardening.sql` (New Migration)
- `server/db.ts` (Event normalization, incident linking, query methods)
- `server/detectionEngine.ts` (Detection rule evaluations, deduplication, incident correlation)
- `server/aiEngine.ts` (PostgreSQL grounded context retrieval, CONFIRMED/INFERRED/UNKNOWN separation)
- `server.ts` (Hardened telemetry ingestion endpoint, /api/health endpoint)
- `scripts/verify-telemetry-pipeline.ts` (Phase 06 test runner)
- `scripts/verify-rbac.ts` (Type fix for agent creation)
- `package.json` (Added `verify:pipeline` script)
- `docs/phase-06-telemetry-pipeline.md` (Phase 06 documentation report)

## 20. Phase 06 Exit Criteria
- [x] Real endpoint telemetry reaches the backend
- [x] Telemetry is validated
- [x] Trusted agent identity is preserved
- [x] Trusted organization identity is preserved
- [x] Events are normalized
- [x] Valid events persist to PostgreSQL
- [x] No local JSON fallback exists
- [x] Detection engine evaluates existing rules
- [x] Detection matching is tenant scoped
- [x] Alerts are persisted
- [x] Alerts are traceable to real events
- [x] Alerts are traceable to existing detection rules
- [x] Alert duplication is controlled
- [x] Existing incident correlation works
- [x] Incident relationships remain traceable
- [x] Audit events are created where appropriate
- [x] SSE updates are emitted
- [x] SSE updates are organization scoped
- [x] Dashboard metrics use real data
- [x] AlertsView uses real alert records
- [x] IncidentsView uses real incident records
- [x] AI Copilot can retrieve detailed authorized workspace records
- [x] AI does not fabricate missing alert details
- [x] AI context is tenant scoped
- [x] Database failures do not silently succeed
- [x] One event failure cannot crash the server
- [x] Retry/idempotency behavior is safe
- [x] Telemetry bursts do not create uncontrolled memory growth
- [x] Required indexes exist where justified
- [x] Phase 03 tenant authorization remains intact
- [x] Phase 04 API security remains intact
- [x] Phase 05 agent security remains intact
- [x] Existing frontend UI remains intact
- [x] Typecheck passes
- [x] Build passes
- [x] Dev startup passes
- [x] Production startup passes
- [x] Seed verification passes
- [x] RBAC verification passes
- [x] API security verification passes
- [x] Agent security verification passes
- [x] Telemetry pipeline verification passes
- [x] End-to-end telemetry flow is verified
- [x] No new product features were added
- [x] No unnecessary UI redesign was performed
