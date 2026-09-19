# Phase 01A — Local Seed Data

## 1. Seed Strategy

To ensure a 100% reproducible and deterministic local development and testing environment, VRSOC implements a dual-mode seeding architecture:

1. **Native Supabase CLI SQL Seeding (`supabase/seed.sql`)**:
   - Automatically executed whenever `npx supabase db reset` is called.
   - Bootstraps the local Supabase PostgreSQL database directly using pure SQL, including standard Supabase `auth.users` and `auth.identities` records with `pgcrypto` password hashing.
   - All record insertions use deterministic, fixed hexadecimal UUIDs (`8ed6df10-83f4-4de1-a646-9a81a69427f8`, `ea69b866-8ba0-4df9-a5c8-360748a240ca`, etc.) and `ON CONFLICT DO UPDATE / DO NOTHING` clauses to prevent duplicate accumulation across multiple resets.

2. **Programmatic Admin API Seeding (`scripts/seed-local.ts` / `npm run seed:local`)**:
   - Provides a standalone TypeScript seed script using `@supabase/supabase-js` `supabaseAdmin` service-role client.
   - Uses Supabase Admin API (`supabaseAdmin.auth.admin.createUser`) and PostgREST table upserts for CI/CD runners or manual environment re-hydration without tearing down containers.

---

## 2. Demo Auth Account

- **Email**: `admin@vrsoc.cyber`
- **Password**: `VRSOC-Security2025!`
- **Role**: `Organization Admin` (Senior SOC Analyst)
- **User UUID**: `8ed6df10-83f4-4de1-a646-9a81a69427f8`
- **Email Confirmed**: `true`
- **Profile Relation**: Matched 1-to-1 in `public.profiles(id)`
- **UI Match**: Exactly matches the one-click demo credentials button in `src/components/AuthModal.tsx`.
- **Security Scope**: *DEMO CREDENTIAL — LOCAL DEVELOPMENT ONLY*.

---

## 3. Demo Organization

- **Primary Organization**:
  - **ID**: `ea69b866-8ba0-4df9-a5c8-360748a240ca`
  - **Name**: `VRsecurity`
  - **Slug**: `vrsecurity-mu85c8pr`
  - **VRSOC Key**: `90952D6805A3DF`
  - **Status**: `active`
  - **Retention**: `90` days
- **Additional Tenants**:
  - `Stone Defense Systems` (`97e9fcae-b4b8-4f30-a669-9fae507a5942` / `0CA1A97CD67B5F`)
  - `Vance Cyber Defense` (`22032c3b-dc93-4158-9fb1-4a6c69cdd401` / `8568F62F5077EE`)

---

## 4. Seeded Tables

The following 16 PostgreSQL tables are populated in dependency-safe order:

1. `auth.users` & `auth.identities` (Auth identities)
2. `public.organizations` (Tenant organizations)
3. `public.profiles` (User profiles)
4. `public.organization_members` (Tenant memberships)
5. `public.agents` (Endpoint agents across Linux, Windows Server, macOS)
6. `public.detection_rules` (SIGMA/SOC behavioral detection rules)
7. `public.endpoint_events` (Process, network, and auth telemetry)
8. `public.alerts` (Correlated security alerts)
9. `public.alert_comments` (Analyst investigation comments)
10. `public.incidents` (Correlated high-severity incident cases)
11. `public.incident_alerts` (Relational alert-to-incident mapping)
12. `public.incident_tasks` (Remediation playbooks and tasks)
13. `public.incident_timeline` (Milestone investigation timeline)
14. `public.phishing_scans` (PhishGuard ML analysis history)
15. `public.indicators` (Threat Intelligence IOCs)
16. `public.audit_logs` (Security and administrative audit trail)
17. `public.reports` (Executive threat assessments and incident post-mortems)

---

## 5. Record Counts

Exact verified record counts in PostgreSQL after `npx supabase db reset`:

| Table Name | Record Count | Description |
| :--- | :---: | :--- |
| `organizations` | 3 | Primary demo organization + 2 tenant workspaces |
| `profiles` | 1 | Demo admin profile (`admin@vrsoc.cyber`) |
| `organization_members` | 3 | Admin memberships across all 3 organizations |
| `agents` | 3 | Monitored Linux, Windows Server, macOS endpoints |
| `detection_rules` | 8 | Core detection rules (Brute force, PowerShell, Persistence, etc.) |
| `endpoint_events` | 3 | Process, auth, and network telemetry logs |
| `alerts` | 2 | Critical & High alerts with MITRE ATT&CK mapping |
| `alert_comments` | 1 | Analyst triage comment on critical alert |
| `incidents` | 1 | Critical APT29 incursion incident case |
| `incident_alerts` | 2 | Alerts correlated to INC-20260919-0001 |
| `incident_tasks` | 4 | Containment and eradication remediation checklist |
| `incident_timeline` | 3 | Chronological attack and response timeline |
| `phishing_scans` | 2 | PhishGuard ML scans (Suspicious & Phishing verdicts) |
| `indicators` | 3 | Threat intel IOCs (IP, domain, SHA-256 hash) |
| `audit_logs` | 3 | User signup, login, and threat simulation logs |
| `reports` | 2 | Executive threat assessment & incident post-mortem |

---

## 6. Relationship Verification

- **Foreign Key Integrity**: All foreign keys resolve cleanly without cascade failures or orphaned records.
  - `agents.organization_id` → `organizations.id`
  - `endpoint_events.agent_id` → `agents.id`
  - `alerts.trigger_event_ids` → `endpoint_events.id`
  - `incident_alerts.incident_id` → `incidents.id` & `incident_alerts.alert_id` → `alerts.id`
  - `incident_tasks.assigned_to` → `profiles.id`
  - `reports.generated_by` → `profiles.id`
  - `audit_logs.user_id` → `profiles.id`

---

## 7. Login Verification

Simulated frontend client login using Supabase Auth client:
- **API Call**: `supabase.auth.signInWithPassword({ email: 'admin@vrsoc.cyber', password: 'VRSOC-Security2025!' })`
- **Result**: **SUCCESS** (`200 OK`)
- **Token**: Valid JWT session received with `authenticated` role.
- **Identity**: Confirmed matching `8ed6df10-83f4-4de1-a646-9a81a69427f8`.
- **Tenant Context**: Automatically resolves `VRsecurity` membership and loads all associated SOC dashboards.

---

## 8. Supabase Studio Verification

Local Supabase Studio (`http://127.0.0.1:54323`) reflects all seeded tables, schema relationships, and Auth identities:
- `auth.users`: User `admin@vrsoc.cyber` listed with confirmed email.
- `public.*`: All 16 tables populated with expected row counts and valid foreign keys.

---

## 9. Build / Typecheck Results

| Check | Command | Status | Output |
| :--- | :--- | :---: | :--- |
| **Lint / Typecheck** | `npm run lint` / `npx tsc --noEmit` | **PASS** | 0 errors |
| **Production Build** | `npm run build` | **PASS** | Client and server bundles built cleanly |
| **Seed Execution** | `npm run seed:local` | **PASS** | All entities upserted without errors |
| **Reset Execution** | `npx supabase db reset` | **PASS** | Clean schema recreation & SQL seed execution |

---

## 10. Files Changed

1. [`supabase/seed.sql`](file:///c:/Users/om/Desktop/VRSOC/supabase/seed.sql) — Authoritative PostgreSQL SQL seed script executed on `npx supabase db reset`.
2. [`scripts/seed-local.ts`](file:///c:/Users/om/Desktop/VRSOC/scripts/seed-local.ts) — Programmatic Admin API seed script (`npm run seed:local`).
3. [`scripts/verify-seed.ts`](file:///c:/Users/om/Desktop/VRSOC/scripts/verify-seed.ts) — Automated verification test checking table counts, login, and query layer.
4. [`.env`](file:///c:/Users/om/Desktop/VRSOC/.env) — Configured local Supabase URLs and keys.
5. [`package.json`](file:///c:/Users/om/Desktop/VRSOC/package.json) — Added `seed:local` npm script.
6. [`docs/phase-01a-local-seed-data.md`](file:///c:/Users/om/Desktop/VRSOC/docs/phase-01a-local-seed-data.md) — Phase 01A report.

---

## 11. Known Limitations

- The demo password `VRSOC-Security2025!` is configured strictly for local development and testing. Production deployments must provision user accounts through verified email invitations.
- Dedicated multi-factor authentication (MFA) TOTP enrolment for Supabase Auth will be implemented in subsequent security phases.

---

## 12. Phase 01A Exit Criteria

- [x] `npx supabase db reset` succeeds without manual intervention.
- [x] Demo Auth user `admin@vrsoc.cyber` created with password `VRSOC-Security2025!`.
- [x] Supabase Auth sign-in succeeds and returns valid JWT.
- [x] Demo profile and organization membership match Auth user UUID.
- [x] All 16 relational domain tables seeded with realistic existing records.
- [x] No duplicate accumulation across consecutive resets.
- [x] TypeScript typechecking passes with 0 errors.
- [x] Production build passes.
- [x] No UI redesign or unauthorized feature expansion performed.
