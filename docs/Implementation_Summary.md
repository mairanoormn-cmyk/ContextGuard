# ContextGuard — Implementation Summary
*Final State | May 16, 2026 | lablab.ai Hackathon Submission*

---

## Overview

ContextGuard is a fully production-capable enterprise AI security platform built in response to real-world supply-chain vulnerabilities. The system monitors, classifies, and governs every interaction between organizational data and third-party AI tools granted OAuth access.

**SRS Coverage: 30/36 Functional Requirements (83%)**

---

## What's Built

### Backend — FastAPI (Python 3.11)

**`main.py`** — Central API with 35+ endpoints:
- Complete OAuth scan lifecycle (schedule + on-demand)
- Full DPI event pipeline with Gemini classification
- Live prompt injection tester (`POST /api/dpi/test`)
- Environment variable scan + classification
- Red-team simulation runner
- Incident response workflow engine
- System health endpoint (`GET /api/status`)
- Workspace connect/disconnect (`POST /api/workspace/connect`)

**`database.py`** — SQLite persistence layer:
- 8 tables: `oauth_apps`, `dpi_events`, `audit_log`, `ioc_list`, `oauth_whitelist`, `env_variables`, `env_alerts`, `incidents`
- All data access functions, no ORM overhead
- `clear_oauth_apps()` for clean workspace transitions

**`gemini.py`** — Google Gemini 2.5 Pro/Flash integration:
- `score_oauth_app()` — structured risk scoring with blast radius, SOC2, geo factors
- `classify_prompt_intent()` — real-time DPI event classification
- `generate_report()` — SOC2/HIPAA compliance report generation
- `call_gemini_with_search()` — live threat intel via Google Search retrieval
- `refresh_ioc_database()` — auto-updates IOC list from current threat feeds

**`google_workspace.py`** — Google Admin SDK:
- `scan_oauth_apps()` — real OAuth app enumeration via `admin/directory_v1/tokens`
- `_scan_workspace_api()` — per-user token listing with scope extraction

**`oauth_scanner.py`** — Scan pipeline:
- `run_oauth_scan()` — orchestrates full scan, scoring, IOC matching, scope drift
- `score_and_save_app()` — saves each app with Gemini risk score
- `detect_scope_drift()` — identifies over-permissioned apps

**`dpi.py`** — Deep Prompt Inspection logic:
- `extract_structured_metadata()` — parses all Lobster Trap fields
- `check_intent_mismatch()` — declared vs. detected intent delta
- `apply_intent_mismatch_policy()` — auto-escalates severity on mismatch
- `inspect_prompt_local()` — heuristic pattern matching (no Gemini needed)

**`env_guardian.py`** — Environment variable security:
- `classify_env_var()` — rule-based + Gemini AI classification
- `analyze_dpi_for_env_access()` — scans every DPI event for env var references
- `REMEDIATION_PLAYBOOKS` — step-by-step rotation guides for 12+ platforms

**`redteam.py`** — Attack simulation:
- `run_redteam_simulation()` — 4-scenario AI supply-chain attack simulation
- `_is_proxy_online()` — detects if Lobster Trap is running
- `_simulate_proxy_response()` — heuristic offline fallback so demo always works
- `run_lobstertrap_builtin_tests()` — runs native Lobster Trap test suite

**`behavior.py`** — Agent baseline tracking:
- Tracks per-agent intent frequency + severity history
- Flags behavioral anomalies vs. established baseline
- Triggers app rescore on anomaly detection

**`incident_response.py`** — Remediation engine:
- `create_incident_from_event()` — auto-creates from CRITICAL DPI events
- Multi-step workflow with playbook definitions per incident type
- `coordinate_credential_rotation()` — 1-click rotation orchestration

---

### Frontend — React 18 + Vite

**`App.jsx`** — Shell with real workspace status:
- Polls `/api/status` every 15s
- Shows real admin email, app count, proxy status in header + sidebar
- All status indicators reflect live backend state

**`ThreatFeed.jsx`** — Live event dashboard:
- Polls events every 10s with severity color coding
- Stats cards: total apps, critical threats, events intercepted
- Gemini compliance report generator with `.txt` download

**`OAuthApps.jsx`** — OAuth audit:
- Connect Workspace modal (file upload flow)
- Lists all apps with risk score, category, Gemini explanation
- Whitelist toggle, rescore button, IOC flag indicator

**`EnvGuardian.jsx`** — Credential monitoring:
- "Scan System Env Vars" → real OS scan via `POST /api/env/scan`
- Manual classify form for any variable name
- Expandable per-variable detail: hash, rotation status, Gemini explanation
- Live access alerts panel
- Stats cards: total monitored, sensitive, misclassified

**`RedTeamSimulator.jsx`** — Dual-mode simulator:
- **Live Prompt Tester** — type any prompt → Gemini verdict in seconds
  - 6 pre-loaded examples (injection, credential theft, PII, jailbreak, etc.)
  - BLOCKED / FLAGGED / ALLOWED verdict with full breakdown
  - Per-test history sidebar (last 10 tests)
  - Every test saved as real DPI event → appears in Threat Feed
- **AI Supply Chain Attack Simulation** — expandable per-scenario results

**`IncidentResponse.jsx`** — Guided remediation:
- Incident list with status tracking
- Step-by-step playbook per incident type
- Advance step + 1-click rotation buttons

---

## Real Data Flow

```
User connects workspace (OAuth Apps tab)
  → POST /api/workspace/connect (saves service_account.json)
  → clear_oauth_apps() (wipes old data)
  → Background scheduler triggers scan (30s later)
  → scan_oauth_apps() calls Google Admin SDK
  → Returns real apps from Google Workspace
  → score_and_save_app() → Gemini AI risk scores each
  → Dashboard shows real apps with real risk scores

User types prompt in Red-Team Simulator
  → POST /api/dpi/test
  → inspect_prompt_local() (heuristic check)
  → classify_prompt_intent() (Gemini AI)
  → check_intent_mismatch() (declared vs detected)
  → save_event() (appears in Threat Feed)
  → Returns: BLOCKED / FLAGGED / ALLOWED verdict

Lobster Trap intercepts real AI agent traffic
  → POST /api/webhook/lobster
  → extract_structured_metadata()
  → Gemini classifies intent + severity
  → analyze_dpi_for_env_access() → env alerts
  → behavioral anomaly check → rescore if needed
  → save_event() → appears in Threat Feed
```

---

## Key Technical Decisions

| Decision | Rationale |
|----------|-----------|
| SQLite over PostgreSQL | Hackathon simplicity; schema designed for PostgreSQL migration |
| Polling over WebSocket | Sufficient for demo; WebSocket would be production improvement |
| Offline simulation fallback | Demo always works even without Lobster Trap running |
| SHA-256 prompt hashing | No PII/credentials ever stored in plaintext |
| dotenv hot-reload for workspace | Avoids needing Docker restart on credential update |
| Rule-based + Gemini dual classification | Rule-based for speed, Gemini for accuracy |

---

## Known Gaps (Post-Hackathon Roadmap)

| Gap | Priority | Effort |
|-----|----------|--------|
| PDF export for compliance reports | HIGH | 1 day |
| WebSocket real-time updates | MEDIUM | 2 days |
| Event detail modal (click-to-expand) | MEDIUM | 1 day |
| Slack/Email alert webhooks | MEDIUM | 1 day |
| Dashboard authentication + MFA | HIGH | 3 days |
| RBAC (Viewer/Analyst/Admin roles) | HIGH | 2 days |
| PostgreSQL migration | LOW | 1 day |
| Docker Compose for full stack | LOW | 4 hours |
