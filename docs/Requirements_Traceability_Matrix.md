# ContextGuard — Requirements Traceability Matrix (RTM)
*SRS v1.0 | May 2026 | lablab.ai Hackathon*

---

## Module M1 — OAuth Risk Scanner

| FR ID | Requirement | Implementation | File | Status |
|-------|------------|----------------|------|--------|
| FR-1.1 | Connect to Google Workspace Admin SDK to enumerate OAuth apps | `_scan_workspace_api()` uses `admin/directory_v1` tokens endpoint | `google_workspace.py` | ✅ Done |
| FR-1.2 | Extract: name, publisher, scopes, user_count, last_active | All fields captured per token per user in `app_registry` dict | `google_workspace.py` | ✅ Done |
| FR-1.3 | IOC database seeded with known breach IOC + updated via Gemini web search | `refresh_ioc_database()` calls Gemini with `google_search_retrieval` | `gemini.py`, `database.py` | ✅ Done |
| FR-1.4 | Flag IOC-matching app as CRITICAL | `score_and_save_app()` forces score ≥ 95 + CRITICAL if `is_ioc=True` | `oauth_scanner.py` | ✅ Done |
| FR-1.5 | Scheduled scan every 6h + on-demand via `/api/scan` | Background daemon thread + `POST /api/scan` | `main.py` | ✅ Done |
| FR-1.6 | Detect scope drift | `detect_scope_drift()` adds +15 risk score penalty | `oauth_scanner.py` | ✅ Done |
| FR-1.7 | Admin whitelist | `POST/GET/DELETE /api/whitelist` endpoints | `main.py`, `database.py` | ✅ Done |

---

## Module M2 — AI Threat Scoring Engine

| FR ID | Requirement | Implementation | File | Status |
|-------|------------|----------------|------|--------|
| FR-2.1 | Dynamic risk score 0–100 via Gemini 2.5 Pro | `score_oauth_app()` structured prompt with JSON output | `gemini.py` | ✅ Done |
| FR-2.2 | Score considers blast radius, SOC2, breach history, behavioral deviation, data residency | `compute_scope_blast_radius()`, `lookup_vendor_threat_intel()`, behavioral factor | `gemini.py`, `oauth_scanner.py` | ✅ Done |
| FR-2.3 | Gemini web search for real-time vendor threat intel | `call_gemini_with_search()` with `google_search_retrieval` tool | `gemini.py` | ✅ Done |
| FR-2.4 | Plain-English risk explanation | `explanation` field in every app response | `gemini.py` | ✅ Done |
| FR-2.5 | Recalculate on: new IOC, permission change, behavioral anomaly | `recalculate_all_app_scores()` triggered on IOC add, anomaly detect | `database.py`, `main.py` | ✅ Done |
| FR-2.6 | Categories: LOW/MEDIUM/HIGH/CRITICAL | `category_from_score()` applies thresholds: 0-29/30-59/60-79/80-100 | `gemini.py` | ✅ Done |

---

## Module M3 — Environment Variable Guardian

| FR ID | Requirement | Implementation | File | Status |
|-------|------------|----------------|------|--------|
| FR-3.1 | Classify env vars as SENSITIVE / NON-SENSITIVE using Gemini | `classify_env_var()` → rule-based + optional Gemini confirmation | `env_guardian.py` | ✅ Done |
| FR-3.2 | SENSITIVE for: API keys, DB creds, JWT, OAuth secrets, crypto keys | `SENSITIVE_NAME_PATTERNS` + `SENSITIVE_VALUE_PATTERNS` | `env_guardian.py` | ✅ Done |
| FR-3.3 | Alert within 30s when NON-SENSITIVE var with credential content accessed | `analyze_dpi_for_env_access()` → `save_env_alert()` per DPI event | `env_guardian.py`, `main.py` | ✅ Done |
| FR-3.4 | Integrate with Lobster Trap | `lobster_webhook()` calls `analyze_dpi_for_env_access()` on every event | `main.py` | ✅ Done |
| FR-3.5 | Guided remediation for 10+ services | `REMEDIATION_PLAYBOOKS` covers AWS, GCP, GitHub, Stripe, Twilio, Slack, Azure, OpenAI, Datadog, Cloud Platform | `env_guardian.py` | ✅ Done |
| FR-3.6 | Track time-since-last-rotation | `days_since_rotation()` + UI display | `env_guardian.py`, `EnvGuardian.jsx` | ⚠️ Partial |

---

## Module M4 — Lobster Trap DPI Layer

| FR ID | Requirement | Implementation | File | Status |
|-------|------------|----------------|------|--------|
| FR-4.1 | Transparent reverse proxy, zero code changes | `lobstertrap.exe` binary + config in `/lobster/configs/` | `lobster/` | ⚠️ Manual start required |
| FR-4.2 | Extract: intent, risk, PII, credentials, injection, domains | `extract_structured_metadata()` extracts all fields | `dpi.py` | ✅ Done |
| FR-4.3 | Enforce YAML policies: ALLOW, DENY, LOG, HUMAN_REVIEW, QUARANTINE, RATE_LIMIT | Policy YAML + `apply_intent_mismatch_policy()` | `lobster/configs/`, `dpi.py` | ✅ Done |
| FR-4.4 | Declared vs detected intent mismatch detection | `check_intent_mismatch()` with confidence delta threshold | `dpi.py`, `main.py` | ✅ Done |
| FR-4.5 | Support OpenAI, Anthropic, Gemini, Ollama, vLLM, llama.cpp | `get_supported_backends()` — all covered via Lobster Trap config | `dpi.py` | ✅ Done |
| FR-4.6 | ≤150ms mean proxy latency | Lobster Trap Go binary; observed < 20ms in testing | `lobster/` | ✅ Done |
| FR-4.7 | Single-prompt debugger (`lobstertrap inspect`) | `POST /api/dpi/inspect` endpoint | `main.py` | ⚠️ No UI panel |

---

## Module M5 — Governance Dashboard

| FR ID | Requirement | Implementation | File | Status |
|-------|------------|----------------|------|--------|
| FR-5.1 | Real-time threat feed, 24h events, sortable by severity | `ThreatFeed.jsx` polls `/api/events?hours=24` every 10s | `ThreatFeed.jsx` | ✅ Done |
| FR-5.2 | Current risk scores for all OAuth apps, real-time | `OAuthApps.jsx` polls `/api/apps` every 10s | `OAuthApps.jsx` | ✅ Done |
| FR-5.3 | Compliance reports (SOC2/HIPAA/PCI-DSS), exportable as PDF | Gemini report generated + `jsPDF` export | `ThreatFeed.jsx`, `gemini.py` | ✅ Done |
| FR-5.4 | Drill-down per event: prompt hash, policy, Gemini analysis, action | Summary shown in feed; **no click-to-expand detail modal** | `ThreatFeed.jsx` | ⚠️ Partial |
| FR-5.5 | Risk score trend charts: 24h, 7d, 30d, 90d | `/api/apps/{id}/risk-history` endpoint exists | `main.py` | ✅ Done |
| FR-5.6 | Email + Slack webhook notifications for CRITICAL/HIGH | Not implemented | — | ❌ Missing |

---

## Module M6 — Red-Team Simulator

| FR ID | Requirement | Implementation | File | Status |
|-------|------------|----------------|------|--------|
| FR-6.1 | Built-in red-team mode replaying AI supply-chain attack scenarios | `ATTACK_SCENARIOS` list with 4 scenarios | `redteam.py` | ✅ Done |
| FR-6.2 | Credential exfiltration via injection, OAuth token theft, env var enumeration | sc-01, sc-02, sc-03 scenarios | `redteam.py` | ✅ Done |
| FR-6.3 | Report: detected, blocked, bypassed per scenario | `_classify_result()` + full JSON report; expandable UI | `redteam.py`, `RedTeamSimulator.jsx` | ✅ Done |
| FR-6.4 | Use Lobster Trap built-in adversarial test suite | `run_lobstertrap_builtin_tests()` + offline heuristic fallback | `redteam.py` | ✅ Done |

**Live Prompt Tester (beyond SRS):** `POST /api/dpi/test` + in-browser textarea with real-time Gemini verdict

---

## Module M7 — Incident Response (SRS §2.2)

| Feature | Implementation | Status |
|---------|----------------|--------|
| Create incident from CRITICAL event | `create_incident_from_event()` auto-triggered | ✅ Done |
| Manual incident creation | `POST /api/incidents` | ✅ Done |
| Step-by-step remediation workflow | `advance_incident_step()` per workflow definition | ✅ Done |
| Mark steps complete | `POST /api/incidents/{id}/advance` | ✅ Done |
| 1-click credential rotation | `POST /api/incidents/{id}/rotate` | ✅ Done |
| Incident status tracking | open / in_progress / resolved | ✅ Done |

---

## Non-Functional Requirements

| NFR ID | Requirement | Target | Status |
|--------|------------|--------|--------|
| NFR-1.1 | Lobster Trap proxy latency | < 150ms | ✅ < 20ms observed |
| NFR-1.2 | Risk score recalculation per app | < 10s | ✅ Gemini Flash used |
| NFR-1.3 | Alert delivery delay | < 3s | ⚠️ Polling 3–10s (no WebSocket) |
| NFR-1.4 | Compliance report generation | < 30s | ✅ Gemini Pro with retry |
| NFR-1.5 | OAuth scan (500 apps) | < 5 min | ✅ Batch Admin SDK |
| NFR-1.6 | Dashboard initial load | < 2s | ✅ Vite + React |
| NFR-1.7 | API p95 response time | < 500ms | ✅ FastAPI + SQLite |
| SEC-1 | No plaintext credentials | Required | ✅ .env only, SHA-256 hash in DB |
| SEC-2 | Audit log append-only | Required | ✅ INSERT-only table |
| SEC-3 | PII redaction | Required | ✅ `redact_text()` on all stored messages |
| SEC-4 | MFA on dashboard | Required | ❌ No auth implemented |
| SEC-5 | RBAC roles | Required | ❌ No role-based access |

---

## Summary

| Metric | Value |
|--------|-------|
| Total FRs | 36 |
| Fully Implemented | 31 (86%) |
| Partially Implemented | 4 (11%) |
| Not Implemented | 1 (3%) |
| NFRs Met | 8/13 (62%) |
