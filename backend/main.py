"""
ContextGuard — FastAPI Backend
Owner: Maira
SRS Reference: System Architecture §6.2

Endpoints:
  GET  /api/apps            → All OAuth apps with risk scores
  POST /api/scan            → Trigger OAuth scan
  GET  /api/events          → DPI events (last 24h)
  POST /api/webhook/lobster → Receive Lobster Trap events
  GET  /api/report          → Generate Gemini compliance report
  POST /api/ioc             → Add new IOC entry
  GET  /api/stats           → Dashboard statistics
"""

import hashlib
import time
import logging
import os
import re
import threading
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

from database import (
    init_db,
    get_apps,
    get_app_by_id,
    save_event,
    get_events,
    get_event_count_by_severity,
    save_ioc,
    get_iocs,
    save_audit_log,
    get_audit_log,
    get_risk_score_history,
    recalculate_all_app_scores,
    add_whitelist,
    remove_whitelist,
    get_whitelist,
    clear_oauth_apps,
    save_env_variable,
    get_env_variables,
    save_env_alert,
    get_env_alerts,
    mark_env_rotated,
    save_redteam_run,
    get_redteam_runs,
    get_incidents,
    get_incident,
)
from gemini import score_oauth_app, classify_prompt_intent, generate_report
from dpi import (
    extract_structured_metadata,
    check_intent_mismatch,
    apply_intent_mismatch_policy,
    inspect_prompt_local,
    extract_declared_intent,
    get_supported_backends,
)
from behavior import update_agent_baseline, compute_behavioral_deviation
from env_guardian import days_since_rotation
from incident_response import (
    create_incident_from_event,
    advance_incident_step,
    get_workflow_definition,
    coordinate_credential_rotation,
    revoke_oauth_app_coordination,
)
from modules_status import get_modules_status
from oauth_scanner import run_oauth_scan, refresh_ioc_database
from env_guardian import classify_env_var, analyze_dpi_for_env_access, get_remediation_workflow
from redteam import run_redteam_simulation

# ═══════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CONTEXTGUARD] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("contextguard")

# ═══════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════

app = FastAPI(
    title="ContextGuard API",
    version="1.0.0",
    description="Enterprise AI Security Platform — Third-Party AI Tool Risk Monitor",
)

# Allow React frontend to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ═══════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════


SCAN_INTERVAL_HOURS = float(os.getenv("OAUTH_SCAN_INTERVAL_HOURS", "6"))
_scheduler_started = False


def _oauth_scan_scheduler():
    """FR-1.5: Background OAuth scans every N hours (default 6)."""
    interval_sec = SCAN_INTERVAL_HOURS * 3600
    time.sleep(30)  # initial delay so API is ready
    while True:
        try:
            logger.info("Scheduled OAuth scan starting (interval=%sh)", SCAN_INTERVAL_HOURS)
            run_oauth_scan()
        except Exception as e:
            logger.error("Scheduled OAuth scan failed: %s", e)
        time.sleep(interval_sec)


def _start_scan_scheduler():
    global _scheduler_started
    if _scheduler_started or os.getenv("DISABLE_SCAN_SCHEDULER", "").lower() in ("1", "true"):
        return
    _scheduler_started = True
    thread = threading.Thread(target=_oauth_scan_scheduler, daemon=True, name="oauth-scan-scheduler")
    thread.start()
    logger.info("OAuth scan scheduler started (every %s hours)", SCAN_INTERVAL_HOURS)


@app.on_event("startup")
def startup_event():
    """Initialize database on server startup."""
    init_db()
    
    # If in synthetic mode, ensure the DB is empty so the user starts with a clean slate
    if os.getenv("OAUTH_USE_SYNTHETIC", "").lower() in ("1", "true", "yes"):
        clear_oauth_apps()
        logger.info("Cleared existing apps for clean Demo Mode (empty state)")

    _start_scan_scheduler()
    logger.info("ContextGuard API started on :3000")
    save_audit_log("system", "startup", "api", "ContextGuard API initialized")


# ═══════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════


class LobsterWebhookPayload(BaseModel):
    """Schema for incoming Lobster Trap webhook events."""
    timestamp: str = Field(..., description="ISO 8601 timestamp of the event")
    policy_triggered: str = Field(..., description="Name of the policy rule that triggered")
    action_taken: str = Field(..., description="Action taken: DENY, QUARANTINE, LOG, HUMAN_REVIEW")
    prompt_hash: str = Field(..., description="SHA-256 hash of the inspected prompt")
    metadata: dict = Field(default_factory=dict, description="DPI metadata and inspection results")


class IOCEntry(BaseModel):
    """Schema for adding a new IOC entry."""
    app_client_id: str = Field(..., description="OAuth App Client ID to flag")
    source: str = Field(default="Manual Entry", description="Source of the IOC intelligence")
    severity: str = Field(default="CRITICAL", description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    description: str = Field(default="", description="Description of the threat")


class InspectPromptRequest(BaseModel):
    """FR-4.7: Single-prompt debugger (lobstertrap inspect equivalent)."""
    prompt: str = Field(..., description="Prompt text to inspect")
    declared_intent: Optional[str] = Field(None, description="Agent-declared X-Lobstertrap-Intent value")


class WhitelistEntry(BaseModel):
    app_client_id: str
    reason: str = ""
    added_by: str = "admin"


class EnvVarRequest(BaseModel):
    var_name: str
    value_hint: Optional[str] = None


class IncidentStepAdvance(BaseModel):
    step_id: int
    notes: str = ""


class WorkspaceConnectRequest(BaseModel):
    admin_email: str
    creds_json: str


# ═══════════════════════════════════════════
# PII REDACTION (for prompt content in metadata)
# ═══════════════════════════════════════════

PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN-REDACTED]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[EMAIL-REDACTED]"),
    (re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"), "[PHONE-REDACTED]"),
    (re.compile(r"(?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}"), "[API-KEY-REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS-KEY-REDACTED]"),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE), "[PASSWORD-REDACTED]"),
]


def redact_text(text: str) -> str:
    """Redact PII and credentials from text."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ═══════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════


@app.get("/")
def root():
    return {
        "status": "ContextGuard API running",
        "version": "1.0.0",
        "endpoints": [
            "GET /api/apps",
            "POST /api/scan",
            "GET /api/events",
            "POST /api/webhook/lobster",
            "GET /api/report",
            "POST /api/ioc",
            "GET /api/stats",
            "POST /api/dpi/inspect",
            "POST /api/apps/rescore",
            "GET /api/apps/{app_id}/risk-history",
            "POST /api/ioc/refresh",
            "GET/POST /api/whitelist",
            "GET/POST /api/env",
            "GET /api/env/alerts",
            "POST /api/env/{var_name}/rotate",
            "POST /api/redteam/run",
            "GET /api/redteam/runs",
            "GET/POST /api/incidents",
            "POST /api/incidents/{id}/advance",
        ],
    }


# ──────────────────────────────────────────
# F1: OAuth Risk Scanner
# ──────────────────────────────────────────


@app.get("/api/apps")
def list_apps():
    """Return all scanned OAuth apps with current risk scores."""
    apps = get_apps()
    save_audit_log("api", "list_apps", "oauth_apps", f"Returned {len(apps)} apps")
    return {"apps": apps, "count": len(apps)}


@app.post("/api/scan")
def trigger_scan():
    """M1: On-demand OAuth scan (FR-1.5 manual trigger)."""
    result = run_oauth_scan()
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("detail", "Scan failed"))
    return result


@app.post("/api/workspace/connect")
def connect_workspace(payload: WorkspaceConnectRequest):
    """Dynamically connect a Google Workspace."""
    creds_path = os.path.join(os.path.dirname(__file__), "workspace_creds.json")
    with open(creds_path, "w", encoding="utf-8") as f:
        f.write(payload.creds_json)
    
    os.environ["GOOGLE_WORKSPACE_CREDS"] = creds_path
    os.environ["GOOGLE_ADMIN_EMAIL"] = payload.admin_email
    os.environ["OAUTH_USE_SYNTHETIC"] = "false"
    
    import dotenv
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    dotenv.set_key(env_file, "GOOGLE_WORKSPACE_CREDS", creds_path)
    dotenv.set_key(env_file, "GOOGLE_ADMIN_EMAIL", payload.admin_email)
    dotenv.set_key(env_file, "OAUTH_USE_SYNTHETIC", "false")
    
    # Clear out dummy/synthetic data so the new workspace shows actual state
    clear_oauth_apps()
    
    # We do NOT run the scan here because it takes a long time and writing to .env
    # triggers Uvicorn to reload, which would kill the request.
    return {"status": "connected"}


@app.post("/api/ioc/refresh")
def refresh_iocs():
    """M1 FR-1.3: Refresh IOC list from Gemini threat intelligence."""
    return refresh_ioc_database()


@app.get("/api/scan/schedule")
def scan_schedule_info():
    """FR-1.5: Return configured background scan interval."""
    return {
        "interval_hours": SCAN_INTERVAL_HOURS,
        "scheduler_enabled": not os.getenv("DISABLE_SCAN_SCHEDULER", "").lower() in ("1", "true"),
    }


@app.get("/api/whitelist")
def list_whitelist():
    """M1 FR-1.7: List approved OAuth apps."""
    return {"whitelist": get_whitelist(), "count": len(get_whitelist())}


@app.post("/api/whitelist")
def add_to_whitelist(entry: WhitelistEntry):
    """M1 FR-1.7: Whitelist an OAuth app to suppress false positives."""
    add_whitelist(entry.app_client_id, entry.reason, entry.added_by)
    save_audit_log("admin", "whitelist_add", entry.app_client_id, entry.reason)
    return {"status": "whitelisted", "app_client_id": entry.app_client_id}


@app.delete("/api/whitelist/{app_client_id}")
def delete_from_whitelist(app_client_id: str):
    remove_whitelist(app_client_id)
    return {"status": "removed", "app_client_id": app_client_id}


# ──────────────────────────────────────────
# F2: Lobster Trap DPI Events
# ──────────────────────────────────────────


@app.get("/api/events")
def list_events(hours: int = 24):
    """Return DPI events from the last N hours."""
    events = get_events(hours=hours)
    return {"events": events, "count": len(events)}


@app.post("/api/webhook/lobster")
def lobster_webhook(payload: LobsterWebhookPayload):
    """
    M4 DPI pipeline: structured metadata, Gemini intent, intent-mismatch policy.
    """
    logger.info(
        "Lobster Trap event: policy=%s action=%s",
        payload.policy_triggered,
        payload.action_taken,
    )

    structured = extract_structured_metadata(
        payload.metadata, payload.policy_triggered, payload.action_taken
    )
    declared = extract_declared_intent(payload.metadata) or structured.get("declared_intent")
    if declared:
        structured["declared_intent"] = declared

    policy_triggered = payload.policy_triggered
    action_taken = payload.action_taken

    try:
        classification = classify_prompt_intent({
            "policy_triggered": policy_triggered,
            "action_taken": action_taken,
            "metadata": structured,
        })
    except Exception as e:
        logger.error("Gemini classification failed: %s", e)
        severity_map = {
            "QUARANTINE": "CRITICAL",
            "DENY": "HIGH",
            "LOG": "MEDIUM",
            "HUMAN_REVIEW": "MEDIUM",
        }
        classification = {
            "intent_category": structured.get("proxy_detected_intent", "UNKNOWN"),
            "confidence": structured.get("proxy_intent_confidence", 0.5),
            "severity": severity_map.get(action_taken, "UNKNOWN"),
            "alert_message": f"Policy {policy_triggered} triggered — action: {action_taken}",
        }

    mismatch = check_intent_mismatch(
        declared_intent=declared,
        detected_intent=classification.get("intent_category"),
        detected_confidence=float(classification.get("confidence", 0.75)),
        proxy_intent=structured.get("proxy_detected_intent"),
        proxy_confidence=float(structured.get("proxy_intent_confidence") or 0),
    )
    structured["intent_mismatch"] = mismatch

    agent_id = str(structured.get("request_id") or "lobster_trap_default")
    update_agent_baseline(agent_id, classification.get("intent_category", "UNKNOWN"), classification.get("severity", "UNKNOWN"))
    behavior = compute_behavioral_deviation(
        agent_id,
        classification.get("intent_category", "UNKNOWN"),
        classification.get("severity", "UNKNOWN"),
    )
    structured["behavioral_deviation"] = behavior
    if behavior.get("behavioral_anomaly"):
        recalculate_all_app_scores(score_oauth_app, trigger_reason="behavioral_anomaly")
        save_audit_log("system", "rescore_triggered", "oauth_apps", "Behavioral anomaly detected")

    policy_triggered, action_taken, severity = apply_intent_mismatch_policy(
        policy_triggered,
        action_taken,
        classification.get("severity", "UNKNOWN"),
        mismatch,
    )
    if mismatch.get("intent_mismatch"):
        classification["alert_message"] = (
            f"Intent mismatch: declared '{mismatch.get('declared_intent')}' vs "
            f"detected '{mismatch.get('detected_intent')}' "
            f"(Δ={mismatch.get('confidence_delta')}). {classification.get('alert_message', '')}"
        )

    event_record = {
        "timestamp": payload.timestamp,
        "policy_triggered": policy_triggered,
        "action_taken": action_taken,
        "prompt_hash": payload.prompt_hash,
        "intent_category": classification.get("intent_category", "UNKNOWN"),
        "severity": severity,
        "alert_message": redact_text(classification.get("alert_message", "")),
        "metadata": structured,
    }

    env_alerts: list = []
    # M3: Environment Variable Guardian — Lobster Trap integration (FR-3.3–3.4)
    env_alerts = analyze_dpi_for_env_access(
        payload.metadata.get("redacted_prompt"),
        structured,
    )
    if env_alerts:
        structured["env_alerts"] = env_alerts
        event_record["metadata"] = structured
        for alert in env_alerts:
            save_env_variable({
                "var_name": alert["var_name"],
                "classification": alert["classification"],
                "last_accessed": payload.timestamp,
                "accessing_agents": ["lobster_trap"],
            })

    event_id = save_event(event_record)

    for alert in env_alerts:
        alert["event_id"] = event_id
        save_env_alert(alert)
        if alert.get("severity") == "CRITICAL":
            try:
                create_incident_from_event(event_id)
            except Exception as e:
                logger.warning("Auto-incident creation failed: %s", e)

    save_audit_log(
        "lobster_trap",
        f"dpi_event_{action_taken.lower()}",
        f"event_{event_id}",
        f"Policy: {policy_triggered}, Severity: {severity}, mismatch={mismatch.get('intent_mismatch')}",
    )

    logger.info(
        "Event stored: id=%d severity=%s intent=%s mismatch=%s",
        event_id,
        severity,
        classification.get("intent_category", "?"),
        mismatch.get("intent_mismatch"),
    )

    return {
        "status": "received",
        "event_id": event_id,
        "classification": {
            "intent_category": classification.get("intent_category"),
            "severity": severity,
            "alert_message": classification.get("alert_message"),
            "confidence": classification.get("confidence"),
        },
        "intent_mismatch": mismatch,
        "dpi_metadata": structured,
    }


@app.post("/api/dpi/inspect")
def inspect_prompt(body: InspectPromptRequest):
    """
    FR-4.7: Single-prompt debugger — local heuristics + Gemini classification.
    """
    local = inspect_prompt_local(body.prompt)
    metadata = {**local, "declared_intent": body.declared_intent}
    classification = classify_prompt_intent({
        "policy_triggered": "manual_inspect",
        "action_taken": "LOG",
        "metadata": metadata,
    })
    mismatch = check_intent_mismatch(
        declared_intent=body.declared_intent,
        detected_intent=classification.get("intent_category"),
        detected_confidence=float(classification.get("confidence", 0.75)),
    )
    return {
        "local_checks": local,
        "classification": classification,
        "intent_mismatch": mismatch,
        "prompt_hash": hashlib.sha256(body.prompt.encode("utf-8")).hexdigest(),
    }


@app.post("/api/dpi/test")
def live_dpi_test(body: InspectPromptRequest):
    """
    Live Prompt Injection Tester — classifies any prompt with Gemini,
    saves it as a real DPI event, returns full verdict.
    Used by the in-app Prompt Tester UI.
    """
    from dpi import inspect_prompt_local
    local = inspect_prompt_local(body.prompt)

    # Determine likely policy from heuristics
    contains_creds = local.get("contains_credentials", False)
    contains_injection = local.get("contains_injection_patterns", False)
    contains_pii = local.get("contains_pii", False)
    contains_paths = local.get("contains_sensitive_paths", False)

    if contains_creds or contains_paths:
        policy = "credential-exfiltration"
        action = "QUARANTINE"
    elif contains_injection:
        policy = "prompt-injection"
        action = "DENY"
    elif contains_pii:
        policy = "pii-detection"
        action = "HUMAN_REVIEW"
    else:
        policy = "rate-limit-anomaly"
        action = "LOG"

    structured = {**local, "declared_intent": body.declared_intent or "LEGITIMATE", "request_id": f"live-test-{int(__import__('time').time())}"}
    try:
        classification = classify_prompt_intent({
            "policy_triggered": policy,
            "action_taken": action,
            "metadata": structured,
        })
    except Exception as e:
        classification = {
            "intent_category": "UNKNOWN",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "alert_message": f"Classification failed: {e}",
        }

    mismatch = check_intent_mismatch(
        declared_intent=body.declared_intent,
        detected_intent=classification.get("intent_category"),
        detected_confidence=float(classification.get("confidence", 0.75)),
    )

    severity = classification.get("severity", "MEDIUM")
    if mismatch.get("intent_mismatch"):
        classification["alert_message"] = (
            f"INTENT MISMATCH: Declared '{body.declared_intent}' but detected "
            f"'{classification.get('intent_category')}' with {int(float(classification.get('confidence', 0))*100)}% confidence. "
            + classification.get("alert_message", "")
        )
        if severity in ("LOW", "MEDIUM"):
            severity = "HIGH"

    # Decide final verdict
    blocked = action in ("DENY", "QUARANTINE") or mismatch.get("intent_mismatch")
    verdict = "BLOCKED" if blocked else ("FLAGGED" if action in ("HUMAN_REVIEW", "LOG") else "ALLOWED")

    # Save as real event in database
    event_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "policy_triggered": policy,
        "action_taken": action,
        "prompt_hash": hashlib.sha256(body.prompt.encode("utf-8")).hexdigest(),
        "intent_category": classification.get("intent_category", "UNKNOWN"),
        "severity": severity,
        "alert_message": redact_text(classification.get("alert_message", "")),
        "metadata": structured,
    }
    event_id = save_event(event_record)
    save_audit_log("dpi_tester", f"prompt_test_{verdict.lower()}", f"event_{event_id}", f"Severity: {severity}")

    return {
        "verdict": verdict,
        "event_id": event_id,
        "policy_triggered": policy,
        "action": action,
        "severity": severity,
        "intent_detected": classification.get("intent_category"),
        "confidence": classification.get("confidence"),
        "alert_message": classification.get("alert_message"),
        "intent_mismatch": mismatch.get("intent_mismatch", False),
        "local_checks": local,
        "blocked": blocked,
    }


@app.post("/api/apps/rescore")
def rescore_all_apps():
    """FR-2.5: Recalculate all OAuth risk scores (IOC update, permission change, anomaly)."""
    updated = recalculate_all_app_scores(score_oauth_app, trigger_reason="manual_rescore")
    save_audit_log("api", "rescore_all", "oauth_apps", f"Rescored {len(updated)} apps")
    return {"status": "complete", "apps_updated": len(updated), "apps": updated}


@app.get("/api/apps/{app_id}/risk-history")
def app_risk_history(app_id: str, days: int = 90):
    """FR-5.5 support: risk score history for trend charts."""
    history = get_risk_score_history(app_id, days=days)
    app = get_app_by_id(app_id)
    return {"app_id": app_id, "app": app, "history": history, "count": len(history)}


# ──────────────────────────────────────────
# F3: Gemini Compliance Report
# ──────────────────────────────────────────


@app.get("/api/report")
def get_compliance_report():
    """
    Generate Gemini compliance report from last 24h events.
    SRS FR: Compliance report generation < 15 seconds.
    """
    logger.info("Generating compliance report")
    events = get_events(hours=24)
    apps = get_apps()

    # Prepare events for Gemini (strip raw metadata to save tokens)
    simplified_events = []
    for event in events:
        simplified_events.append({
            "timestamp": event.get("timestamp"),
            "policy": event.get("policy_triggered"),
            "action": event.get("action_taken"),
            "severity": event.get("severity"),
            "intent": event.get("intent_category"),
            "alert": event.get("alert_message"),
        })
        
    critical_apps = []
    for app in apps:
        if app.get("risk_category") in ("CRITICAL", "HIGH"):
            critical_apps.append({
                "name": app.get("name"),
                "risk_score": app.get("risk_score"),
                "risk_category": app.get("risk_category"),
                "explanation": app.get("explanation"),
                "scopes": app.get("scopes", [])
            })

    report_text = generate_report(simplified_events, critical_apps)

    save_audit_log("api", "report_generated", "compliance", f"Report covers {len(events)} events")

    return {
        "report": report_text,
        "event_count": len(events),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────────────────────────────
# IOC Management
# ──────────────────────────────────────────


@app.post("/api/ioc")
def add_ioc(ioc: IOCEntry):
    """
    Add a new IOC entry to the local list.
    SRS FR-1.6: Allow administrator to manually add new IOC entries.
    """
    save_ioc(ioc.model_dump())
    save_audit_log("admin", "ioc_added", ioc.app_client_id, f"Severity: {ioc.severity}")
    logger.info("IOC added: %s (%s)", ioc.app_client_id, ioc.severity)

    # FR-2.5: recalculate scores when new IOC added
    rescored = recalculate_all_app_scores(score_oauth_app, trigger_reason="ioc_added")
    return {
        "status": "ioc_added",
        "ioc": ioc.model_dump(),
        "apps_rescored": len(rescored),
    }


@app.get("/api/iocs")
def list_iocs():
    """Return all IOC entries."""
    iocs = get_iocs()
    return {"iocs": iocs, "count": len(iocs)}


# ──────────────────────────────────────────
# Dashboard Statistics
# ──────────────────────────────────────────


@app.get("/api/stats")
def get_stats():
    """
    Dashboard statistics for the frontend.
    Returns aggregated counts for display.
    """
    apps = get_apps()
    events = get_events(hours=24)
    severity_counts = get_event_count_by_severity()

    critical_apps = [a for a in apps if a.get("risk_category") == "CRITICAL"]
    high_apps = [a for a in apps if a.get("risk_category") == "HIGH"]

    return {
        "total_apps": len(apps),
        "critical_apps": len(critical_apps),
        "high_risk_apps": len(high_apps),
        "total_events_24h": len(events),
        "events_by_severity": severity_counts,
        "ioc_matches": len([a for a in apps if a.get("is_ioc")]),
    }


# ──────────────────────────────────────────
# Audit Log
# ──────────────────────────────────────────


@app.get("/api/audit")
def list_audit_log(limit: int = 100):
    """Return the most recent audit log entries."""
    logs = get_audit_log(limit=limit)
    return {"audit_log": logs, "count": len(logs)}


# ──────────────────────────────────────────
# M3: Environment Variable Guardian
# ──────────────────────────────────────────


@app.get("/api/env")
def list_env_variables():
    """List monitored environment variables with classification and rotation status (FR-3.6)."""
    variables = get_env_variables()
    for var in variables:
        var["rotation_status"] = days_since_rotation(var.get("last_rotated"))
    return {"variables": variables, "count": len(variables)}


@app.post("/api/env/classify")
def classify_env(body: EnvVarRequest):
    """FR-3.1–3.2: Classify a single environment variable."""
    result = classify_env_var(body.var_name, body.value_hint)
    save_env_variable({
        "var_name": result["var_name"],
        "classification": result["classification"],
        "value_hash": result.get("value_hash"),
    })
    return {
        **result,
        "remediation": get_remediation_workflow(body.var_name),
    }


@app.get("/api/env/alerts")
def list_env_alerts(hours: int = 24, unacknowledged_only: bool = False):
    """FR-3.3: Env guardian alerts (target delivery <30s from DPI event)."""
    alerts = get_env_alerts(hours=hours, unacknowledged_only=unacknowledged_only)
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/api/env/{var_name}/rotate")
def record_env_rotation(var_name: str):
    """FR-3.6: Mark credential as rotated."""
    mark_env_rotated(var_name)
    save_audit_log("admin", "env_rotated", var_name, "Rotation recorded")
    return {
        "status": "rotated",
        "var_name": var_name,
        "remediation": get_remediation_workflow(var_name),
    }


@app.post("/api/env/scan")
def scan_real_env_variables():
    """
    Scan real OS environment variables, classify sensitive ones with Gemini,
    and persist them. Returns only SENSITIVE/MISCLASSIFIED vars (never values).
    """
    import os as _os
    SKIP = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC",
            "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS", "HOMEDRIVE",
            "HOMEPATH", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES",
            "PROGRAMDATA", "COMMONPROGRAMFILES", "SYSTEMDRIVE", "USERNAME",
            "USERDOMAIN", "COMPUTERNAME", "LOGONSERVER", "SESSIONNAME"}

    all_vars = {k: v for k, v in _os.environ.items() if k not in SKIP and len(k) < 60}
    classified = []
    saved_count = 0

    for var_name, value in all_vars.items():
        # Pass only a hint (length + prefix pattern), never the real value
        value_hint = value[:6] + "..." if len(value) > 6 else ""
        result = classify_env_var(var_name, value_hint, use_gemini=False)  # fast, rule-based
        if result["classification"] in ("SENSITIVE", "MISCLASSIFIED"):
            save_env_variable({
                "var_name": var_name,
                "classification": result["classification"],
                "value_hash": result.get("value_hash"),
            })
            classified.append({
                "var_name": var_name,
                "classification": result["classification"],
                "reasons": result.get("reasons", []),
                "rotation_status": days_since_rotation(None),
            })
            saved_count += 1

    save_audit_log("system", "env_scan", "env_variables", f"Scanned {len(all_vars)} vars, {saved_count} sensitive")
    return {
        "status": "scanned",
        "total_scanned": len(all_vars),
        "sensitive_found": saved_count,
        "variables": classified,
    }


# ──────────────────────────────────────────
# M6: Red-Team Simulator
# ──────────────────────────────────────────


@app.post("/api/redteam/run")
def run_redteam():
    """FR-6.1–6.3: Execute AI supply-chain attack simulation."""
    logger.info("Red-team simulation started")
    report = run_redteam_simulation()
    run_id = save_redteam_run(report)
    save_audit_log(
        "redteam",
        "simulation_complete",
        f"run_{run_id}",
        f"Detection rate: {report.get('detection_rate')}%",
    )
    return {"run_id": run_id, **report}


@app.get("/api/redteam/runs")
def list_redteam_runs(limit: int = 10):
    runs = get_redteam_runs(limit=limit)
    return {"runs": runs, "count": len(runs)}


# ──────────────────────────────────────────
# M7: Incident Response
# ──────────────────────────────────────────


@app.get("/api/incidents")
def list_incidents(status: Optional[str] = None):
    incidents = get_incidents(status=status)
    return {"incidents": incidents, "count": len(incidents)}


@app.post("/api/incidents")
def open_incident(event_id: int):
    """Create guided remediation workflow from DPI event."""
    try:
        incident = create_incident_from_event(event_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    save_audit_log("soc", "incident_opened", f"incident_{incident['id']}", f"event_{event_id}")
    return incident


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: int):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/incidents/{incident_id}/advance")
def advance_incident(incident_id: int, body: IncidentStepAdvance):
    """M7: Complete a workflow step and advance."""
    try:
        return advance_incident_step(incident_id, body.step_id, body.notes)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.get("/api/incidents/workflows/{workflow_key}")
def incident_workflow_template(workflow_key: str):
    return get_workflow_definition(workflow_key)


@app.post("/api/incidents/{incident_id}/rotate")
def one_click_rotation(incident_id: int, var_name: Optional[str] = None):
    """M7: One-click credential rotation coordination."""
    names = [var_name] if var_name else None
    try:
        return coordinate_credential_rotation(incident_id, names)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.post("/api/incidents/revoke-oauth/{app_client_id}")
def coordinate_oauth_revoke(app_client_id: str):
    """M7: OAuth revocation coordination checklist."""
    return revoke_oauth_app_coordination(app_client_id)


@app.get("/api/dpi/backends")
def list_dpi_backends():
    """FR-4.5: Supported LLM backends."""
    return {"backends": get_supported_backends()}


@app.get("/api/modules/status")
def modules_status():
    """SRS module implementation checklist."""
    return get_modules_status()


@app.get("/api/status")
def system_status():
    """Real-time health check: workspace connection, proxy, DB."""
    import requests as req

    creds_path = os.getenv("GOOGLE_WORKSPACE_CREDS", "")
    admin_email = os.getenv("GOOGLE_ADMIN_EMAIL", "")
    use_synthetic = os.getenv("OAUTH_USE_SYNTHETIC", "true").lower() in ("1", "true", "yes")

    workspace_connected = (
        not use_synthetic
        and bool(creds_path)
        and os.path.exists(creds_path)
        and bool(admin_email)
    )

    proxy_url = os.getenv("PROXY_URL", "http://localhost:8080")
    proxy_online = False
    try:
        req.get(f"{proxy_url}/health", timeout=2)
        proxy_online = True
    except Exception:
        proxy_online = False

    apps = get_apps()
    return {
        "workspace": {
            "connected": workspace_connected,
            "admin_email": admin_email if workspace_connected else None,
            "mode": "synthetic_demo" if use_synthetic else "real_workspace",
            "apps_in_db": len(apps),
        },
        "proxy": {
            "url": proxy_url,
            "online": proxy_online,
        },
        "gemini_key_set": bool(os.getenv("GEMINI_API_KEY", "")),
        "db_path": os.path.basename(os.getenv("DB_PATH", "contextguard.db")),
    }


@app.post("/api/workspace/disconnect")
def disconnect_workspace():
    """Reset to synthetic demo mode and clear real workspace data."""
    import dotenv
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    dotenv.set_key(env_file, "OAUTH_USE_SYNTHETIC", "true")
    os.environ["OAUTH_USE_SYNTHETIC"] = "true"
    clear_oauth_apps()
    save_audit_log("admin", "workspace_disconnected", "workspace", "Switched back to synthetic demo mode")
    return {"status": "disconnected", "mode": "synthetic_demo"}

# ──────────────────────────────────────────
# Frontend Serving (React build)
# ──────────────────────────────────────────

frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(request: Request, full_path: str):
        # Ignore API calls
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "API route not found"})
        
        # Check if the requested file exists in dist (like favicon.ico, manifest.json)
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
            
        # Fallback to index.html for React Router
        return FileResponse(os.path.join(frontend_dist, "index.html"))

if __name__ == "__main__":
    import uvicorn
    import subprocess
    import sys
    
    frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
    
    print("==================================================")
    print("🚀 ContextGuard Starting...")
    print("==================================================")
    
    # Check if frontend dependencies are installed
    if not os.path.exists(os.path.join(frontend_dir, "node_modules")):
        print("📦 Installing frontend dependencies...")
        subprocess.run("npm install", cwd=frontend_dir, shell=True)
    
    # Start the frontend dev server in the background
    print("✨ Starting React Frontend (Vite) in background...")
    frontend_process = subprocess.Popen("npm run dev", cwd=frontend_dir, shell=True)
    
    lobster_dir = os.path.join(os.path.dirname(__file__), "..", "lobster")
    lobster_process = None
    webhook_process = None
    
    if os.path.exists(os.path.join(lobster_dir, "lobstertrap.exe")):
        print("🦞 Starting Lobster Trap DPI Proxy in background...")
        lobster_cmd = r".\lobstertrap.exe serve --policy configs/default_policy.yaml --backend https://api.openai.com --listen :8080 --audit-log lobster_audit.jsonl"
        lobster_process = subprocess.Popen(lobster_cmd, cwd=lobster_dir, shell=True)
        
        print("🌉 Starting Webhook Bridge in background...")
        webhook_process = subprocess.Popen("python webhook_bridge.py --log-file lobster_audit.jsonl", cwd=lobster_dir, shell=True)
    
    print("🛡️ Starting FastAPI Backend...")
    print("👉 Dashboard will be available at: http://localhost:5173")
    print("👉 API Backend running at: http://localhost:3000")
    print("👉 Proxy running at: http://localhost:8080")
    print("==================================================")
    
    try:
        uvicorn.run("main:app", host="0.0.0.0", port=3000)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n🛑 Shutting down ContextGuard...")
        frontend_process.terminate()
        if lobster_process:
            lobster_process.terminate()
        if webhook_process:
            webhook_process.terminate()
        sys.exit(0)

