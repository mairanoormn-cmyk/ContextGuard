"""
ContextGuard — M7 Incident Response Workflows
SRS §2.2 M7: Guided remediation, credential rotation coordination.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from database import (
    complete_rotation_ticket,
    get_event,
    get_incident,
    mark_env_rotated,
    save_audit_log,
    save_incident,
    save_rotation_ticket,
    update_incident,
)
from env_guardian import get_remediation_workflow

logger = logging.getLogger("contextguard.incident")

WORKFLOW_TEMPLATES: dict[str, dict] = {
    "credential_exfiltration": {
        "title": "Credential Exfiltration Response",
        "severity": "CRITICAL",
        "steps": [
            {"id": 1, "action": "Isolate affected AI agent / disable OAuth app access", "owner": "SOC"},
            {"id": 2, "action": "Identify exposed secrets via DPI event metadata", "owner": "SOC"},
            {"id": 3, "action": "Rotate compromised credentials (see remediation playbook)", "owner": "IT Admin"},
            {"id": 4, "action": "Revoke third-party OAuth tokens for affected users", "owner": "IT Admin"},
            {"id": 5, "action": "Re-scan Workspace OAuth apps (POST /api/scan)", "owner": "Automated"},
            {"id": 6, "action": "Document incident in compliance audit log", "owner": "Compliance"},
        ],
    },
    "prompt_injection": {
        "title": "Prompt Injection Incident",
        "severity": "HIGH",
        "steps": [
            {"id": 1, "action": "Confirm DENY/QUARANTINE action in Lobster Trap logs", "owner": "SOC"},
            {"id": 2, "action": "Review agent prompt source and upstream data feeds", "owner": "Security Analyst"},
            {"id": 3, "action": "Update DPI policy rules if new pattern identified", "owner": "Admin"},
            {"id": 4, "action": "Notify application owner", "owner": "SOC"},
        ],
    },
    "intent_mismatch": {
        "title": "Intent Mismatch — Possible Agent Compromise",
        "severity": "HIGH",
        "steps": [
            {"id": 1, "action": "Place agent in HUMAN_REVIEW queue — halt autonomous actions", "owner": "SOC"},
            {"id": 2, "action": "Compare declared vs detected intent in event metadata", "owner": "Analyst"},
            {"id": 3, "action": "Validate agent software version and supply chain", "owner": "DevOps"},
            {"id": 4, "action": "Re-enable only after manual approval", "owner": "CISO"},
        ],
    },
    "env_guardian_alert": {
        "title": "Environment Variable Exposure",
        "severity": "CRITICAL",
        "steps": [
            {"id": 1, "action": "Block further agent access to affected variables", "owner": "Automated"},
            {"id": 2, "action": "Execute platform-specific rotation playbook", "owner": "IT Admin"},
            {"id": 3, "action": "Mark credential rotation complete in Env Guardian", "owner": "IT Admin"},
            {"id": 4, "action": "Run red-team validation (POST /api/redteam/run)", "owner": "SOC"},
        ],
    },
    "oauth_ioc_match": {
        "title": "Malicious OAuth Application Detected",
        "severity": "CRITICAL",
        "steps": [
            {"id": 1, "action": "Revoke OAuth app access for all users immediately", "owner": "IT Admin"},
            {"id": 2, "action": "Reset passwords for affected Google Workspace accounts", "owner": "IT Admin"},
            {"id": 3, "action": "Audit all downstream connected systems and cloud consoles", "owner": "SOC"},
            {"id": 4, "action": "Add app to permanent block list", "owner": "Admin"},
            {"id": 5, "action": "File breach notification per organizational policy", "owner": "Compliance"},
        ],
    },
    "generic": {
        "title": "Security Event Response",
        "severity": "MEDIUM",
        "steps": [
            {"id": 1, "action": "Triage event severity and scope", "owner": "SOC"},
            {"id": 2, "action": "Apply containment per DPI policy action", "owner": "Automated"},
            {"id": 3, "action": "Close incident after verification", "owner": "Analyst"},
        ],
    },
}


def _workflow_key_for_event(event: dict) -> str:
    intent = (event.get("intent_category") or "").upper()
    policy = (event.get("policy_triggered") or "").lower()
    meta = event.get("metadata") or {}
    if meta.get("env_alerts"):
        return "env_guardian_alert"
    if "ioc" in policy or intent == "OAUTH_COMPROMISE":
        return "oauth_ioc_match"
    if "intent_mismatch" in policy or meta.get("intent_mismatch", {}).get("intent_mismatch"):
        return "intent_mismatch"
    if "injection" in policy or intent == "PROMPT_INJECTION":
        return "prompt_injection"
    if "credential" in policy or intent == "CREDENTIAL_EXFILTRATION":
        return "credential_exfiltration"
    return "generic"


def create_incident_from_event(event_id: int) -> dict[str, Any]:
    """Create guided incident workflow from DPI event."""
    event = get_event(event_id)
    if not event:
        raise ValueError(f"Event {event_id} not found")

    workflow_key = _workflow_key_for_event(event)
    template = WORKFLOW_TEMPLATES[workflow_key]
    steps = [{**s, "status": "pending"} for s in template["steps"]]

    remediation = None
    meta = event.get("metadata") or {}
    env_alerts = meta.get("env_alerts") or []
    if env_alerts:
        remediation = env_alerts[0].get("remediation")

    incident = {
        "event_id": event_id,
        "workflow_key": workflow_key,
        "title": template["title"],
        "severity": event.get("severity") or template["severity"],
        "status": "open",
        "current_step": 1,
        "steps": steps,
        "remediation_playbook": remediation,
        "event_summary": {
            "policy": event.get("policy_triggered"),
            "action": event.get("action_taken"),
            "intent": event.get("intent_category"),
            "alert": event.get("alert_message"),
        },
    }
    incident_id = save_incident(incident)
    incident["id"] = incident_id
    return incident


def advance_incident_step(incident_id: int, step_id: int, notes: str = "") -> dict:
    """Mark workflow step complete and advance."""
    from database import get_incident

    incident = get_incident(incident_id)
    if not incident:
        raise ValueError("Incident not found")

    steps = incident.get("steps", [])
    for step in steps:
        if step["id"] == step_id:
            step["status"] = "completed"
            step["completed_at"] = datetime.now(timezone.utc).isoformat()
            if notes:
                step["notes"] = notes

    pending = [s for s in steps if s.get("status") != "completed"]
    new_status = "resolved" if not pending else "in_progress"
    current_step = pending[0]["id"] if pending else steps[-1]["id"]

    update_incident(incident_id, {
        "steps": steps,
        "status": new_status,
        "current_step": current_step,
    })
    return get_incident(incident_id)


def get_workflow_definition(workflow_key: str) -> dict:
    return WORKFLOW_TEMPLATES.get(workflow_key, WORKFLOW_TEMPLATES["generic"])


def coordinate_credential_rotation(incident_id: int, var_names: list[str] | None = None) -> dict:
    """
    M7: One-click credential rotation coordination.
    Creates rotation tickets, marks steps complete, records rotation timestamps.
    """
    incident = get_incident(incident_id)
    if not incident:
        raise ValueError("Incident not found")

    event = get_event(incident.get("event_id")) if incident.get("event_id") else None
    meta = (event or {}).get("metadata") or {}
    env_alerts = meta.get("env_alerts") or []

    targets = var_names or [a.get("var_name") for a in env_alerts if a.get("var_name")]
    if not targets:
        targets = ["GENERIC_SECRET"]

    tickets = []
    for var_name in targets:
        playbook = get_remediation_workflow(var_name)
        ticket_id = save_rotation_ticket(
            incident_id,
            var_name,
            playbook.get("inferred_service", "generic"),
            playbook,
        )
        mark_env_rotated(var_name)
        complete_rotation_ticket(ticket_id)
        tickets.append({
            "ticket_id": ticket_id,
            "var_name": var_name,
            "service": playbook.get("inferred_service"),
            "status": "completed",
            "playbook_steps": playbook.get("steps", []),
        })

    # Auto-complete rotation workflow steps
    for step in incident.get("steps", []):
        if "rotation" in step.get("action", "").lower() or "Rotate" in step.get("action", ""):
            step["status"] = "completed"
            step["completed_at"] = datetime.now(timezone.utc).isoformat()
            step["notes"] = "One-click rotation coordinated"

    update_incident(incident_id, {
        "steps": incident.get("steps", []),
        "status": "in_progress",
        "current_step": 4,
    })

    save_audit_log(
        "incident_response",
        "rotation_coordinated",
        f"incident_{incident_id}",
        f"Rotated {len(tickets)} credential(s)",
    )

    return {
        "incident_id": incident_id,
        "rotation_tickets": tickets,
        "message": f"Coordinated rotation for {len(tickets)} credential(s). Update secrets in vault per playbook.",
    }


def revoke_oauth_app_coordination(app_client_id: str) -> dict:
    """M7: Coordinate OAuth app revocation (audit + checklist)."""
    steps = [
        "Revoke app access in Google Workspace Admin Console → Security → API controls.",
        "Force password reset for all users who authorized the app.",
        "Run POST /api/scan to verify removal.",
        "Add to block list if malicious.",
    ]
    save_audit_log("incident_response", "oauth_revoke_coordinated", app_client_id, "Revocation checklist issued")
    return {"app_client_id": app_client_id, "revocation_steps": steps, "status": "coordination_issued"}
