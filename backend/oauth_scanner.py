"""
ContextGuard — M1 OAuth Risk Scanner
SRS §4.1: Workspace enumeration, IOC matching, scope drift, whitelist, scheduled scans.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from database import (
    check_ioc,
    get_app_by_id,
    is_whitelisted,
    save_app,
    save_app_snapshot,
    save_audit_log,
    save_ioc,
    save_risk_score_history,
)
from gemini import call_gemini_with_search, score_oauth_app
from google_workspace import scan_oauth_apps

logger = logging.getLogger("contextguard.oauth")

KNOWN_BREACH_IOC = (
    "110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com"
)


def detect_scope_drift(granted_scopes: list, declared_scopes: list | None) -> dict[str, Any]:
    """
    FR-1.6: Flag apps granted more scopes than declared in manifest.
    """
    if not declared_scopes:
        return {"scope_drift": False, "extra_scopes": [], "declared_scopes": []}

    granted = {str(s).strip() for s in granted_scopes}
    declared = {str(s).strip() for s in declared_scopes}
    extra = sorted(granted - declared)
    return {
        "scope_drift": len(extra) > 0,
        "extra_scopes": extra,
        "declared_scopes": sorted(declared),
        "granted_count": len(granted),
        "declared_count": len(declared),
    }


def discover_iocs_via_intel() -> list[dict]:
    """
    FR-1.3: Enrich IOC list using Gemini threat intelligence (web-search style prompt).
    """
    prompt = """You are a threat intelligence analyst with web search. List known malicious or compromised
third-party OAuth application client IDs published in public security bulletins since 2025,
especially related to AI SaaS supply-chain attacks.

Return ONLY a JSON array (max 5 entries). Each object:
{"app_client_id": "<id>", "source": "<bulletin>", "severity": "CRITICAL", "description": "<1 sentence>"}

If none are known with confidence, return an empty array []."""
    try:
        raw = call_gemini_with_search(prompt, use_pro=False)
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0]
        data = json.loads(cleaned)
        if isinstance(data, dict) and "iocs" in data:
            return data["iocs"]
        if isinstance(data, list):
            return data
    except Exception as e:
        logger.warning("IOC intel discovery failed: %s", e)
    return []


def refresh_ioc_database() -> dict:
    """FR-1.3: Update IOC database from threat intel."""
    added = 0
    for ioc in discover_iocs_via_intel():
        client_id = ioc.get("app_client_id")
        if not client_id:
            continue
        save_ioc({
            "app_client_id": client_id,
            "source": ioc.get("source", "Gemini Threat Intel"),
            "severity": ioc.get("severity", "CRITICAL"),
            "description": ioc.get("description", ""),
        })
        added += 1
    save_audit_log("system", "ioc_refresh", "ioc_list", f"Processed intel, {added} new entries")
    return {"status": "ok", "new_iocs_processed": added}


def score_and_save_app(app_data: dict) -> dict:
    """Score one OAuth app and persist."""
    app_id = app_data.get("app_id", "")
    if is_whitelisted(app_id):
        app_data["risk_score"] = 0
        app_data["risk_category"] = "LOW"
        app_data["explanation"] = "Whitelisted approved application — alerts suppressed."
        app_data["is_ioc"] = False
        app_data["whitelisted"] = True
        save_app(app_data)
        return app_data

    is_ioc = check_ioc(app_id)
    drift = detect_scope_drift(
        app_data.get("scopes") or [],
        app_data.get("declared_scopes"),
    )
    app_data["scope_drift"] = drift

    permission_changed = save_app_snapshot(
        app_id,
        app_data.get("scopes") or [],
        app_data.get("user_count", 0),
    )
    prior = get_app_by_id(app_id)

    try:
        score_result = score_oauth_app(
            name=app_data["name"],
            publisher=app_data.get("publisher", "Unknown"),
            scopes=app_data.get("scopes", []),
            user_count=app_data.get("user_count", 0),
            is_ioc=is_ioc,
            prior_score=prior.get("risk_score") if prior else None,
            permission_changed=permission_changed,
        )
    except Exception as e:
        logger.error("Scoring failed for %s: %s", app_data["name"], e)
        score_result = {
            "risk_score": 95 if is_ioc else 30,
            "risk_category": "CRITICAL" if is_ioc else "MEDIUM",
            "explanation": str(e),
        }

    if is_ioc:
        score_result["risk_score"] = max(int(score_result.get("risk_score", 0)), 95)
        score_result["risk_category"] = "CRITICAL"
        score_result["explanation"] = (
            f"IOC MATCH: {score_result.get('explanation', '')} "
            "Matches a known supply-chain breach indicator in the IOC database."
        )

    if drift.get("scope_drift"):
        from gemini import category_from_score
        score_result["risk_score"] = min(100, int(score_result.get("risk_score", 0)) + 15)
        score_result["risk_category"] = category_from_score(int(score_result["risk_score"]))
        score_result["explanation"] = (
            f"{score_result.get('explanation', '')} "
            f"SCOPE DRIFT: {len(drift['extra_scopes'])} undeclared permission(s) granted."
        ).strip()

    app_record = {
        **app_data,
        "risk_score": score_result.get("risk_score", 0),
        "risk_category": score_result.get("risk_category", "UNKNOWN"),
        "explanation": score_result.get("explanation", ""),
        "contributing_factors": score_result.get("contributing_factors", {}),
        "threat_intel": score_result.get("threat_intel", {}),
        "is_ioc": is_ioc,
        "whitelisted": False,
    }
    save_app(app_record)
    trigger = "permission_change" if permission_changed else "oauth_scan"
    save_risk_score_history(
        app_id,
        app_record["risk_score"],
        app_record["risk_category"],
        app_record.get("contributing_factors"),
        trigger,
    )
    return app_record


def run_oauth_scan() -> dict[str, Any]:
    """
    FR-1.1–1.5: Full OAuth scan pipeline.
    """
    logger.info("M1 OAuth scan started")
    save_audit_log("api", "scan_triggered", "oauth_apps", "OAuth scan started")

    raw_apps = scan_oauth_apps()
    if not raw_apps:
        save_audit_log("api", "scan_completed", "oauth_apps", "Workspace scan returned 0 apps")
        return {
            "status": "scan_complete",
            "apps_scanned": 0,
            "apps": [],
            "ioc_matches": 0,
            "scope_drift_count": 0,
            "whitelisted_count": 0,
            "message": "No OAuth apps found in workspace. Either the workspace is clean or credentials lack token-listing permissions.",
        }

    scored = [score_and_save_app(app) for app in raw_apps]
    save_audit_log("api", "scan_completed", "oauth_apps", f"Scanned {len(scored)} apps")

    return {
        "status": "scan_complete",
        "apps_scanned": len(scored),
        "apps": scored,
        "ioc_matches": len([a for a in scored if a.get("is_ioc")]),
        "scope_drift_count": len([a for a in scored if a.get("scope_drift", {}).get("scope_drift")]),
        "whitelisted_count": len([a for a in scored if a.get("whitelisted")]),
    }
