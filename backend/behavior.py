"""
ContextGuard — Behavioral baseline & anomaly detection (FR-2.2, FR-2.5).
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from database import get_agent_baseline, save_agent_baseline


def update_agent_baseline(agent_id: str, intent_category: str, severity: str) -> None:
    """Record DPI event into rolling agent behavior profile."""
    baseline = get_agent_baseline(agent_id) or {
        "agent_id": agent_id,
        "intent_counts": {},
        "severity_counts": {},
        "total_events": 0,
    }
    intents = baseline.get("intent_counts") or {}
    severities = baseline.get("severity_counts") or {}
    intents[intent_category] = intents.get(intent_category, 0) + 1
    severities[severity] = severities.get(severity, 0) + 1
    baseline["intent_counts"] = intents
    baseline["severity_counts"] = severities
    baseline["total_events"] = int(baseline.get("total_events", 0)) + 1
    baseline["last_seen"] = datetime.now(timezone.utc).isoformat()
    save_agent_baseline(baseline)


def compute_behavioral_deviation(agent_id: str, current_intent: str, current_severity: str) -> dict[str, Any]:
    """
    FR-2.2: Detect drift from established baseline (possible compromise).
    """
    baseline = get_agent_baseline(agent_id)
    if not baseline or int(baseline.get("total_events", 0)) < 5:
        return {
            "behavioral_anomaly": False,
            "deviation_score": 0.0,
            "reason": "insufficient_baseline",
            "baseline_events": int(baseline.get("total_events", 0)) if baseline else 0,
        }

    intents = baseline.get("intent_counts") or {}
    total = sum(intents.values()) or 1
    dominant_intent = max(intents, key=intents.get)
    dominant_ratio = intents.get(dominant_intent, 0) / total

    severity_counts = baseline.get("severity_counts") or {}
    high_ratio = (
        severity_counts.get("HIGH", 0) + severity_counts.get("CRITICAL", 0)
    ) / (sum(severity_counts.values()) or 1)

    anomaly = False
    reasons = []

    if current_intent != dominant_intent and dominant_ratio > 0.6:
        anomaly = True
        reasons.append(f"intent drift: usual {dominant_intent}, now {current_intent}")

    if current_severity in ("HIGH", "CRITICAL") and high_ratio < 0.1:
        anomaly = True
        reasons.append("severity spike vs historical baseline")

    threat_intents = {
        "CREDENTIAL_EXFILTRATION",
        "PROMPT_INJECTION",
        "DATA_EXFILTRATION",
        "PII_LEAK",
    }
    if current_intent in threat_intents and intents.get(current_intent, 0) == 0:
        anomaly = True
        reasons.append(f"first occurrence of {current_intent}")

    deviation_score = min(1.0, 0.3 * len(reasons) + (0.4 if anomaly else 0.0))

    return {
        "behavioral_anomaly": anomaly,
        "deviation_score": round(deviation_score, 2),
        "reasons": reasons,
        "dominant_intent": dominant_intent,
        "baseline_events": int(baseline.get("total_events", 0)),
    }
