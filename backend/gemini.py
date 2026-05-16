"""
ContextGuard — M2 AI Threat Scoring Engine
SRS §4.2: Gemini 2.5 Pro/Flash risk scoring, threat intel, intent classification.

Supports google-generativeai (native) with AIMLAPI fallback.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("contextguard.gemini")

API_KEY = os.getenv("GEMINI_API_KEY", "")
AIMLAPI_URL = "https://api.aimlapi.com/v1/chat/completions"
MODEL_FLASH = os.getenv("GEMINI_FLASH_MODEL", "gemini-2.5-flash")
MODEL_PRO = os.getenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
AIML_MODEL_FLASH = os.getenv("AIML_FLASH_MODEL", "google/gemini-2.0-flash")
AIML_MODEL_PRO = os.getenv("AIML_PRO_MODEL", "google/gemini-2.0-flash")
USE_NATIVE = os.getenv("GEMINI_USE_NATIVE", "true").lower() in ("1", "true", "yes")

_native_configured = False

# High-risk OAuth scope keywords (permission blast radius)
HIGH_RISK_SCOPE_KEYWORDS = (
    "admin", "directory", "drive", "gmail", "mail", "calendar",
    "contacts", "documents", "spreadsheets", "full", "all",
    "https://www.googleapis.com/auth/",
)
SENSITIVE_SCOPE_KEYWORDS = ("delete", "write", "manage", "security", "tokens")


def category_from_score(score: int) -> str:
    """FR-2.6 risk categories."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _configure_native() -> bool:
    global _native_configured
    if not USE_NATIVE or not API_KEY:
        return False
    try:
        import google.generativeai as genai

        genai.configure(api_key=API_KEY)
        _native_configured = True
        return True
    except Exception as e:
        logger.warning("Native Gemini unavailable: %s", e)
        return False


def call_gemini_with_retry(
    prompt: str,
    *,
    use_pro: bool = False,
    max_retries: int = 3,
) -> str:
    """SRS: retry with exponential backoff."""
    if _configure_native():
        try:
            import google.generativeai as genai

            model_name = MODEL_PRO if use_pro else MODEL_FLASH
            model = genai.GenerativeModel(model_name)
            for attempt in range(max_retries):
                try:
                    response = model.generate_content(
                        prompt,
                        generation_config={"temperature": 0.1, "max_output_tokens": 2048},
                    )
                    return (response.text or "").strip()
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.warning("Native Gemini failed, falling back to AIMLAPI: %s", e)
                    else:
                        time.sleep(2**attempt)
        except Exception as e:
            logger.warning("Native call error: %s", e)

    return _call_aimlapi(prompt, use_pro=use_pro, max_retries=max_retries)


def _call_aimlapi(prompt: str, *, use_pro: bool, max_retries: int) -> str:
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": AIML_MODEL_PRO if use_pro else AIML_MODEL_FLASH,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 2048,
    }
    response = None
    for attempt in range(max_retries):
        try:
            response = requests.post(AIMLAPI_URL, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            if attempt == max_retries - 1:
                body = response.text if response is not None else "no body"
                raise RuntimeError(f"Gemini API failed after {max_retries} attempts: {e} — {body}") from e
            time.sleep(2**attempt)
    return ""


def _parse_json_response(text: str) -> dict:
    cleaned = (text or "").strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    return json.loads(cleaned.strip())


def compute_scope_blast_radius(scopes: list) -> dict[str, Any]:
    """FR-2.2: Permission blast radius heuristic."""
    if not scopes:
        return {"blast_radius_score": 10, "high_risk_scopes": [], "scope_count": 0}

    scope_text = " ".join(str(s).lower() for s in scopes)
    high_risk = [s for s in scopes if any(k in str(s).lower() for k in HIGH_RISK_SCOPE_KEYWORDS)]
    sensitive = [s for s in scopes if any(k in str(s).lower() for k in SENSITIVE_SCOPE_KEYWORDS)]

    score = min(100, 15 * len(scopes) + 25 * len(high_risk) + 15 * len(sensitive))
    return {
        "blast_radius_score": score,
        "high_risk_scopes": high_risk[:10],
        "sensitive_scopes": sensitive[:10],
        "scope_count": len(scopes),
    }


def call_gemini_with_search(prompt: str, *, use_pro: bool = False) -> str:
    """
    FR-2.3 / FR-1.3: Threat intel with Google Search grounding when available.
    Falls back to enhanced prompt + standard Gemini call.
    """
    if _configure_native():
        try:
            import google.generativeai as genai

            model_name = MODEL_PRO if use_pro else MODEL_FLASH
            try:
                model = genai.GenerativeModel(
                    model_name,
                    tools=[{"google_search_retrieval": {}}],
                )
                response = model.generate_content(
                    prompt,
                    generation_config={"temperature": 0.1, "max_output_tokens": 2048},
                )
                return (response.text or "").strip()
            except Exception:
                model = genai.GenerativeModel(model_name)
                response = model.generate_content(
                    prompt + "\n\nUse current public security bulletins and vendor trust data (2025-2026).",
                    generation_config={"temperature": 0.1, "max_output_tokens": 2048},
                )
                return (response.text or "").strip()
        except Exception as e:
            logger.warning("Search-grounded Gemini failed: %s", e)

    return call_gemini_with_retry(
        prompt + "\n\nIncorporate latest public security bulletin knowledge (2025-2026).",
        use_pro=use_pro,
    )


def lookup_vendor_threat_intel(name: str, publisher: str) -> dict[str, Any]:
    """
    FR-2.3: Gemini web-search threat intelligence for vendor reputation and breaches.
    """
    prompt = f"""You are a cybersecurity threat intelligence analyst with web search access.
Research the third-party SaaS vendor below using public security bulletins and news.
Do NOT invent specific breach dates unless widely known; prefer "unknown" when uncertain.

Vendor/App: {name}
Publisher: {publisher}

Return ONLY JSON:
{{
  "vendor_reputation": "<TRUSTED|NEUTRAL|SUSPICIOUS|UNKNOWN>",
  "soc2_compliance": "<YES|NO|UNKNOWN>",
  "known_breach_history": "<none|minor|major|unknown>",
  "recent_incidents_summary": "<1 sentence citing public source if known>",
  "data_residency": "<US|EU|GLOBAL|UNKNOWN>",
  "threat_intel_confidence": <0.0-1.0>,
  "sources_consulted": "<brief note on intel sources>"
}}"""
    try:
        raw = call_gemini_with_search(prompt, use_pro=False)
        return _parse_json_response(raw)
    except Exception as e:
        logger.warning("Threat intel lookup failed for %s: %s", name, e)
        return {
            "vendor_reputation": "UNKNOWN",
            "soc2_compliance": "UNKNOWN",
            "known_breach_history": "unknown",
            "recent_incidents_summary": "Threat intel unavailable",
            "data_residency": "UNKNOWN",
            "threat_intel_confidence": 0.0,
        }


def classify_prompt_intent(event: dict) -> dict[str, Any]:
    """
    FR-4.4 / M4: Classify prompt intent with confidence (Flash — latency-sensitive).
    """
    metadata = event.get("metadata") or {}
    prompt = CLASSIFY_PROMPT.format(
        event=json.dumps(
            {
                "policy": event.get("policy_triggered"),
                "action": event.get("action_taken"),
                "metadata": metadata,
                "declared_intent": metadata.get("declared_intent"),
            },
            default=str,
        )
    )
    try:
        raw = call_gemini_with_retry(prompt, use_pro=False)
        result = _parse_json_response(raw)
        result["intent_category"] = result.get("intent_category", "UNKNOWN")
        result["confidence"] = float(result.get("confidence", 0.75))
        return result
    except Exception as e:
        logger.error("Intent classification failed: %s", e)
        proxy_intent = metadata.get("intent_category") or metadata.get("proxy_detected_intent")
        return {
            "intent_category": proxy_intent or "UNKNOWN",
            "confidence": float(metadata.get("intent_confidence") or metadata.get("proxy_intent_confidence") or 0.5),
            "severity": "MEDIUM",
            "alert_message": f"DPI policy {event.get('policy_triggered')} triggered.",
        }


def classify_event(event: dict) -> dict[str, Any]:
    """Backward-compatible wrapper for webhook pipeline."""
    result = classify_prompt_intent(event)
    return {
        "intent_category": result.get("intent_category", "UNKNOWN"),
        "severity": result.get("severity", "MEDIUM"),
        "alert_message": result.get("alert_message", ""),
        "confidence": result.get("confidence", 0.5),
    }


def score_oauth_app(
    name: str,
    publisher: str,
    scopes: list,
    *,
    user_count: int = 0,
    is_ioc: bool = False,
    prior_score: int | None = None,
    behavioral_deviation: dict | None = None,
    permission_changed: bool = False,
) -> dict[str, Any]:
    """
    FR-2.1–2.6: Dynamic risk score with blast radius, threat intel, compliance factors.
    """
    blast = compute_scope_blast_radius(scopes)
    intel = lookup_vendor_threat_intel(name, publisher)
    behavior = behavioral_deviation or {}
    behavior_note = (
        f"ANOMALY: {behavior.get('reasons', [])} (score {behavior.get('deviation_score', 0)})"
        if behavior.get("behavioral_anomaly")
        else "normal"
    )

    prompt = f"""You are an enterprise security analyst scoring third-party AI OAuth applications.

App Name: {name}
Publisher: {publisher}
Permission Scopes: {json.dumps(scopes)}
Authorized Users: {user_count}
IOC Match (known compromised): {is_ioc}
Permissions changed since last scan: {permission_changed}

Pre-computed factors (incorporate into your score):
- Permission blast radius score: {blast['blast_radius_score']}/100
- High-risk scopes: {json.dumps(blast.get('high_risk_scopes', []))}
- Vendor reputation: {intel.get('vendor_reputation')}
- SOC2 compliance: {intel.get('soc2_compliance')}
- Known breach history: {intel.get('known_breach_history')}
- Data residency: {intel.get('data_residency')}
- Threat intel summary: {intel.get('recent_incidents_summary')}
- Behavioral deviation: {behavior_note}
- Prior risk score: {prior_score if prior_score is not None else 'none'}

Consider: permission blast radius, vendor SOC2/compliance, breach history, behavioral deviation, user exposure, data residency.
If IOC Match is true, minimum risk_score is 95 and risk_category CRITICAL.

Return ONLY JSON:
{{
  "risk_score": <integer 0-100>,
  "risk_category": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "explanation": "<2 sentences plain English for executives>",
  "contributing_factors": {{
    "blast_radius": "<low|medium|high>",
    "vendor_trust": "<low|medium|high>",
    "compliance_posture": "<weak|adequate|strong|unknown>",
    "breach_history": "<none|concern|critical>",
    "user_exposure": "<low|medium|high>",
    "behavioral_risk": "<low|medium|high>"
  }}
}}"""

    try:
        raw = call_gemini_with_retry(prompt, use_pro=True)
        result = _parse_json_response(raw)
    except Exception as e:
        logger.error("OAuth scoring failed for %s: %s", name, e)
        base = 95 if is_ioc else min(100, blast["blast_radius_score"])
        result = {
            "risk_score": base,
            "risk_category": category_from_score(base),
            "explanation": f"Rule-based fallback score due to API error: {e}",
            "contributing_factors": {"blast_radius": "computed", "api_error": True},
        }

    score = int(result.get("risk_score", 0))
    if is_ioc:
        score = max(score, 95)

    result["risk_score"] = score
    result["risk_category"] = category_from_score(score)
    if behavior.get("behavioral_anomaly"):
        result["risk_score"] = min(100, int(result.get("risk_score", 0)) + 10)
        result["risk_category"] = category_from_score(int(result["risk_score"]))
    if permission_changed:
        result["risk_score"] = min(100, int(result.get("risk_score", 0)) + 8)

    result["threat_intel"] = intel
    result["blast_radius"] = blast
    result["behavioral_deviation"] = behavior
    return result


def classify_env_var_with_gemini(var_name: str, value_hint: str | None = None) -> dict[str, Any]:
    """FR-3.1: Gemini classification of environment variable sensitivity."""
    prompt = f"""Classify this environment variable for enterprise security.
Variable name: {var_name}
Value pattern hint (may be empty, never store real secrets): {value_hint or '[not provided]'}

Return ONLY JSON:
{{
  "classification": "<SENSITIVE|NON-SENSITIVE|MISCLASSIFIED>",
  "credential_in_value": <true|false>,
  "explanation": "<1 sentence>",
  "confidence": <0.0-1.0>
}}"""
    try:
        raw = call_gemini_with_retry(prompt, use_pro=False)
        return _parse_json_response(raw)
    except Exception as e:
        return {"classification": "UNKNOWN", "error": str(e), "confidence": 0.0}


def generate_report(events: list, critical_apps: list = None) -> str:
    """Compliance summary from DPI events and critical OAuth apps."""
    if critical_apps is None:
        critical_apps = []
        
    if not events and not critical_apps:
        return "No security events or critical OAuth apps recorded in the last 24 hours. The environment is currently secure."

    prompt = REPORT_PROMPT.format(
        events=json.dumps(events, indent=2, default=str),
        apps=json.dumps(critical_apps, indent=2, default=str)
    )
    try:
        return call_gemini_with_retry(prompt, use_pro=True).strip()
    except Exception as e:
        return f"Error generating compliance report: {e}"



CLASSIFY_PROMPT = """
You are a security analyst reviewing AI agent traffic flagged by a DPI proxy.

Event: {event}

Return ONLY JSON:
{{
  "intent_category": "<CREDENTIAL_EXFILTRATION|PROMPT_INJECTION|PII_LEAK|DATA_EXFILTRATION|LEGITIMATE|UNKNOWN>",
  "confidence": <0.0-1.0>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "alert_message": "<1 sentence alert for SOC dashboard>"
}}
"""

REPORT_PROMPT = """
You are a security compliance officer writing a daily summary report.

DPI Events (last 24h):
{events}

Critical/High Risk OAuth Apps Currently Monitored:
{apps}

Write a concise plain-text compliance summary (max 250 words) covering:
1. Total events and severity breakdown, plus high-risk OAuth apps discovered.
2. Significant threats (injection, credential exfiltration, intent mismatches, or dangerous OAuth permissions).
3. Automated actions taken (DENY, QUARANTINE, HUMAN_REVIEW) or OAuth apps that need revocation.
4. Recommended next steps for the security team.
"""
