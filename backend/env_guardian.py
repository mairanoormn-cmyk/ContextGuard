"""
ContextGuard — M3 Environment Variable Guardian (100% SRS §4.3).
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("contextguard.env")

SENSITIVE_NAME_PATTERNS = [
    re.compile(r"(api[_-]?key|secret|token|password|passwd|credential|private[_-]?key)", re.I),
    re.compile(r"(jwt|oauth|client[_-]?secret|signing[_-]?key|encryption[_-]?key)", re.I),
    re.compile(r"(db[_-]?pass|database[_-]?url|connection[_-]?string|redis[_-]?url)", re.I),
    re.compile(r"^(aws|gcp|azure|stripe|twilio|github|gitlab)[_-]", re.I),
]

SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"^sk[_-](live|test)[_-]", re.I),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^ghp_[a-zA-Z0-9]{20,}$"),
    re.compile(r"^xox[baprs]-[a-zA-Z0-9-]+$"),
    re.compile(r"^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$"),
    re.compile(r"postgres(ql)?://[^:]+:[^@]+@", re.I),
]

ENV_ACCESS_PROMPT_PATTERNS = [
    re.compile(r"(?:read|cat|dump|print|export|getenv|os\.environ).*\.env", re.I),
    re.compile(r"/etc/(?:shadow|passwd)", re.I),
    re.compile(r"\$\{?[A-Z][A-Z0-9_]{2,}\}?", re.I),
    re.compile(r"process\.env\.[A-Z][A-Z0-9_]+", re.I),
]

REMEDIATION_PLAYBOOKS: dict[str, dict] = {
    "aws": {"service": "AWS IAM", "steps": ["Deactivate compromised access key in IAM.", "Create new key pair.", "Update secrets manager.", "Audit CloudTrail for abuse."], "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
    "gcp": {"service": "Google Cloud", "steps": ["Delete compromised service account key.", "Create new JSON key.", "Update deployment secrets.", "Restart workloads."], "docs_url": "https://cloud.google.com/iam/docs/keys-create-delete"},
    "github": {"service": "GitHub", "steps": ["Revoke PAT or GitHub App credentials.", "Generate new fine-grained token.", "Update Actions secrets."], "docs_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"},
    "stripe": {"service": "Stripe", "steps": ["Roll secret key in Dashboard.", "Update webhook signing secret.", "Audit charges."], "docs_url": "https://stripe.com/docs/keys#roll-keys"},
    "twilio": {"service": "Twilio", "steps": ["Delete compromised API key.", "Create secondary key.", "Rotate Auth Token."], "docs_url": "https://www.twilio.com/docs/iam/api-keys"},
    "openai": {"service": "OpenAI", "steps": ["Revoke key at platform.openai.com.", "Deploy new key to agents."], "docs_url": "https://platform.openai.com/api-keys"},
    "cloud_deployment": {"service": "Cloud Platform", "steps": ["Remove exposed env vars.", "Regenerate integration tokens.", "Redeploy all environments."], "docs_url": ""},
    "slack": {"service": "Slack", "steps": ["Regenerate client secret.", "Rotate bot token.", "Reinstall app."], "docs_url": "https://api.slack.com/authentication/oauth-v2"},
    "azure": {"service": "Azure", "steps": ["Rotate client secret in Entra ID.", "Update Key Vault references.", "Invalidate sessions."], "docs_url": "https://learn.microsoft.com/en-us/azure/active-directory/develop"},
    "datadog": {"service": "Datadog", "steps": ["Revoke API key.", "Create new key with least privilege."], "docs_url": "https://docs.datadoghq.com/account_management/api-app-keys/"},
    "database": {"service": "Database", "steps": ["Rotate DB password.", "Update DATABASE_URL in vault.", "Restart connection pools."], "docs_url": ""},
    "jwt": {"service": "JWT / Signing", "steps": ["Generate new signing key pair.", "Deploy validators.", "Invalidate sessions."], "docs_url": ""},
    "generic": {"service": "Generic Secret", "steps": ["Identify all consumers.", "Generate new secret in vault.", "Revoke old credential.", "Monitor 72h."], "docs_url": ""},
}


def _rule_classify(var_name: str, value_hint: str | None) -> dict[str, Any]:
    name = (var_name or "").strip()
    classification = "NON-SENSITIVE"
    reasons = []
    for pat in SENSITIVE_NAME_PATTERNS:
        if pat.search(name):
            classification = "SENSITIVE"
            reasons.append(f"name:{pat.pattern[:24]}")
            break
    credential_in_value = False
    if value_hint:
        for pat in SENSITIVE_VALUE_PATTERNS:
            if pat.search(value_hint):
                credential_in_value = True
                reasons.append("value_pattern")
                break
    if credential_in_value and classification == "NON-SENSITIVE":
        classification = "MISCLASSIFIED"
    return {
        "var_name": name,
        "classification": classification,
        "credential_in_value": credential_in_value,
        "reasons": reasons,
        "value_hash": hashlib.sha256((value_hint or "").encode()).hexdigest()[:16] if value_hint else None,
    }


def classify_env_var(var_name: str, value_hint: str | None = None, use_gemini: bool = True) -> dict[str, Any]:
    """FR-3.1–3.2: Rule-based + Gemini classification."""
    rules = _rule_classify(var_name, value_hint)
    if not use_gemini:
        return rules

    from gemini import classify_env_var_with_gemini

    try:
        gemini = classify_env_var_with_gemini(var_name, value_hint)
        final_class = gemini.get("classification", rules["classification"])
        if rules["classification"] == "SENSITIVE":
            final_class = "SENSITIVE"
        if rules.get("credential_in_value") or gemini.get("credential_in_value"):
            if final_class == "NON-SENSITIVE":
                final_class = "MISCLASSIFIED"
        return {
            **rules,
            "classification": final_class,
            "gemini_explanation": gemini.get("explanation", ""),
            "confidence": float(gemini.get("confidence", 0.8)),
            "method": "rules+gemini",
        }
    except Exception as e:
        logger.warning("Gemini env classify failed: %s", e)
        rules["method"] = "rules_only"
        return rules


def days_since_rotation(last_rotated: str | None) -> dict[str, Any]:
    """FR-3.6: Time since last credential rotation."""
    if not last_rotated:
        return {"days": None, "status": "never_rotated", "display": "Never rotated"}
    try:
        rotated = datetime.fromisoformat(last_rotated.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - rotated
        days = delta.days
        status = "ok" if days < 90 else "overdue"
        return {"days": days, "status": status, "display": f"{days} days ago"}
    except Exception:
        return {"days": None, "status": "unknown", "display": "Unknown"}


def infer_service_from_var(var_name: str) -> str:
    lower = var_name.lower()
    for svc in REMEDIATION_PLAYBOOKS:
        if svc != "generic" and svc in lower:
            return svc
    if "jwt" in lower or "signing" in lower:
        return "jwt"
    if "database" in lower or "db_" in lower or "postgres" in lower:
        return "database"
    return "generic"


def get_remediation_workflow(var_name: str) -> dict:
    service = infer_service_from_var(var_name)
    playbook = REMEDIATION_PLAYBOOKS.get(service, REMEDIATION_PLAYBOOKS["generic"])
    return {"var_name": var_name, "inferred_service": service, **playbook}


def extract_env_vars_from_prompt(prompt: str) -> list[str]:
    found = set()
    for pat in ENV_ACCESS_PROMPT_PATTERNS:
        for m in pat.finditer(prompt or ""):
            found.add(m.group(0)[:64])
    for m in re.finditer(r"\b([A-Z][A-Z0-9_]{2,})\b", prompt or ""):
        name = m.group(1)
        if any(k in name for k in ("KEY", "SECRET", "TOKEN", "PASS", "URL", "CRED")):
            found.add(name)
    return sorted(found)


def analyze_dpi_for_env_access(prompt: str | None, metadata: dict) -> list[dict]:
    """FR-3.3–3.4: Env access via Lobster Trap — alert within seconds of event."""
    alerts = []
    meta = metadata or {}
    prompt_text = prompt or meta.get("redacted_prompt") or ""
    triggers = []
    if meta.get("contains_sensitive_paths") or ".env" in prompt_text.lower():
        triggers.append("sensitive_path")
    if meta.get("contains_credentials"):
        triggers.append("credential_pattern")

    var_names = extract_env_vars_from_prompt(prompt_text)
    if not var_names and triggers:
        var_names = ["ENV_FILE_ACCESS"]

    for var_name in var_names:
        classification = classify_env_var(var_name, use_gemini=True)
        is_misuse = (
            classification["classification"] in ("NON-SENSITIVE", "MISCLASSIFIED")
            and (classification.get("credential_in_value") or triggers)
        ) or triggers

        if is_misuse or classification["classification"] == "SENSITIVE":
            alerts.append({
                "var_name": var_name,
                "classification": classification["classification"],
                "severity": "CRITICAL" if is_misuse else "HIGH",
                "message": (
                    f"AI agent accessed '{var_name}' ({classification['classification']}). "
                    f"Triggers: {', '.join(triggers) or 'env reference'}."
                ),
                "triggers": triggers,
                "remediation": get_remediation_workflow(var_name),
                "alert_latency_target_seconds": 30,
            })
    return alerts
