"""
ContextGuard — M4 Lobster Trap DPI Processing
SRS §4.4 FR-4.2, FR-4.4: structured metadata + intent mismatch detection.
"""

from __future__ import annotations

import re
from typing import Any

# SRS intent-mismatch policy: >40% confidence delta
INTENT_MISMATCH_THRESHOLD = 0.40

INTENT_ALIASES = {
    "LEGITIMATE": {"legitimate", "general", "chat", "question", "code_execution", "help"},
    "CREDENTIAL_EXFILTRATION": {"credential_exfiltration", "credential", "secret", "exfiltration"},
    "PROMPT_INJECTION": {"prompt_injection", "injection", "jailbreak"},
    "PII_LEAK": {"pii_leak", "pii", "privacy"},
    "DATA_EXFILTRATION": {"data_exfiltration", "exfiltration", "data_export"},
}

DPI_METADATA_FIELDS = (
    "intent_category",
    "intent_confidence",
    "risk_score",
    "contains_credentials",
    "contains_pii",
    "contains_pii_request",
    "contains_injection_patterns",
    "contains_exfiltration",
    "contains_sensitive_paths",
    "contains_role_impersonation",
    "contains_malware_request",
    "contains_system_commands",
    "contains_obfuscation",
    "target_domains",
    "target_paths",
    "direction",
    "request_id",
    "token_count",
)


def normalize_intent(intent: str | None) -> str:
    """Map varied intent labels to canonical SRS categories."""
    if not intent:
        return "UNKNOWN"
    raw = intent.strip().upper().replace("-", "_").replace(" ", "_")
    for canonical, aliases in INTENT_ALIASES.items():
        if raw == canonical or raw in aliases:
            return canonical
        if any(a in raw.lower() for a in aliases):
            return canonical
    return raw


def extract_declared_intent(metadata: dict, entry_mismatches: list | None = None) -> str | None:
    """
    FR-4.4: Read agent-declared intent from Lobster Trap headers / audit fields.
    Header: X-Lobstertrap-Intent (also exposed as declared_headers in audit log).
    """
    if not metadata:
        metadata = {}

    for key in ("declared_intent", "x_lobstertrap_intent", "X-Lobstertrap-Intent"):
        if metadata.get(key):
            return str(metadata[key])

    declared_headers = metadata.get("declared_headers")
    if isinstance(declared_headers, dict):
        for hk in ("intent", "X-Lobstertrap-Intent", "x-lobstertrap-intent"):
            if declared_headers.get(hk):
                return str(declared_headers[hk])

    if entry_mismatches and isinstance(entry_mismatches, list):
        for m in entry_mismatches:
            if isinstance(m, dict) and m.get("field") == "intent":
                return m.get("declared")

    return None


def extract_egress_metadata(raw_metadata: dict) -> dict:
    """FR-4.2: Response-side metadata (credential/PII leaks in model output)."""
    meta = raw_metadata or {}
    return {
        "egress_has_credentials": bool(meta.get("contains_credentials")),
        "egress_has_pii": bool(meta.get("contains_pii")),
        "egress_blocked": meta.get("direction") == "egress" and meta.get("action_taken") == "DENY",
    }


def get_supported_backends() -> list[dict]:
    """FR-4.5: OpenAI-compatible backends without proxy reconfiguration."""
    return [
        {"id": "openai", "base_url": "https://api.openai.com/v1", "path": "/chat/completions"},
        {"id": "anthropic", "base_url": "https://api.anthropic.com", "path": "/v1/messages", "note": "via compatibility layer"},
        {"id": "gemini", "base_url": "https://generativelanguage.googleapis.com", "path": "/v1beta"},
        {"id": "ollama", "base_url": "http://localhost:11434", "path": "/v1/chat/completions"},
        {"id": "vllm", "base_url": "http://localhost:8000", "path": "/v1/chat/completions"},
        {"id": "llama_cpp", "base_url": "http://localhost:8081", "path": "/v1/chat/completions"},
    ]


def extract_structured_metadata(raw_metadata: dict, policy: str, action: str) -> dict:
    """
    FR-4.2: Normalize DPI fields for storage and dashboard drill-down.
    """
    meta = dict(raw_metadata or {})
    structured = {field: meta.get(field) for field in DPI_METADATA_FIELDS if field in meta}

    structured["policy_triggered"] = policy
    structured["action_taken"] = action
    structured["has_credentials"] = bool(
        meta.get("contains_credentials") or meta.get("contains_exfiltration")
    )
    structured["has_pii"] = bool(meta.get("contains_pii") or meta.get("contains_pii_request"))
    structured["has_injection"] = bool(
        meta.get("contains_injection_patterns") or meta.get("contains_role_impersonation")
    )
    structured["target_domains"] = meta.get("target_domains") or []
    structured["injection_indicators"] = _injection_indicators(meta)
    structured["credential_patterns"] = _credential_flags(meta)
    structured["declared_intent"] = extract_declared_intent(meta, meta.get("mismatches"))

    proxy_intent = meta.get("intent_category")
    if proxy_intent:
        structured["proxy_detected_intent"] = normalize_intent(str(proxy_intent))
        structured["proxy_intent_confidence"] = float(meta.get("intent_confidence") or 0.0)

    structured.update(extract_egress_metadata(meta))
    structured["risk_score"] = meta.get("risk_score")
    return structured


def _injection_indicators(meta: dict) -> list[str]:
    flags = []
    if meta.get("contains_injection_patterns"):
        flags.append("injection_patterns")
    if meta.get("contains_role_impersonation"):
        flags.append("role_impersonation")
    if meta.get("contains_obfuscation"):
        flags.append("obfuscation")
    return flags


def _credential_flags(meta: dict) -> list[str]:
    flags = []
    if meta.get("contains_credentials"):
        flags.append("credentials_in_content")
    if meta.get("contains_exfiltration"):
        flags.append("exfiltration_pattern")
    if meta.get("contains_sensitive_paths"):
        flags.append("sensitive_path_access")
    return flags


def check_intent_mismatch(
    declared_intent: str | None,
    detected_intent: str | None,
    detected_confidence: float,
    proxy_intent: str | None = None,
    proxy_confidence: float = 0.0,
) -> dict[str, Any]:
    """
    FR-4.4: Compare declared vs Gemini-classified intent.
    Mismatch when categories differ AND confidence delta exceeds threshold.
    """
    declared_norm = normalize_intent(declared_intent)
    detected_norm = normalize_intent(detected_intent or proxy_intent)

    if not declared_intent or declared_norm == "UNKNOWN":
        return {
            "intent_mismatch": False,
            "confidence_delta": 0.0,
            "declared_intent": declared_intent,
            "detected_intent": detected_norm,
            "recommended_action": None,
        }

    if declared_norm == detected_norm:
        return {
            "intent_mismatch": False,
            "confidence_delta": 0.0,
            "declared_intent": declared_norm,
            "detected_intent": detected_norm,
            "recommended_action": None,
        }

    conf = max(float(detected_confidence or 0), float(proxy_confidence or 0), 0.5)
    # Category mismatch: treat detection confidence as delta vs undeclared truth
    confidence_delta = conf if declared_norm != detected_norm else abs(conf - proxy_confidence)
    mismatch = confidence_delta > INTENT_MISMATCH_THRESHOLD

    return {
        "intent_mismatch": mismatch,
        "confidence_delta": round(confidence_delta, 3),
        "declared_intent": declared_norm,
        "detected_intent": detected_norm,
        "recommended_action": "HUMAN_REVIEW" if mismatch else None,
    }


def apply_intent_mismatch_policy(
    policy_triggered: str,
    action_taken: str,
    severity: str,
    mismatch_result: dict,
) -> tuple[str, str, str]:
    """Elevate event when intent mismatch policy fires (SRS policy pack: LOG + HUMAN_REVIEW)."""
    if not mismatch_result.get("intent_mismatch"):
        return policy_triggered, action_taken, severity

    return (
        "intent_mismatch",
        "HUMAN_REVIEW",
        "HIGH" if severity in ("LOW", "MEDIUM", "UNKNOWN") else severity,
    )


def inspect_prompt_local(prompt: str) -> dict:
    """
    FR-4.7 lightweight inspect — regex/heuristic pre-check before Gemini.
    Full analysis via POST /api/dpi/inspect uses Gemini.
    """
    text = prompt or ""
    lower = text.lower()
    return {
        "contains_credentials": bool(
            re.search(r"(api[_-]?key|secret|bearer|akia[0-9a-z]{16}|sk-[a-z0-9]{20,})", lower)
        ),
        "contains_pii": bool(re.search(r"\b\d{3}-\d{2}-\d{4}\b", text))
        or bool(re.search(r"@[a-z0-9.-]+\.[a-z]{2,}", lower)),
        "contains_injection_patterns": bool(
            re.search(r"ignore (all |previous )?instructions|jailbreak|dan mode", lower)
        ),
        "contains_exfiltration": bool(re.search(r"pastebin|webhook|exfil|evil-", lower)),
        "contains_sensitive_paths": bool(re.search(r"\.env|/etc/shadow|\.ssh", lower)),
    }
