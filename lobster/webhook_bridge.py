"""
ContextGuard — Lobster Trap Webhook Bridge
Owner: Tayyab

Tails the Lobster Trap audit log file and forwards flagged events
(non-ALLOW verdicts) as structured webhook POSTs to the FastAPI backend.

Usage:
    python webhook_bridge.py --log-file ./lobster_audit.jsonl

SRS Reference: F2 — Lobster Trap DPI Layer
    - Webhook: POST http://localhost:3000/api/webhook/lobster
    - Payload: { timestamp, policy_triggered, action_taken, prompt_hash, metadata }
"""

import json
import hashlib
import time
import sys
import os
import argparse
import re
import logging
from datetime import datetime, timezone

import requests

# ═══════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════

FASTAPI_WEBHOOK_URL = os.getenv(
    "WEBHOOK_URL", "http://localhost:3000/api/webhook/lobster"
)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.5"))  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds

# ═══════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WEBHOOK-BRIDGE] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("webhook_bridge")

# ═══════════════════════════════════════════
# PII / SENSITIVE DATA REDACTION
# ═══════════════════════════════════════════

PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN-REDACTED]"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "[EMAIL-REDACTED]"),
    (re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"), "[PHONE-REDACTED]"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "[CARD-REDACTED]"),
    (re.compile(r"(?:sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}"), "[API-KEY-REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS-KEY-REDACTED]"),
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.IGNORECASE), "[PASSWORD-REDACTED]"),
    (re.compile(r"(?:bearer|token)\s+[a-zA-Z0-9._\-]{20,}", re.IGNORECASE), "[TOKEN-REDACTED]"),
]


def redact_sensitive_data(text: str) -> str:
    """Redact PII and credentials from text before storing."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def hash_prompt(prompt_text: str) -> str:
    """SHA-256 hash of the prompt for audit without storing raw content."""
    if not prompt_text:
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════
# AUDIT LOG PARSER
# ═══════════════════════════════════════════


def parse_audit_entry(line: str) -> dict | None:
    """Parse a JSON line from the Lobster Trap audit log."""
    try:
        entry = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    # Only forward flagged events (non-ALLOW actions)
    action = entry.get("action", "").upper()
    if action == "ALLOW":
        return None

    return entry


def build_webhook_payload(entry: dict) -> dict:
    """
    Transform a Lobster Trap audit log entry into the structured
    webhook payload expected by the FastAPI backend.

    Actual Lobster Trap audit log format:
    {
        "timestamp": "...",
        "request_id": "req-N",
        "direction": "ingress|egress",
        "action": "DENY|QUARANTINE|LOG|...",
        "rule_name": "prompt_injection",
        "deny_message": "...",
        "metadata": { ...DPI fields... },
        "token_count": N,
        "declared_headers": null,
        "mismatches": null
    }
    """
    # Extract the rule/policy that triggered
    rule_name = entry.get("rule_name", entry.get("rule", entry.get("matched_rule", "unknown")))

    # Extract the action taken
    action = entry.get("action", "UNKNOWN").upper()

    # Build metadata from DPI inspection results
    # In Lobster Trap, the DPI fields are nested under "metadata"
    raw_metadata = entry.get("metadata", {})
    webhook_metadata = {}

    # Copy over DPI metadata fields
    dpi_fields = [
        "intent_category", "intent_confidence", "risk_score",
        "contains_code", "contains_credentials", "contains_pii",
        "contains_pii_request", "contains_system_commands",
        "contains_injection_patterns", "contains_exfiltration",
        "contains_sensitive_paths", "contains_role_impersonation",
        "contains_malware_request", "contains_obfuscation",
        "contains_harm_patterns", "contains_phishing_patterns",
        "target_domains", "target_paths", "target_commands",
    ]
    for field in dpi_fields:
        if field in raw_metadata:
            webhook_metadata[field] = raw_metadata[field]

    # FR-4.4: declared intent from agent headers / Lobster Trap audit
    declared_headers = entry.get("declared_headers")
    if declared_headers:
        webhook_metadata["declared_headers"] = declared_headers
        if isinstance(declared_headers, dict):
            for hk in ("intent", "X-Lobstertrap-Intent", "x-lobstertrap-intent"):
                if declared_headers.get(hk):
                    webhook_metadata["declared_intent"] = declared_headers[hk]
                    break

    mismatches = entry.get("mismatches")
    if mismatches:
        webhook_metadata["mismatches"] = mismatches

    # Include top-level fields
    webhook_metadata["token_count"] = entry.get("token_count", raw_metadata.get("token_count", 0))
    webhook_metadata["direction"] = entry.get("direction", "unknown")
    webhook_metadata["request_id"] = entry.get("request_id", "")

    # Include deny message if present
    deny_message = entry.get("deny_message", "")
    if deny_message:
        webhook_metadata["deny_message"] = redact_sensitive_data(deny_message)

    # Map action to severity
    severity_map = {
        "QUARANTINE": "CRITICAL",
        "DENY": "HIGH",
        "HUMAN_REVIEW": "MEDIUM",
        "LOG": "MEDIUM",
        "RATE_LIMIT": "LOW",
    }
    webhook_metadata["severity"] = severity_map.get(action, "UNKNOWN")

    # Generate prompt hash from metadata content (Lobster Trap doesn't log raw prompts)
    hash_content = json.dumps(raw_metadata, sort_keys=True)
    prompt_hash_value = hash_prompt(hash_content)

    payload = {
        "timestamp": entry.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "policy_triggered": rule_name,
        "action_taken": action,
        "prompt_hash": prompt_hash_value,
        "metadata": webhook_metadata,
    }

    return payload


# ═══════════════════════════════════════════
# WEBHOOK SENDER
# ═══════════════════════════════════════════


def send_webhook(payload: dict) -> bool:
    """POST the structured event to the FastAPI backend with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                FASTAPI_WEBHOOK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if response.status_code == 200:
                logger.info(
                    "Webhook sent: policy=%s action=%s hash=%s",
                    payload["policy_triggered"],
                    payload["action_taken"],
                    payload["prompt_hash"][:12] + "...",
                )
                return True
            else:
                logger.warning(
                    "Webhook returned %d: %s", response.status_code, response.text
                )
        except requests.exceptions.ConnectionError:
            logger.warning(
                "FastAPI backend unreachable (attempt %d/%d)", attempt + 1, MAX_RETRIES
            )
        except requests.exceptions.Timeout:
            logger.warning("Webhook timeout (attempt %d/%d)", attempt + 1, MAX_RETRIES)
        except Exception as e:
            logger.error("Webhook error: %s", e)

        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (attempt + 1))

    logger.error("Webhook delivery FAILED after %d attempts", MAX_RETRIES)
    return False


# ═══════════════════════════════════════════
# LOG FILE TAILER
# ═══════════════════════════════════════════


def tail_file(filepath: str):
    """
    Tail a file like `tail -f`, yielding new lines as they appear.
    Handles file rotation and missing files gracefully.
    """
    logger.info("Tailing audit log: %s", filepath)

    # Wait for file to exist
    while not os.path.exists(filepath):
        logger.info("Waiting for audit log file to appear: %s", filepath)
        time.sleep(2)

    with open(filepath, "r", encoding="utf-8") as f:
        # Seek to end of file (only process new entries)
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(POLL_INTERVAL)


def process_stdin():
    """Process audit log entries from stdin (piped mode)."""
    logger.info("Reading audit log from stdin")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        entry = parse_audit_entry(line)
        if entry is None:
            continue

        payload = build_webhook_payload(entry)
        send_webhook(payload)


def process_file(filepath: str):
    """Process audit log entries by tailing a file."""
    for line in tail_file(filepath):
        line = line.strip()
        if not line:
            continue

        entry = parse_audit_entry(line)
        if entry is None:
            continue

        payload = build_webhook_payload(entry)
        send_webhook(payload)


# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════


def main():
    global FASTAPI_WEBHOOK_URL

    parser = argparse.ArgumentParser(
        description="ContextGuard Webhook Bridge — Forwards Lobster Trap audit events to FastAPI"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to Lobster Trap audit log file (JSONL). If not specified, reads from stdin.",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        default=None,
        help="FastAPI webhook URL (default: http://localhost:3000/api/webhook/lobster)",
    )
    args = parser.parse_args()

    if args.webhook_url:
        FASTAPI_WEBHOOK_URL = args.webhook_url

    logger.info("ContextGuard Webhook Bridge starting")
    logger.info("Target: %s", FASTAPI_WEBHOOK_URL)

    try:
        if args.log_file:
            process_file(args.log_file)
        else:
            process_stdin()
    except KeyboardInterrupt:
        logger.info("Webhook bridge stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
