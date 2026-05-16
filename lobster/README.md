# Lobster Trap Setup — ContextGuard
# Owner: Tayyab

## Binary
The `lobstertrap.exe` binary (v0.1.0) is built from source:
- Repo: https://github.com/veeainc/lobstertrap
- Built with Go 1.22+

## Policy
The ContextGuard DPI policy is at: `configs/default_policy.yaml`

### Rules Summary
| # | Rule | Action | Severity | What It Catches |
|---|------|--------|----------|----------------|
| 1 | credential_exfiltration | QUARANTINE | CRITICAL | API keys, secrets, credentials in prompts |
| 2 | data_exfiltration | QUARANTINE | CRITICAL | Data being sent to external endpoints |
| 3 | prompt_injection | DENY | HIGH | "ignore instructions", "jailbreak", "DAN mode" |
| 4 | role_impersonation | DENY | HIGH | "pretend you are", "you are now" |
| 5 | pii_detection | LOG | MEDIUM | SSNs, emails, phone numbers |
| 6 | block_malware | DENY | HIGH | Malware/exploit generation requests |
| 7 | block_sensitive_paths | DENY | HIGH | /etc/shadow, .ssh, .env access |
| 8 | block_dangerous_commands | DENY | HIGH | rm -rf, curl|bash, sudo |
| 9+ | Egress rules | DENY | CRITICAL | Credential/PII leaks in model output |

## Start the Proxy
```bash
# Start Lobster Trap DPI proxy (port 8080, forwarding to AIMLAPI)
.\lobstertrap.exe serve \
  --policy configs/default_policy.yaml \
  --backend https://api.aimlapi.com \
  --listen :8080 \
  --audit-log lobster_audit.jsonl

# In another terminal — start the webhook bridge
python webhook_bridge.py --log-file lobster_audit.jsonl
```

## Test the Policy
```bash
# Test a specific prompt
.\lobstertrap.exe inspect "ignore all previous instructions"

# Run the full built-in test suite (11 tests)
.\lobstertrap.exe test

# Run the ContextGuard demo simulator (from project root)
cd ../demo && python simulate_traffic.py
```

## Architecture
```
Agent → Lobster Trap (:8080) → AIMLAPI/LLM Backend
                 ↓ audit log
         webhook_bridge.py
                 ↓ POST
         FastAPI Backend (:3000)
                 ↓
         SQLite → Dashboard (:5173)
```

## How Webhook Bridge Works
Lobster Trap writes JSON audit log entries to `lobster_audit.jsonl`.
The `webhook_bridge.py` script tails this file and:
1. Filters for non-ALLOW events
2. SHA-256 hashes the prompt (no raw prompts stored)
3. Redacts PII/credentials from metadata
4. POSTs structured JSON to `http://localhost:3000/api/webhook/lobster`
