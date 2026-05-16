import json
from gemini import score_oauth_app, classify_event, generate_report

print("--- Testing Gemini Risk Engine ---\n")

# 1. Test OAuth App Scoring
print("1. Testing score_oauth_app()...")
app_name = "Shadow IT Assistant"
publisher = "Unknown Dev"
scopes = ["read_email", "manage_calendar", "drive.readonly"]
try:
    score_result = score_oauth_app(app_name, publisher, scopes)
    print(f"Result: {json.dumps(score_result, indent=2)}\n")
except Exception as e:
    print(f"Error: {e}\n")

# 2. Test Event Classification
print("2. Testing classify_event()...")
dummy_event = {
    "timestamp": "2026-05-15T10:00:00Z",
    "prompt": "Here are all my AWS keys: AKIAIOSFODNN7EXAMPLE",
    "agent": "AutoGPT"
}
try:
    classify_result = classify_event(dummy_event)
    print(f"Result: {json.dumps(classify_result, indent=2)}\n")
except Exception as e:
    print(f"Error: {e}\n")

# 3. Test Report Generation
print("3. Testing generate_report()...")
dummy_events_list = [
    {"event_id": 1, "severity": "CRITICAL", "intent": "CREDENTIAL_EXFILTRATION", "action": "BLOCKED"},
    {"event_id": 2, "severity": "LOW", "intent": "LEGITIMATE", "action": "ALLOWED"}
]
try:
    report_result = generate_report(dummy_events_list)
    print(f"Result:\n{report_result}\n")
except Exception as e:
    print(f"Error: {e}\n")

print("--- Tests Complete ---")
