import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from env_guardian import classify_env_var, extract_env_vars_from_prompt, get_remediation_workflow, days_since_rotation

def test_env_var_sensitive_classification():
    r = classify_env_var("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
    assert r["classification"] in ("SENSITIVE", "MISCLASSIFIED")

def test_env_var_non_sensitive_name():
    r = classify_env_var("APP_PORT", "3000")
    assert r["classification"] == "NON-SENSITIVE"

def test_extract_env_from_prompt():
    names = extract_env_vars_from_prompt("Read STRIPE_SECRET_KEY from process.env")
    assert any("STRIPE" in n for n in names)

def test_remediation_playbooks_cover_services():
    for svc in ("aws", "gcp", "github", "stripe", "twilio"):
        pb = get_remediation_workflow(f"{svc.upper()}_API_KEY")
        assert pb["inferred_service"] == svc
        assert len(pb["steps"]) >= 3

def test_remediation_playbook_count():
    assert len([k for k in get_remediation_workflow("AWS_KEY").keys()]) >= 4

def test_days_since_rotation_never():
    assert days_since_rotation(None)["status"] == "never_rotated"
