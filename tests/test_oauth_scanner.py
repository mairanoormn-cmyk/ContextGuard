import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from oauth_scanner import detect_scope_drift, KNOWN_BREACH_IOC

def test_scope_drift_detection():
    drift = detect_scope_drift(
        ["read_email", "admin_sdk", "write_drive"],
        ["read_email"],
    )
    assert drift["scope_drift"] is True
    assert "admin_sdk" in drift["extra_scopes"]

def test_no_scope_drift():
    drift = detect_scope_drift(["read_email"], ["read_email", "read_drive"])
    assert drift["scope_drift"] is False

def test_ioc_constant():
    assert "googleusercontent.com" in KNOWN_BREACH_IOC
