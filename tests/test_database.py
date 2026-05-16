import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from database import init_db, get_apps, get_events, save_audit_log, get_audit_log

@pytest.fixture(scope="module", autouse=True)
def _init_test_db():
    init_db()

def test_database_initialization():
    apps = get_apps()
    assert isinstance(apps, list)

def test_audit_log_save_and_retrieve():
    save_audit_log("test_actor", "test_action", "test_resource", "test_outcome")
    logs = get_audit_log(limit=10)
    assert len(logs) > 0
    assert any(log["actor"] == "test_actor" for log in logs)
