import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from database import init_db

@pytest.fixture(scope="module", autouse=True)
def _init_test_db():
    init_db()

from incident_response import WORKFLOW_TEMPLATES, _workflow_key_for_event

def test_incident_workflow_key_env():
    event = {"metadata": {"env_alerts": [{"var_name": "X"}]}}
    assert _workflow_key_for_event(event) == "env_guardian_alert"

def test_incident_workflow_templates_exist():
    assert "credential_exfiltration" in WORKFLOW_TEMPLATES
    assert "oauth_ioc_match" in WORKFLOW_TEMPLATES
