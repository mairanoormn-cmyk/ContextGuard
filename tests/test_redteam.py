import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from database import init_db

@pytest.fixture(scope="module", autouse=True)
def _init_test_db():
    init_db()

from redteam import ATTACK_SCENARIOS, _classify_result, run_lobstertrap_builtin_tests

def test_attack_scenarios_count():
    assert len(ATTACK_SCENARIOS) >= 3
    ids = {s["id"] for s in ATTACK_SCENARIOS}
    assert "sc-01-credential-exfil" in ids
    assert "sc-03-env-enumeration" in ids

def test_redteam_classify_blocked():
    scenario = ATTACK_SCENARIOS[0]
    result = {"blocked": True, "action": "DENY", "rule": "prompt_injection"}
    assert _classify_result(scenario, result) == "blocked"

def test_lobstertrap_test_runner_returns_dict():
    r = run_lobstertrap_builtin_tests()
    assert "status" in r
