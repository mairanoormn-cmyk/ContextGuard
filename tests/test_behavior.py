import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from behavior import compute_behavioral_deviation

def test_behavioral_deviation_insufficient_data():
    r = compute_behavioral_deviation("new_agent", "LEGITIMATE", "LOW")
    assert r["behavioral_anomaly"] is False
