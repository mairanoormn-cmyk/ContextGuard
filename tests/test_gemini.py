import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from gemini import category_from_score, compute_scope_blast_radius

def test_category_from_score_srs_mapping():
    assert category_from_score(10) == "LOW"
    assert category_from_score(45) == "MEDIUM"
    assert category_from_score(70) == "HIGH"
    assert category_from_score(90) == "CRITICAL"

def test_blast_radius_high_risk_scopes():
    scopes = [
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/drive",
    ]
    result = compute_scope_blast_radius(scopes)
    assert result["scope_count"] == 2
    assert result["blast_radius_score"] >= 40
    assert len(result["high_risk_scopes"]) >= 1
