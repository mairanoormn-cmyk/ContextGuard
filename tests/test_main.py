import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from main import app

client = TestClient(app)

def test_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert "workspace" in data
    assert "proxy" in data

def test_modules_status_endpoint():
    response = client.get("/api/modules/status")
    assert response.status_code == 200
