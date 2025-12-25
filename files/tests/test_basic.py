# Basic pytest tests for registration, login, and upload using TestClient.

import os
import json
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import database, models
import asyncio

# Ensure SECRET_KEY is set for tests
os.environ.setdefault("SECRET_KEY", "test_secret_for_ci")

client = TestClient(app)


def test_register_and_login_and_upload():
    # Register
    resp = client.post("/auth/register", json={"email": "tester@example.com", "password": "password"})
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data

    # Login
    resp = client.post("/auth/login", json={"email": "tester@example.com", "password": "password"})
    assert resp.status_code == 200
    token_data = resp.json()
    assert "access_token" in token_data
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Upload sample log
    sample_path = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "sample.log")
    with open(sample_path, "rb") as f:
        files = {"file": ("sample.log", f, "text/plain")}
        resp = client.post("/logs/upload", headers=headers, files=files)
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert "analysis_id" in result
    assert result["total_lines"] > 0
    assert isinstance(result["top_threats"], dict)

    # Retrieve analysis
    aid = result["analysis_id"]
    resp = client.get(f"/logs/{aid}", headers=headers)
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["id"] == aid
    assert detail["user_id"] == data["id"]