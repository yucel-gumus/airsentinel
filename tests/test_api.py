"""Tests for FastAPI endpoints."""
import pytest
from fastapi.testclient import TestClient
from airsentinel.config import settings
from airsentinel.web.app import app

@pytest.fixture(autouse=True)
def disable_hardware_scanners():
    settings.enable_ble_scanner = False
    settings.enable_wifi_scanner = False
    yield

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_api_status(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ONLINE"
    assert "catalog_version" in data
    assert data["rules_count"] > 5000

def test_api_devices(client):
    res = client.get("/api/devices")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_alerts(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_drones(client):
    res = client.get("/api/drones")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_intel_debrief(client):
    res = client.get("/api/intel/debrief")
    assert res.status_code == 200
    data = res.json()
    assert "debrief_markdown" in data
    assert "AIRSENTINEL" in data["debrief_markdown"]

def test_api_export_wigle(client):
    res = client.get("/api/export/wigle")
    assert res.status_code == 200
    assert "WigleWifi" in res.text

def test_api_export_gpx(client):
    res = client.get("/api/export/gpx")
    assert res.status_code == 200
    assert "<gpx" in res.text
