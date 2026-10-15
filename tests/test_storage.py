"""Tests for SQLite database persistence."""
import pytest
from pathlib import Path
from airsentinel.models import Alert, AlertLevel, Observation, RadioType, ThreatCategory
from airsentinel.storage.db import Database

@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_airsentinel.db"
    return Database(db_path=db_file)

def test_db_upsert_and_retrieve(temp_db):
    obs = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="AA:BB:CC:11:22:33",
        name="Target_Network_5G",
        rssi=-55,
        channel_or_freq="36 (5GHz)",
    )
    tracked = temp_db.upsert_observation(obs)
    assert tracked.mac_or_uuid == "AA:BB:CC:11:22:33"
    assert tracked.hit_count == 1
    assert tracked.avg_rssi == -55.0

    # Second hit with different RSSI
    obs2 = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="AA:BB:CC:11:22:33",
        name="Target_Network_5G",
        rssi=-65,
    )
    tracked2 = temp_db.upsert_observation(obs2)
    assert tracked2.hit_count == 2
    assert tracked2.avg_rssi == -60.0

    # Fetch list
    devices = temp_db.get_devices()
    assert len(devices) == 1
    assert devices[0].name == "Target_Network_5G"

def test_db_insert_alert(temp_db):
    alert = Alert(
        level=AlertLevel.HIGH,
        category=ThreatCategory.BLE_PAIRING_FLOOD,
        title="Test Flood",
        description="Test burst detected",
        device_id="FF:EE:DD:00:11:22",
        rssi=-42,
    )
    alert_id = temp_db.insert_alert(alert)
    assert alert_id is not None
    assert alert_id > 0

    alerts = temp_db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].title == "Test Flood"

    stats = temp_db.get_stats()
    assert stats["alerts_count"] == 1
