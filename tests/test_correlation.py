"""Tests for Correlation, Flood Detection, and Stalking Tracker Detection."""
import time
import pytest
from airsentinel.config import settings
from airsentinel.correlation.flood_detector import FloodDetector
from airsentinel.correlation.tracker_detector import TrackerDetector
from airsentinel.models import DeviceClass, MatchedSignature, Observation, RadioType, ThreatCategory

def test_flood_detector_ble_spam():
    detector = FloodDetector()
    alert = None

    # Simulate 10 rapid pairing advertisements within 1 second
    for i in range(10):
        obs = Observation(
            radio=RadioType.BLE,
            mac_or_uuid=f"F0:00:00:00:00:{i:02X}",
            rssi=-45,
            company_id=0x004C,
            manufacturer_data_hex="07130102030405",
            is_randomized_mac=True,
        )
        res = detector.process_observation(obs)
        if res:
            alert = res
            break

    assert alert is not None
    assert alert.category == ThreatCategory.BLE_PAIRING_FLOOD
    assert "Bluetooth Pairing Flood" in alert.title

def test_tracker_detector_persistent_cotravel():
    detector = TrackerDetector()
    mac = "4A:7C:1E:88:99:AA"
    
    # Simulate sightings of an AirTag over time
    now = time.time()
    # Inject 5 historical sightings starting 12 minutes ago
    detector._sighting_history[mac] = [
        (now - 720, -60),
        (now - 500, -62),
        (now - 300, -58),
        (now - 120, -59),
    ]

    obs = Observation(
        radio=RadioType.BLE,
        mac_or_uuid=mac,
        name="Apple AirTag",
        rssi=-59,
        matched_signature=MatchedSignature(
            fleet_id="fleet-airtag",
            fleet_name="Apple AirTag (Find My)",
            device_class=DeviceClass.TRACKER,
            matched_rule="Apple Find My",
        ),
    )

    alert = detector.process_observation(obs)
    assert alert is not None
    assert alert.category == ThreatCategory.STALKING_CO_TRAVEL
    assert "Persistent Tracker" in alert.title
