"""Tests for AirSentinel v4 Counter-Surveillance (TSCM), MITM Shield, SpyCam SoftAP, OUI Intel & Room Audit."""
import asyncio
import sys
from pathlib import Path
from fastapi.testclient import TestClient

import airsentinel.correlation.engine as eng_mod
from airsentinel.correlation.engine import CorrelationEngine
from airsentinel.models import DeviceClass, Observation, RadioType, ThreatCategory
from airsentinel.scanners.ble_scanner import BleScanner
from airsentinel.scanners.wifi_scanner import WifiScanner
from airsentinel.storage.db import Database
from airsentinel.web.app import app

app_mod = sys.modules["airsentinel.web.app"]


def test_onvif_ws_discovery_xml_parser_and_extended_camera_ports():
    sample_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
                       xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <SOAP-ENV:Body>
        <d:ProbeMatches>
          <d:ProbeMatch>
            <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
            <d:Scopes>onvif://www.onvif.org/name/IPC_Cam_4K onvif://www.onvif.org/hardware/IMX335</d:Scopes>
            <d:XAddrs>http://192.168.1.64:8000/onvif/device_service</d:XAddrs>
          </d:ProbeMatch>
        </d:ProbeMatches>
      </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
    """
    parsed = WifiScanner._parse_onvif_ws_discovery_response(sample_xml)
    assert parsed is not None
    assert "IPC_Cam_4K" in parsed
    assert "192.168.1.64:8000" in parsed


def test_spycam_softap_ssid_and_close_range_hidden_ssid_detection(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_spycam.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # 1. Known Spy Camera SoftAP SSID (e.g. V380 / LookCam / HDWiFiCamPro)
    spy_meta = WifiScanner._detect_spycam_or_hidden_ap(ssid="V380_884192", rssi=-49, ch_num=6, is_hidden=False)
    assert spy_meta["is_spycam_ap"] is True

    obs_spy = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="EC:3D:FD:11:22:33",
        name="V380_884192",
        rssi=-49,
        role_hint=spy_meta["role_hint"],
        decoded_fields=spy_meta["decoded_fields"],
    )
    dev_spy = asyncio.run(engine.process_observation(obs_spy))
    assert dev_spy.device_class == DeviceClass.SURVEILLANCE
    assert dev_spy.risk_score >= 80
    assert any(a.category == ThreatCategory.SURVEILLANCE_CAMERA for a in test_db.get_alerts())

    # 2. Hidden (nameless) 2.4GHz Wi-Fi AP inside the room (RSSI -46 dBm)
    hidden_meta = WifiScanner._detect_spycam_or_hidden_ap(ssid=None, rssi=-46, ch_num=11, is_hidden=True)
    assert hidden_meta["is_hidden_room_ap"] is True
    obs_hid = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="24:0A:C4:AA:BB:CC",
        name=hidden_meta["display_name"],
        rssi=-46,
        role_hint=hidden_meta["role_hint"],
        decoded_fields=hidden_meta["decoded_fields"],
    )
    dev_hid = asyncio.run(engine.process_observation(obs_hid))
    assert dev_hid.risk_score >= 45


def test_camera_and_iot_chip_oui_hardware_intelligence(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_oui.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # Shenzhen Bilian (LB-LINK) Wi-Fi spy-camera module OUI EC:3D:FD
    obs = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="EC:3D:FD:55:66:77",
        name="LAN Wireless Peer (192.168.1.99)",
        rssi=-50,
    )
    dev = asyncio.run(engine.process_observation(obs))
    assert any(f.get("label") == "Donanım Çip Üreticisi (OUI)" for f in dev.decoded_fields)
    assert dev.risk_score >= 30


def test_arp_spoofing_mitm_shield(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_arp_mitm.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # Normal ARP table: Gateway 192.168.1.1 -> AA:BB:CC:00:00:01, Peer 192.168.1.50 -> 11:22:33:44:55:66
    anomalies_clean = engine.check_arp_table_anomalies([
        ("192.168.1.1", "AA:BB:CC:00:00:01", "en0"),
        ("192.168.1.50", "11:22:33:44:55:66", "en0"),
    ])
    assert len(anomalies_clean) == 0

    # Attack: 192.168.1.1 now claims MAC 11:22:33:44:55:66 (duplicate MAC / Gateway ARP poisoning)
    anomalies_attack = asyncio.run(
        engine.process_arp_table([
            ("192.168.1.1", "11:22:33:44:55:66", "en0"),
            ("192.168.1.50", "11:22:33:44:55:66", "en0"),
        ])
    )
    assert len(anomalies_attack) >= 1
    alerts = test_db.get_alerts()
    assert any(a.category == ThreatCategory.ARP_SPOOFING_MITM for a in alerts)


def test_gatt_deep_forensics_and_hid_keystroke_injection_warning():
    fields = BleScanner.analyze_gatt_service_risks(["00001812-0000-1000-8000-00805f9b34fb", "Human Interface Device"])
    assert any("HID Klavye/Fare" in f["value"] for f in fields)


def test_one_click_hotel_bungalow_room_audit_endpoint(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_audit.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    monkeypatch.setattr(app_mod, "db", test_db)

    class DummyWifiScanner:
        is_running = True
        async def run_deep_camera_scan(self):
            return {"peers_checked": 4, "cameras_found_count": 0, "cameras": []}
        def _read_arp_neighbors(self):
            return [("192.168.1.1", "AA:BB:CC:11:22:33", "en0")]

    monkeypatch.setattr(app_mod, "wifi_scanner", DummyWifiScanner())

    # Insert a close-range stationary unknown transmitter (5 sightings at -55 dBm -> risk_score=15)
    for _ in range(5):
        test_db.upsert_observation(
            Observation(
                radio=RadioType.BLE,
                mac_or_uuid="DE:AD:BE:EF:11:22",
                name="Covert_Node_X",
                rssi=-55,
            )
        )

    client = TestClient(app)
    res = client.post("/api/audit/room")
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "ŞÜPHELİ"
    assert len(data["suspicious_devices"]) == 1
    susp_dev = data["suspicious_devices"][0]
    assert susp_dev["mac_or_uuid"] == "DE:AD:BE:EF:11:22"
    assert len(susp_dev.get("audit_flags", [])) >= 1
    assert "Covert_Node_X" in data["checks"][4]["detail"]
    assert any("sabit" in r.lower() for r in data["recommendations"])
