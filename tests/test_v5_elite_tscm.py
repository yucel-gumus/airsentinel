"""Tests for AirSentinel v5 Elite TSCM: Dahua/Ubiquiti/SADP Discovery, DNS Hijack Shield, RF Motion Shadowing & Forensic Report."""
import asyncio
import hashlib
import sys
from pathlib import Path
from fastapi.testclient import TestClient

import airsentinel.correlation.engine as eng_mod
from airsentinel.correlation.engine import CorrelationEngine
from airsentinel.intel.exporters import DataExporter
from airsentinel.models import DeviceClass, Observation, RadioType, ThreatCategory
from airsentinel.scanners.wifi_scanner import WifiScanner
from airsentinel.storage.db import Database
from airsentinel.web.app import app

app_mod = sys.modules["airsentinel.web.app"]


def test_dahua_dhip_and_hikvision_sadp_proprietary_camera_parsers():
    # 1. Dahua DHIP JSON response (UDP 37810)
    dahua_pkt = (
        b"\x20\x00\x00\x00DHIP\x00\x00\x00\x00\x00\x00\x00\x00"
        b'{"method":"client.notifyDevInfo","params":{"deviceInfo":{"DeviceType":"IPC-HDW2431T-AS","SerialNo":"8J05921PAZ","Mac":"3c:ef:8c:11:22:33"}}}'
    )
    dh_info = WifiScanner._parse_dahua_dhip_response(dahua_pkt)
    assert dh_info is not None
    assert "IPC-HDW2431T-AS" in dh_info
    assert "Dahua" in dh_info

    # 2. Hikvision SADP XML response (UDP 37020)
    sadp_xml = b"""<?xml version="1.0" encoding="utf-8"?>
    <ProbeMatch>
        <Types>inquiry</Types>
        <DeviceDescription>DS-2CD2443G0-IW</DeviceDescription>
        <DeviceSN>DS-2CD2443G0-IW20230911AAWR</DeviceSN>
        <CommandPort>8000</CommandPort>
        <HttpPort>80</HttpPort>
    </ProbeMatch>
    """
    hk_info = WifiScanner._parse_hikvision_sadp_response(sadp_xml)
    assert hk_info is not None
    assert "DS-2CD2443G0-IW" in hk_info
    assert "Hikvision" in hk_info


def test_dns_hijack_and_private_ip_phishing_detection(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_dns_hijack.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # Simulate a rogue hotel router resolving "www.apple.com" to a local phishing IP "192.168.1.250"
    hijack = WifiScanner. evaluate_dns_resolution_anomaly("www.apple.com", ["192.168.1.250"])
    assert hijack is not None
    assert hijack["type"] == "DNS_PRIVATE_IP_HIJACK"

    alerts = asyncio.run(engine.process_dns_anomalies([hijack]))
    assert len(alerts) == 1
    db_alerts = test_db.get_alerts()
    assert any(a.category == ThreatCategory.DNS_HIJACK_MITM for a in db_alerts)


def test_rf_shadowing_human_presence_motion_detector_in_sentry_mode(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_rf_motion.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()
    engine.sentry_mode = True

    # Trusted stationary router in the hotel room with rock-steady signal (-50, -50, -51, -50, -50)
    for rssi in (-50, -50, -51, -50, -50):
        obs = Observation(
            radio=RadioType.WIFI,
            mac_or_uuid="AA:BB:CC:DD:EE:01",
            name="Bungalow_AP",
            rssi=rssi,
        )
        asyncio.run(engine.process_observation(obs))
    test_db.toggle_trust("AA:BB:CC:DD:EE:01")

    # Now an intruder in Airplane Mode walks directly between the router and MacBook Air M2,
    # causing a sudden 14 dB RF body-shadowing drop (-64 dBm) on the stationary link!
    obs_shadow = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="AA:BB:CC:DD:EE:01",
        name="Bungalow_AP",
        rssi=-65,
    )
    asyncio.run(engine.process_observation(obs_shadow))

    alerts = test_db.get_alerts()
    assert any(a.category == ThreatCategory.RF_PRESENCE_MOTION for a in alerts)


def test_tamper_evident_forensic_evidence_export_endpoint(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_forensic_export.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    monkeypatch.setattr(app_mod, "db", test_db)
    engine = CorrelationEngine()

    obs = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="EC:3D:FD:99:88:77",
        name="V380_998877",
        rssi=-45,
        role_hint="Gizli Kamera Doğrudan Wi-Fi Yayını (SpyCam SoftAP)",
        decoded_fields=[{"label": "Açık Kamera Portu", "value": "RTSP Canlı Video (Port 554)"}],
    )
    asyncio.run(engine.process_observation(obs))

    client = TestClient(app)
    res = client.get("/api/export/forensic-report")
    assert res.status_code == 200
    html_text = res.text
    assert "ADLİ BİLİŞİM VE KARŞI-İSTİHBARAT (TSCM) KANIT RAPORU" in html_text
    assert "EC:3D:FD:99:88:77" in html_text
    assert "SHA-256" in html_text
