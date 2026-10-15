"""Tests for AirSentinel v3 Discovery, Forensic Intelligence, and Risk Scoring."""
import asyncio
import struct
from pathlib import Path

from airsentinel.correlation.engine import CorrelationEngine
import airsentinel.correlation.engine as eng_mod
from airsentinel.models import DeviceClass, Observation, RadioType, ThreatCategory
from airsentinel.scanners.wifi_scanner import WifiScanner
from airsentinel.signatures.decoder import AdvPayloadDecoder
from airsentinel.storage.db import Database


def test_wifi_ie_wps_and_rsn_security_decoding():
    # Build synthetic 802.11 Information Elements:
    # 1) Tag 0 (SSID): "Hotel_Cam_AP"
    ssid_bytes = b"Hotel_Cam_AP"
    ie_ssid = bytes([0, len(ssid_bytes)]) + ssid_bytes

    # 2) Tag 7 (Country): "TR "
    ie_country = bytes([7, 3]) + b"TR\x20"

    # 3) Tag 48 (RSN / WPA2-PSK)
    ie_rsn = bytes([48, 4, 1, 0, 0, 4])

    # 4) Tag 45 (HT Capabilities -> Wi-Fi 4) and Tag 191 (VHT -> Wi-Fi 5) and Tag 255+35 (HE -> Wi-Fi 6)
    ie_he = bytes([255, 3, 35, 1, 0])

    # 5) Tag 221: Microsoft WPS (00:50:F2:04) with Manufacturer (0x1021)="Hikvision", Model (0x1023)="DS-2CD2143G2"
    def wps_tlv(attr_type: int, val: str) -> bytes:
        b = val.encode("utf-8")
        return struct.pack(">HH", attr_type, len(b)) + b

    wps_body = (
        b"\x00\x50\xF2\x04"
        + wps_tlv(0x1021, "Hikvision")
        + wps_tlv(0x1023, "DS-2CD2143G2")
        + wps_tlv(0x1011, "LobbyDomeCam")
    )
    ie_wps = bytes([221, len(wps_body)]) + wps_body

    full_ie = ie_ssid + ie_country + ie_rsn + ie_he + ie_wps
    info = WifiScanner._parse_ie_intelligence(full_ie)

    assert info["ssid"] == "Hotel_Cam_AP"
    assert info["country"] == "TR"
    assert "WPA2" in info["security"]
    assert "Wi-Fi 6" in info["wifi_standard"]
    assert info["wps_manufacturer"] == "Hikvision"
    assert info["wps_model"] == "DS-2CD2143G2"
    assert info["wps_device_name"] == "LobbyDomeCam"


def test_evil_twin_rogue_ap_detection(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_evil_twin.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # Legitimate hotel WPA2 AP
    obs_legit = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="EC:75:0C:11:22:33",
        name="Bungalow_Resort_WiFi",
        rssi=-55,
        decoded_fields=[{"label": "Wi-Fi Güvenliği", "value": "WPA2/WPA3 Şifreli"}],
    )
    asyncio.run(engine.process_observation(obs_legit))
    assert len(test_db.get_alerts()) == 0

    # Rogue Evil Twin broadcasting same SSID but OPEN (unencrypted) from a different randomized MAC
    obs_rogue = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="DA:A1:19:99:88:77",
        name="Bungalow_Resort_WiFi",
        rssi=-42,
        is_randomized_mac=True,
        decoded_fields=[{"label": "Wi-Fi Güvenliği", "value": "AÇIK (Şifresiz Ağ)"}],
    )
    asyncio.run(engine.process_observation(obs_rogue))
    alerts = test_db.get_alerts()
    assert any(a.category == ThreatCategory.EVIL_TWIN_AP for a in alerts)


def test_expanded_ble_decoders_airplay_ip_tile_smarttag_xiaomi():
    # 1. Apple Continuity AirPlay (0x09) embedding LAN IPv4 address 192.168.1.145
    # TLV: type=0x09, len=6, flags=0x00, config=0x01, ip=192.168.1.145 (C0 A8 01 91)
    dec_ap = AdvPayloadDecoder.analyze(
        company_id=0x004C,
        manufacturer_data_hex="09060001C0A80191",
    )
    assert any("192.168.1.145" in f.value for f in dec_ap.fields)

    # 2. Tile Tracker (Service Data 0xFEED)
    dec_tile = AdvPayloadDecoder.analyze(
        service_data={"0000feed-0000-1000-8000-00805f9b34fb": "0200aabbccddeeff1122"}
    )
    assert dec_tile.role_hint == "Tile Bluetooth Tracker"
    assert dec_tile.fingerprint_id is not None and dec_tile.fingerprint_id.startswith("fp-strong:tile:")

    # 3. Samsung SmartTag (Service Data 0xFD5A) separated from owner (state byte bit 0x20/0x40)
    dec_st = AdvPayloadDecoder.analyze(
        service_data={"0000fd5a-0000-1000-8000-00805f9b34fb": "430011223344556677889900"}
    )
    assert "Samsung SmartTag" in (dec_st.role_hint or "")
    assert any("SmartTag" in f.label for f in dec_st.fields)

    # 4. DJI BLE Device (Company ID 0x08AA)
    dec_dji = AdvPayloadDecoder.analyze(
        company_id=0x08AA,
        manufacturer_data_hex="01020304",
    )
    assert "DJI" in (dec_dji.role_hint or "")


def test_stationary_hidden_device_mobility_distance_and_risk_score(tmp_path: Path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_risk_mobility.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # Feed 5 observations of an untrusted hidden camera with rock-steady RSSI (-48, -48, -49, -48, -48)
    dev = None
    for rssi in (-48, -48, -49, -48, -48):
        obs = Observation(
            radio=RadioType.WIFI,
            mac_or_uuid="AA:BB:CC:99:88:77",
            name="IP Kamera (192.168.1.88)",
            rssi=rssi,
            tx_power=-42,
            role_hint="Ağda Canlı Video Yayını Yapan Kamera (RTSP/ONVIF)",
            decoded_fields=[{"label": "Açık Kamera Portu", "value": "RTSP Canlı Video (Port 554)"}],
        )
        dev = asyncio.run(engine.process_observation(obs))

    assert dev is not None
    assert dev.device_class == DeviceClass.SURVEILLANCE
    assert dev.estimated_distance_m is not None and 0.3 <= dev.estimated_distance_m <= 5.0
    assert dev.mobility_profile is not None and "Sabit" in dev.mobility_profile
    assert dev.risk_score >= 70
    assert len(dev.risk_reasons) >= 2
