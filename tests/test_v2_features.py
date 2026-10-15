"""Comprehensive test suite for AirSentinel v2 production capabilities."""
from pathlib import Path
from fastapi.testclient import TestClient

from airsentinel.correlation.flood_detector import FloodDetector
from airsentinel.correlation.hunt import SignalHunter
from airsentinel.intel.exporters import DataExporter, sanitize_csv_cell
from airsentinel.models import HuntCue, Observation, RadioType
from airsentinel.signatures.catalog import catalog
from airsentinel.signatures.decoder import AdvPayloadDecoder
from airsentinel.signatures.remote_id import RemoteIdParser
from airsentinel.storage.db import Database
from airsentinel.web.app import app


def test_mac_normalization_and_tplink_arp():
    # macOS `arp -an` outputs single-digit hex octets like ec:75:c:11:22:33
    norm = catalog._normalize_mac("ec:75:c:11:22:33")
    assert norm == "EC:75:0C:11:22:33"
    sig = catalog.match(radio=RadioType.WIFI, mac="ec:75:c:11:22:33")
    assert sig is not None
    assert "TP-Link" in sig.fleet_name


def test_adv_payload_decoder_apple_and_microsoft():
    # 1. Real iPhone Continuity Nearby Info (0x10)
    analysis = AdvPayloadDecoder.analyze(
        company_id=0x004C,
        manufacturer_data_hex="10060a1e0b95db23",
    )
    assert any("Apple Continuity State" in f.label for f in analysis.fields)
    assert analysis.role_hint == "iPhone / iPad / Mac"

    # 2. Real Windows 10/11 Desktop CDP (0x0006, type 0x01, devType 0x09)
    analysis_ms = AdvPayloadDecoder.analyze(
        company_id=0x0006,
        manufacturer_data_hex="01092022fa07b7991e7aa96fd1c6c613d653c3024041b4cf7068ce",
    )
    assert any("Windows 10/11 Desktop" in f.value for f in analysis_ms.fields)
    assert analysis_ms.role_hint == "Windows 10/11 Desktop"
    assert analysis_ms.is_windows_cdp is True
    assert analysis_ms.is_pairing_popup is False

    # 3. Microsoft Swift Pair (0x0006, type 0x03)
    analysis_sp = AdvPayloadDecoder.analyze(
        company_id=0x0006,
        manufacturer_data_hex="030080",
    )
    assert any("Microsoft Swift Pair" in f.label for f in analysis_sp.fields)
    assert analysis_sp.is_pairing_popup is True

    # 4. Apple AirPods Pro 2 Proximity Pairing (0x07)
    analysis_ap = AdvPayloadDecoder.analyze(
        company_id=0x004C,
        manufacturer_data_hex="071901142075aa88010000",
    )
    assert any("AirPods Pro (2nd gen, Lightning)" in f.value for f in analysis_ap.fields)
    assert analysis_ap.role_hint == "AirPods Pro (2nd gen, Lightning)"


def test_adv_payload_decoder_fast_pair_and_ruuvi_and_axon():
    # Google Fast Pair (Pixel Buds Pro = 0x2A1B47)
    analysis_fp = AdvPayloadDecoder.analyze(
        service_data={"0000fe2c-0000-1000-8000-00805f9b34fb": "2a1b47"}
    )
    assert any("Google Fast Pair" in f.label for f in analysis_fp.fields)

    # RuuviTag Format 5 (0x0499)
    analysis_rv = AdvPayloadDecoder.analyze(
        company_id=0x0499,
        manufacturer_data_hex="0512fc5394c37c0004fffe040cac364200cdcbb8334c884f",
    )
    assert any("Ruuvi Telemetry" in f.label for f in analysis_rv.fields)
    assert analysis_rv.role_hint == "RuuviTag Environmental Sensor"

    # Axon Body Cam BWCDEVICE
    analysis_ax = AdvPayloadDecoder.analyze(
        service_data={"0000fe6c-0000-1000-8000-00805f9b34fb": "42574344455649434500"}
    )
    assert any("Axon Signature" in f.label for f in analysis_ax.fields)
    assert analysis_ax.role_hint == "Axon Body-Worn Camera"


def test_cta2063_serial_and_odid_service_data_wrapper():
    mfg, model = RemoteIdParser.identify_manufacturer_and_model("18179132987654")
    assert mfg == "Freefly"
    assert model == "Freefly Alta X Gen2"

    mfg_b, model_b = RemoteIdParser.identify_manufacturer_and_model("1914CL2D999999")
    assert mfg_b == "BRINC Drones"
    assert model_b == "BRINC Lemur 2"

    # Build 0xFFFA service data wrapper: [0x0D, counter=0x01, 0xF2, msg_size=25, count=1, BasicID_msg(25)]
    basic_id = bytearray(25)
    basic_id[0] = (0x0 << 4) | 0x2
    basic_id[1] = (1 << 4) | 1
    serial = b"18179132987654"
    basic_id[2 : 2 + len(serial)] = serial
    wrapped = bytes([0x0D, 0x01, 0xF2, 25, 1]) + bytes(basic_id)

    parsed = RemoteIdParser.parse_payload(wrapped)
    assert parsed is not None
    assert parsed.uas_id == "18179132987654"
    assert parsed.manufacturer == "Freefly"
    assert parsed.model_name == "Freefly Alta X Gen2"


def test_flood_detector_ignores_benign_windows_cdp():
    detector = FloodDetector()
    # 30 observations from a single Windows 10/11 CDP desktop should NEVER trigger a flood alert
    for _ in range(30):
        obs = Observation(
            radio=RadioType.BLE,
            mac_or_uuid="25FA2774-A10C-0CAD-8DFA-C81EE95CC3D5",
            rssi=-62,
            company_id=0x0006,
            manufacturer_data_hex="01092022fa07b7991e7aa96f",
        )
        assert detector.process_observation(obs) is None


def test_signal_hunter_geiger_cues():
    hunter = SignalHunter()
    mac = "AA:BB:CC:11:22:33"
    base_ts = 1000.0
    hunter.record_sample(mac, -82, now=base_ts - 10.0)
    hunter.record_sample(mac, -80, now=base_ts - 8.0)
    hunter.record_sample(mac, -40, now=base_ts - 1.0)
    hunter.record_sample(mac, -39, now=base_ts)

    state = hunter.evaluate(mac, now=base_ts)
    assert state["cue"] == HuntCue.VERY_CLOSE.value
    assert state["proximity_pct"] >= 80
    assert state["tick_ms"] is not None and state["tick_ms"] <= 200


def test_sits_and_sit_diff(tmp_path: Path):
    test_db = Database(db_path=tmp_path / "test_sits.db")
    obs1 = Observation(radio=RadioType.WIFI, mac_or_uuid="11:22:33:44:55:01", rssi=-50, name="ResidentAP")
    test_db.upsert_observation(obs1)

    sit1 = test_db.start_sit("Morning Baseline")
    sit1 = test_db.stop_sit(sit1.id)
    assert sit1.device_count == 1

    # Add an intruder device
    obs2 = Observation(radio=RadioType.BLE, mac_or_uuid="AA:BB:CC:DD:EE:99", rssi=-45, name="IntruderNode")
    test_db.upsert_observation(obs2)

    sit2 = test_db.start_sit("Night Sweep")
    diff = test_db.compare_sits(sit1.id, sit2.id)
    assert diff is not None
    assert diff["new_count"] == 1
    assert diff["new_devices"][0]["mac_or_uuid"] == "AA:BB:CC:DD:EE:99"
    assert diff["stayed_count"] == 1
    assert diff["stayed_devices"][0]["mac_or_uuid"] == "11:22:33:44:55:01"


def test_csv_sanitization_and_kml_export():
    assert sanitize_csv_cell("=CMD|' /C calc'!A0") == "'=CMD|' /C calc'!A0"
    client = TestClient(app)
    res_kml = client.get("/api/export/kml")
    assert res_kml.status_code == 200
    assert "<kml" in res_kml.text


def test_apple_find_my_1202_owner_nearby_vs_1219_separated():
    # 1. Short 2-byte 0x1202 frame = Owner nearby (active Apple device, NOT a separated AirTag)
    dec_nearby = AdvPayloadDecoder.analyze(company_id=0x004C, manufacturer_data_hex="12020001")
    assert dec_nearby.is_unmaintained_find_my is False
    assert dec_nearby.is_apple_continuity_device is True
    assert any("Owner nearby" in f.value for f in dec_nearby.fields)

    sig_nearby = catalog.match(radio=RadioType.BLE, company_id=0x004C, manufacturer_data_hex="12020001")
    assert sig_nearby is not None
    assert sig_nearby.fleet_name == "Apple Device"
    assert sig_nearby.device_class.value == "PHONE"

    # 2. Long 25-byte 0x1219 frame with status 0x00 = Separated AirTag
    dec_sep = AdvPayloadDecoder.analyze(
        company_id=0x004C,
        manufacturer_data_hex="121900112233445566778899001122334455667788990011223344",
    )
    assert dec_sep.is_unmaintained_find_my is True
    assert any("Separated from owner" in f.value for f in dec_sep.fields)

    sig_sep = catalog.match(
        radio=RadioType.BLE,
        company_id=0x004C,
        manufacturer_data_hex="121900112233445566778899001122334455667788990011223344",
    )
    assert sig_sep is not None
    assert sig_sep.fleet_name == "Apple AirTags"
    assert sig_sep.device_class.value == "TRACKER"


def test_eddystone_find_hub_gopro_and_govee_decoders():
    # Google Find Hub (0xFEAA, frame 0x40)
    dec_fh = AdvPayloadDecoder.analyze(service_data={"feaa": "4011223344556677889900"})
    assert dec_fh.role_hint == "Google Find Hub Tracker"
    assert any("Google Find Hub" in f.label for f in dec_fh.fields)

    # GoPro Camera (0xF202)
    dec_gp = AdvPayloadDecoder.analyze(company_id=0xF202, manufacturer_data_hex="0100")
    assert dec_gp.role_hint == "GoPro Action Camera"
    assert any("Recording active" in f.value for f in dec_gp.fields)

    # Govee Sensor (0xEC88)
    dec_gv = AdvPayloadDecoder.analyze(company_id=0xEC88, manufacturer_data_hex="0003a28c5500")
    assert dec_gv.role_hint == "Govee Smart Thermo-Hygrometer"
    assert any("Govee Telemetry" in f.label for f in dec_gv.fields)


def test_wifi_infrastructure_classification_and_clear_data(tmp_path: Path):
    test_db = Database(db_path=tmp_path / "test_wifi_class.db")
    obs_ap = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="00:57:46:24:02:03",
        name="Wi-Fi AP [Ch 36 (5GHz, 80MHz)]",
        rssi=-55,
    )
    dev = test_db.upsert_observation(obs_ap)
    assert dev.device_class.value == "INFRASTRUCTURE"
    assert len(test_db.get_devices()) == 1

    res = test_db.clear_data()
    assert res["deleted_devices"] == 1
    assert len(test_db.get_devices()) == 0


def test_ble_mac_rotation_reidentification_preserves_trust_and_history(tmp_path: Path):
    test_db = Database(db_path=tmp_path / "test_mac_rot.db")
    obs1 = Observation(
        radio=RadioType.BLE,
        mac_or_uuid="AAAA-1111-OLD-UUID",
        name="Kullanıcı iPhone’u",
        rssi=-46,
        fingerprint_id="fp-strong:name:kullanıcı iphone’u",
    )
    d1 = test_db.upsert_observation(obs1)
    assert d1.hit_count == 1
    assert test_db.toggle_trust("AAAA-1111-OLD-UUID") is True

    # Simulate BLE MAC rotation to a brand-new UUID for the same device
    obs2 = Observation(
        radio=RadioType.BLE,
        mac_or_uuid="BBBB-2222-NEW-UUID",
        name="Kullanıcı iPhone’u",
        rssi=-48,
        fingerprint_id="fp-strong:name:kullanıcı iphone’u",
    )
    d2 = test_db.upsert_observation(obs2)
    assert d2.mac_or_uuid == "BBBB-2222-NEW-UUID"
    assert d2.hit_count == 2
    assert d2.is_trusted is True
    assert any(f.get("label") == "MAC Rotasyonu" for f in d2.decoded_fields)
    # Only 1 deduplicated device in DB
    all_devs = test_db.get_devices()
    assert len(all_devs) == 1
    assert all_devs[0].mac_or_uuid == "BBBB-2222-NEW-UUID"


def test_household_trust_and_sentry_mode_intruder_alert(tmp_path: Path, monkeypatch):
    import asyncio
    from airsentinel.correlation.engine import CorrelationEngine
    import airsentinel.correlation.engine as eng_mod

    test_db = Database(db_path=tmp_path / "test_sentry.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    # 1. Add household device and mark all current devices as trusted
    obs_home = Observation(
        radio=RadioType.BLE,
        mac_or_uuid="HOME-IPHONE-01",
        name="Kullanıcı iPhone’u",
        rssi=-44,
        company_id=0x004C,
        manufacturer_data_hex="10060a1e0b95db23",
    )
    asyncio.run(engine.process_observation(obs_home))
    trusted_cnt = test_db.trust_all_current_devices()
    assert trusted_cnt == 1

    # 2. Enable Sentry Mode (Bekçi Modu)
    engine.sentry_mode = True

    # Trusted device at -44 dBm should NOT trigger an alert
    dev_home = asyncio.run(engine.process_observation(obs_home))
    assert dev_home.is_trusted is True
    assert len(test_db.get_alerts()) == 0

    # Untrusted close-range phone (-48 dBm) MUST trigger an INTRUDER_PROXIMITY alert
    obs_intruder = Observation(
        radio=RadioType.BLE,
        mac_or_uuid="INTRUDER-PHONE-99",
        rssi=-48,
        company_id=0x004C,
        manufacturer_data_hex="1006071f00112233",
    )
    dev_intruder = asyncio.run(engine.process_observation(obs_intruder))
    assert dev_intruder.is_threat is True
    alerts = test_db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].category.value == "INTRUDER_PROXIMITY"
    assert "Bekçi Modu" in alerts[0].title


def test_wifi_rtsp_camera_port_detection_and_alert(tmp_path: Path, monkeypatch):
    import asyncio
    import socket
    from airsentinel.correlation.engine import CorrelationEngine
    import airsentinel.correlation.engine as eng_mod
    from airsentinel.scanners import wifi_scanner as ws_mod
    from airsentinel.scanners.wifi_scanner import WifiScanner

    # Bind an ephemeral local TCP listener and test _probe_camera_ports against it
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        monkeypatch.setitem(ws_mod.CAMERA_STREAM_PORTS, port, f"RTSP Test Kamera (Port {port})")
        found = WifiScanner._probe_camera_ports("127.0.0.1", timeout=0.2)
        assert any(f"Port {port}" in s for s in found)

    # Verify CorrelationEngine classifies RTSP camera observation as SURVEILLANCE and emits CRITICAL alert
    test_db = Database(db_path=tmp_path / "test_cam.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    obs_cam = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="AA:BB:CC:DD:EE:77",
        name="IP Kamera (192.168.1.55)",
        rssi=-52,
        channel_or_freq="LAN (en1 · 192.168.1.55)",
        role_hint="Ağda Canlı Video Yayını Yapan Kamera (RTSP/ONVIF)",
        decoded_fields=[{"label": "Açık Kamera Portu", "value": "RTSP Canlı Video (Port 554)"}],
    )
    dev_cam = asyncio.run(engine.process_observation(obs_cam))
    assert dev_cam.device_class.value == "SURVEILLANCE"
    assert dev_cam.is_threat is True
    alerts = test_db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].category.value == "SURVEILLANCE_CAMERA"


def test_gatt_profile_enrichment_and_apple_model_map(tmp_path: Path):
    from airsentinel.scanners.ble_scanner import APPLE_MODEL_MAP

    assert APPLE_MODEL_MAP["iPhone11,8"] == "iPhone XR"
    assert APPLE_MODEL_MAP["Mac16,10"] == "Mac mini (M4, 2024)"

    test_db = Database(db_path=tmp_path / "test_gatt.db")
    obs = Observation(radio=RadioType.BLE, mac_or_uuid="BLE-GATT-TEST-01", rssi=-50)
    test_db.upsert_observation(obs)

    updated = test_db.update_gatt_profile(
        mac_or_uuid="BLE-GATT-TEST-01",
        name="iPhone XR (iPhone11,8)",
        role_hint="Apple Inc. · iPhone XR (iPhone11,8)",
        gatt_fields=[
            {"label": "GATT Üretici", "value": "Apple Inc."},
            {"label": "GATT Model", "value": "iPhone XR (iPhone11,8)"},
            {"label": "GATT Pil Seviyesi", "value": "%85"},
        ],
    )
    assert updated is not None
    assert updated.name == "iPhone XR (iPhone11,8)"
    assert any(f.get("label") == "GATT Pil Seviyesi" for f in updated.decoded_fields)


def test_reset_clears_in_memory_dedup_and_preserves_drone_info(tmp_path: Path, monkeypatch):
    import asyncio
    from airsentinel.correlation.engine import CorrelationEngine
    import airsentinel.correlation.engine as eng_mod
    from airsentinel.models import DroneRemoteID

    test_db = Database(db_path=tmp_path / "test_reset.db")
    monkeypatch.setattr(eng_mod, "db", test_db)
    engine = CorrelationEngine()

    obs_drone1 = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="60:60:1F:AA:BB:CC",
        rssi=-55,
        drone_data=DroneRemoteID(uas_id="1581F000111222", manufacturer="DJI", altitude_m=85.0),
    )
    d1 = asyncio.run(engine.process_observation(obs_drone1))
    assert d1.drone_info is not None
    assert d1.drone_info.uas_id == "1581F000111222"
    assert len(test_db.get_alerts()) == 1

    # Second observation without drone_data must preserve drone_info on returned TrackedDevice
    obs_drone2 = Observation(
        radio=RadioType.WIFI,
        mac_or_uuid="60:60:1F:AA:BB:CC",
        rssi=-52,
    )
    d2 = asyncio.run(engine.process_observation(obs_drone2))
    assert d2.drone_info is not None
    assert d2.drone_info.uas_id == "1581F000111222"

    # Reset DB + engine state, then re-observe the same drone -> must alert again
    test_db.clear_data()
    engine.reset()
    asyncio.run(engine.process_observation(obs_drone1))
    assert len(test_db.get_alerts()) == 1

