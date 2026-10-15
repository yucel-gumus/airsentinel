"""FastAPI Web and WebSocket Server for AirSentinel Core."""
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from airsentinel.config import settings, STATIC_DIR
from airsentinel.correlation.engine import correlation_engine
from airsentinel.correlation.hunt import signal_hunter
from airsentinel.intel.exporters import DataExporter
from airsentinel.intel.local_ai import ai_analyzer
from airsentinel.models import DeviceClass
from airsentinel.scanners.ble_scanner import BleScanner
from airsentinel.scanners.wifi_scanner import WifiScanner
from airsentinel.signatures.catalog import catalog
from airsentinel.storage.db import db

logger = logging.getLogger("airsentinel.web")

# Active WebSocket clients
connected_clients: List[WebSocket] = []

# Scanners
ble_scanner: Optional[BleScanner] = None
wifi_scanner: Optional[WifiScanner] = None


class SitStartRequest(BaseModel):
    label: str = "Tactical Sit"


async def broadcast_ws(message: dict):
    """Broadcasts a JSON message to all connected WebSocket clients."""
    if not connected_clients:
        return
    text = json.dumps(message)
    dead_clients = []
    for client in connected_clients:
        try:
            await client.send_text(text)
        except Exception:
            dead_clients.append(client)
    for dc in dead_clients:
        if dc in connected_clients:
            connected_clients.remove(dc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ble_scanner, wifi_scanner
    logger.info("Initializing AirSentinel Engine & Scanners...")

    correlation_engine.register_broadcast_listener(broadcast_ws)

    if settings.enable_ble_scanner:
        ble_scanner = BleScanner(correlation_engine.process_observation)
        await ble_scanner.start()

    if settings.enable_wifi_scanner:
        wifi_scanner = WifiScanner(correlation_engine.process_observation)
        await wifi_scanner.start()

    yield

    logger.info("Shutting down AirSentinel Engine...")
    if ble_scanner:
        await ble_scanner.stop()
    if wifi_scanner:
        await wifi_scanner.stop()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/status")
async def get_status():
    stats = db.get_stats()
    return {
        "status": "ONLINE",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "catalog_version": catalog.catalog_version,
        "rules_count": catalog.rules_count,
        "connected_clients": len(connected_clients),
        "sentry_mode": correlation_engine.sentry_mode,
        "radios": {
            "ble_scanning": ble_scanner.is_running if ble_scanner else False,
            "wifi_scanning": wifi_scanner.is_running if wifi_scanner else False,
        },
        "stats": stats,
    }


@app.get("/api/devices")
async def get_devices(
    limit: int = Query(250, ge=1, le=1000),
    device_class: Optional[DeviceClass] = None,
    bookmarked_only: bool = Query(False),
):
    devices = db.get_devices(
        limit=limit, class_filter=device_class, bookmarked_only=bookmarked_only
    )
    return [d.model_dump(mode="json") for d in devices]


@app.post("/api/devices/{mac:path}/bookmark")
async def toggle_device_bookmark(mac: str):
    dev = db.get_device(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    bookmarked = db.toggle_bookmark(mac)
    return {"mac_or_uuid": mac, "is_bookmarked": bookmarked}


@app.post("/api/devices/{mac:path}/trust")
async def toggle_device_trust(mac: str):
    dev = db.get_device(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    trusted = db.toggle_trust(mac)
    await _broadcast_full_state()
    return {"mac_or_uuid": mac, "is_trusted": trusted}


@app.post("/api/devices/{mac:path}/gatt")
async def inspect_device_gatt(mac: str):
    dev = db.get_device(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    scanner = ble_scanner or BleScanner(correlation_engine.process_observation)
    gatt_res = await scanner.inspect_gatt(mac)
    if gatt_res.get("connected"):
        new_name = gatt_res.get("device_name") or gatt_res.get("model")
        new_role = None
        if gatt_res.get("manufacturer") or gatt_res.get("model"):
            parts = [p for p in (gatt_res.get("manufacturer"), gatt_res.get("model")) if p]
            new_role = " · ".join(parts)
        updated_dev = db.update_gatt_profile(
            mac_or_uuid=mac,
            name=new_name,
            role_hint=new_role,
            gatt_fields=gatt_res.get("gatt_fields", []),
        )
        if updated_dev:
            await broadcast_ws({
                "type": "OBSERVATION",
                "data": updated_dev.model_dump(mode="json"),
            })
            gatt_res["device"] = updated_dev.model_dump(mode="json")
    return gatt_res


@app.post("/api/sentry/toggle")
async def toggle_sentry_mode():
    correlation_engine.sentry_mode = not correlation_engine.sentry_mode
    await broadcast_ws({
        "type": "SENTRY_STATE",
        "data": {"sentry_mode": correlation_engine.sentry_mode},
    })
    return {"sentry_mode": correlation_engine.sentry_mode}


@app.post("/api/sentry/trust-all")
async def trust_all_household_devices():
    count = db.trust_all_current_devices()
    await _broadcast_full_state()
    return {"trusted_updated": count, "stats": db.get_stats()}


@app.post("/api/wifi/deep-scan")
async def run_wifi_deep_camera_scan():
    scanner = wifi_scanner or WifiScanner(correlation_engine.process_observation)
    result = await scanner.run_deep_camera_scan()
    await _broadcast_full_state()
    return result


@app.post("/api/audit/room")
async def run_room_security_audit():
    """Executes a 5-stage Hotel / Bungalow / Home TSCM Counter-Surveillance & Network Security Audit."""
    scanner = wifi_scanner or WifiScanner(correlation_engine.process_observation)
    cam_scan = await scanner.run_deep_camera_scan()
    arp_peers = await asyncio.to_thread(scanner._read_arp_neighbors)
    arp_anomalies = await correlation_engine.process_arp_table(arp_peers)
    dns_check_fn = getattr(scanner, "check_live_dns_hijack", WifiScanner.check_live_dns_hijack)
    dns_anomalies = await asyncio.to_thread(dns_check_fn)
    await correlation_engine.process_dns_anomalies(dns_anomalies)

    devices = db.get_devices(limit=500)
    alerts = db.get_alerts(limit=50)
    untrusted = [d for d in devices if not d.is_trusted]

    # 1. Network MITM, DNS Hijacking & Evil Twin Check
    mitm_alerts = [
        a for a in alerts
        if not a.acknowledged and a.category.value in ("ARP_SPOOFING_MITM", "EVIL_TWIN_AP", "DNS_HIJACK_MITM")
    ]
    net_status = "TEHLİKELİ" if (mitm_alerts or arp_anomalies or dns_anomalies) else "TEMİZ"

    # 2. Hidden / Network Cameras Check
    cameras = [
        d for d in untrusted
        if d.device_class == DeviceClass.SURVEILLANCE or (d.role_hint and "kamera" in d.role_hint.lower())
    ]
    cam_status = "TEHLİKELİ" if cameras else "TEMİZ"

    # 3. SpyCam SoftAP & Close-Range Hidden SSID Check
    hidden_or_spy_aps = []
    for d in untrusted:
        f_blob = " ".join(
            f"{f.get('label', '')} {f.get('value', '')}" for f in (d.decoded_fields or []) if isinstance(f, dict)
        ).lower()
        if "gizli ssid" in f_blob or "casus kamera ağı" in f_blob:
            hidden_or_spy_aps.append(d)
    ap_status = "TEHLİKELİ" if any("casus kamera" in (d.role_hint or "").lower() for d in hidden_or_spy_aps) else (
        "ŞÜPHELİ" if hidden_or_spy_aps else "TEMİZ"
    )

    # 4. Trackers (AirTag / SmartTag / Tile / Find Hub)
    trackers = [d for d in untrusted if d.device_class == DeviceClass.TRACKER]
    tracker_status = "ŞÜPHELİ" if trackers else "TEMİZ"

    # 5. Close-Range Stationary Unknown/High-Risk Transmitters (< 3.5m / RSSI >= -60 dBm)
    close_stationary = [
        d for d in untrusted
        if d.device_class not in (DeviceClass.INFRASTRUCTURE, DeviceClass.PHONE, DeviceClass.PC)
        and (d.risk_score >= 40 or (d.mobility_profile and "Sabit" in d.mobility_profile and d.last_rssi >= -60))
    ]
    stat_status = "ŞÜPHELİ" if close_stationary else "TEMİZ"

    def _fmt_short(d) -> str:
        lbl = d.name or d.matched_fleet or "İsimsiz Verici"
        dist = f", ~{d.estimated_distance_m}m" if d.estimated_distance_m is not None else ""
        return f"{lbl} [{d.mac_or_uuid[:17]}] ({d.last_rssi} dBm{dist})"

    checks = [
        {
            "title": "1. Ağ Güvenliği, ARP Spoofing (MITM), DNS Zehirleme ve Sahte Wi-Fi Kontrolü",
            "status": net_status,
            "detail": (
                f"{len(mitm_alerts) + len(arp_anomalies) + len(dns_anomalies)} ağ saldırı anomalisi tespit edildi: "
                + " | ".join(
                    [a.title for a in mitm_alerts]
                    + [x.get("title", "") for x in arp_anomalies]
                    + [x.get("title", "") for x in dns_anomalies]
                )
                if net_status != "TEMİZ"
                else f"Modem, DNS ve ARP tablosu temiz ({len(arp_peers)} yerel ağ komşusu doğrulandı)."
            ),
        },
        {
            "title": "2. ONVIF / RTSP / UPnP / Dahua / Hikvision ve 10 Kamera Portu Taraması",
            "status": cam_status,
            "detail": (
                f"🚨 {len(cameras)} adet kamera / görüntü yayını yapan cihaz bulundu: "
                + ", ".join(_fmt_short(d) for d in cameras)
                if cameras
                else f"Açık RTSP/ONVIF/MJPEG kamera portu bulunmadı ({cam_scan.get('peers_checked', 0)} IP tarandı)."
            ),
        },
        {
            "title": "3. Casus Kamera Wi-Fi (SoftAP) ve Oda İçi Gizli SSID Kontrolü",
            "status": ap_status,
            "detail": (
                f"⚠️ Oda içinde {len(hidden_or_spy_aps)} adet gizli/şüpheli Wi-Fi yayını algılandı: "
                + ", ".join(_fmt_short(d) for d in hidden_or_spy_aps)
                if hidden_or_spy_aps
                else "Oda içinde isimsiz (Gizli SSID) veya casus kamera SoftAP yayını yok."
            ),
        },
        {
            "title": "4. Konum Takip Cihazı (AirTag / SmartTag / Tile) Kontrolü",
            "status": tracker_status,
            "detail": (
                f"📍 Çevrede {len(trackers)} adet takip etiketi sinyal yayıyor: "
                + ", ".join(_fmt_short(d) for d in trackers)
                if trackers
                else "Çevrede yabancı AirTag, SmartTag veya Tile takip cihazı algılanmadı."
            ),
        },
        {
            "title": "5. Oda İçi Sabit (📌) & Kamera Çipli (OUI) Verici Analizi",
            "status": stat_status,
            "detail": (
                f"📌 Yakın mesafede {len(close_stationary)} adet sabit/yüksek riskli verici tespit edildi: "
                + ", ".join(_fmt_short(d) for d in close_stationary)
                if close_stationary
                else "Yakın mesafede şüpheli sabit verici veya gizli kamera çipi (OUI) görülmedi."
            ),
        },
    ]

    # Collect EVERY device that triggered any check OR has risk_score >= 25 or is_threat
    susp_map = {}
    audit_flags_map = {}

    def _add_susp(dev_list, flag_reason: str):
        for d in dev_list:
            susp_map[d.mac_or_uuid] = d
            flags = audit_flags_map.setdefault(d.mac_or_uuid, [])
            if flag_reason not in flags:
                flags.append(flag_reason)

    _add_susp(cameras, "Madde 2: Kamera / Görüntü Yayını (ONVIF/RTSP/Kamera Sınıfı)")
    _add_susp(hidden_or_spy_aps, "Madde 3: Casus Kamera SoftAP veya Oda İçi Gizli SSID Yayını")
    _add_susp(trackers, "Madde 4: Konum Takip Etiketi (AirTag / SmartTag / Tile)")
    _add_susp(close_stationary, "Madde 5: Oda İçinde Yakın Mesafede Sabit (📌) veya Yüksek Riskli Verici")
    for d in untrusted:
        if d.risk_score >= 25 or d.is_threat:
            _add_susp([d], f"Genel Risk Analizi (Risk Puanı: {d.risk_score}/100)")

    suspicious_sorted = sorted(
        susp_map.values(),
        key=lambda x: (-x.risk_score, -x.last_rssi),
    )[:15]

    suspicious_payload = []
    for d in suspicious_sorted:
        d_dict = d.model_dump(mode="json")
        d_dict["audit_flags"] = audit_flags_map.get(d.mac_or_uuid, [])
        suspicious_payload.append(d_dict)

    max_risk = max([d.risk_score for d in untrusted], default=0)
    if net_status == "TEHLİKELİ" or cam_status == "TEHLİKELİ":
        max_risk = max(max_risk, 90)
    elif any(c["status"] == "ŞÜPHELİ" for c in checks):
        max_risk = max(max_risk, 35)

    if max_risk >= 70 or net_status == "TEHLİKELİ" or cam_status == "TEHLİKELİ":
        verdict = "TEHLİKELİ"
    elif max_risk >= 35 or any(c["status"] == "ŞÜPHELİ" for c in checks):
        verdict = "ŞÜPHELİ"
    else:
        verdict = "TEMİZ"

    recommendations = []
    if cameras:
        recommendations.append(
            "🎯 Tespit edilen kamera cihazına tıklayıp 'Sinyal Avcısı (Geiger)' modunu açarak odada sinyal gücünün -35 dBm'e çıktığı noktayı (priz, duman dedektörü, TV ünitesi) fiziksel olarak kontrol edin."
        )
    if mitm_alerts or arp_anomalies or dns_anomalies:
        recommendations.append(
            "🛑 Bulunduğunuz Wi-Fi ağında ARP Spoofing, DNS Zehirleme veya Sahte Baz İstasyonu (Evil Twin) tespit edildi! Wi-Fi bağlantısını kesin veya VPN kullanmadan şifre girmeyin."
        )
    if hidden_or_spy_aps:
        recommendations.append(
            "🔍 Oda içinde güçlü sinyal veren Gizli SSID / SoftAP vericisini Geiger Sayacı ile tarayın; casus kameralar genellikle 2.4 GHz bandında gizli ağ açar."
        )
    if trackers:
        recommendations.append(
            "📍 Çevredeki takip etiketinin çantanızda veya eşyalarınızda olup olmadığını anlamak için cihaz kartından 'Sahibinden Uzak' durumunu kontrol edin."
        )
    if close_stationary:
        recommendations.append(
            "📌 Odada yakın mesafede sürekli sabit (📌) sinyal yayan cihazları aşağıdaki kartlardan inceleyin: size ait bir cihazsa '🏠 Benim Cihazım (Güvenli İşaretle)' butonuna basın; tanımadığınız bir cihazsa '🎯 Geiger ile Yerini Bul' ile odadaki yerini tespit edin."
        )
    if not recommendations:
        recommendations.append(
            "✅ Oda ve yerel ağ şu an güvenli görünüyor. Gece uyurken üst menüden '🛡️ Bekçi Modu' ve '🗣️ Sesli Alarm' özelliğini açık bırakabilirsiniz."
        )

    await _broadcast_full_state()
    return {
        "verdict": verdict,
        "overall_risk_score": max_risk,
        "checks": checks,
        "suspicious_devices": suspicious_payload,
        "recommendations": recommendations,
    }


@app.get("/api/devices/{mac:path}")
async def get_device_detail(mac: str):
    dev_dict = db.get_device(mac)
    if not dev_dict:
        raise HTTPException(status_code=404, detail="Device not found")
    hunt = signal_hunter.evaluate(mac)
    return {
        "device": dev_dict,
        "sightings": dev_dict.get("sightings_history", []),
        "hunt": hunt,
    }


@app.get("/api/hunt/{mac:path}")
async def get_hunt_telemetry(mac: str):
    """Returns real-time Signal Hunt / Geiger Counter telemetry for a target MAC/UUID."""
    state = signal_hunter.evaluate(mac)
    dev_dict = db.get_device(mac)
    return {
        "hunt": state,
        "device": dev_dict,
    }


@app.get("/api/drones")
async def get_drones():
    devices = db.get_devices(limit=100, class_filter=DeviceClass.DRONE)
    return [d.model_dump(mode="json") for d in devices if d.drone_info]


@app.get("/api/alerts")
async def get_alerts(limit: int = Query(50, ge=1, le=200)):
    alerts = db.get_alerts(limit=limit)
    return [a.model_dump(mode="json") for a in alerts]


@app.post("/api/alerts/{alert_id}/ack")
async def ack_alert(alert_id: int):
    ok = db.acknowledge_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"id": alert_id, "acknowledged": True}


@app.get("/api/sits")
async def list_sits():
    sits = db.get_sits()
    return [s.model_dump(mode="json") for s in sits]


@app.post("/api/sits/start")
async def start_sit(req: Optional[SitStartRequest] = None):
    label = req.label if req and req.label else "Tactical Sit"
    sit = db.start_sit(name=label)
    return sit.model_dump(mode="json")


@app.post("/api/sits/{sit_id}/stop")
async def stop_sit(sit_id: int):
    sit = db.stop_sit(sit_id)
    if not sit:
        raise HTTPException(status_code=404, detail="Sit session not found")
    return sit.model_dump(mode="json")


@app.get("/api/sits/diff")
async def diff_sits(base_id: int = Query(...), target_id: int = Query(...)):
    diff = db.compare_sits(base_sit_id=base_id, target_sit_id=target_id)
    if not diff:
        raise HTTPException(status_code=404, detail="One or both Sit sessions not found")
    return diff


@app.get("/api/intel/debrief")
async def get_intel_debrief():
    stats = db.get_stats()
    alerts = db.get_alerts(limit=20)
    drones = [d.drone_info.model_dump(mode="json") for d in db.get_devices(class_filter=DeviceClass.DRONE) if d.drone_info]
    trackers = [d.model_dump(mode="json") for d in db.get_devices(class_filter=DeviceClass.TRACKER)]

    summary = {
        "total_devices": stats["total_devices"],
        "drones": drones,
        "trackers": trackers,
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }

    debrief_md = await asyncio.to_thread(ai_analyzer.generate_ai_debrief, summary)
    return {
        "debrief_markdown": debrief_md,
        "summary": summary,
    }


@app.get("/api/export/wigle")
async def export_wigle():
    devices = db.get_devices(limit=1000)
    csv_text = DataExporter.export_wigle_csv(devices)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=airsentinel-wigle.csv"},
    )


@app.get("/api/export/gpx")
async def export_gpx():
    devices = db.get_devices(limit=1000)
    gpx_text = DataExporter.export_gpx(devices)
    return Response(
        content=gpx_text,
        media_type="application/gpx+xml",
        headers={"Content-Disposition": "attachment; filename=airsentinel-tracks.gpx"},
    )


@app.get("/api/export/kml")
async def export_kml():
    devices = db.get_devices(limit=1000)
    kml_text = DataExporter.export_kml(devices)
    return Response(
        content=kml_text,
        media_type="application/vnd.google-earth.kml+xml",
        headers={"Content-Disposition": "attachment; filename=airsentinel-overlay.kml"},
    )


@app.get("/api/export/forensic-report")
async def export_forensic_report():
    """Exports a self-contained Turkish TSCM Forensic Evidence Report (HTML) with a SHA-256 integrity seal."""
    devices = db.get_devices(limit=1000)
    alerts = db.get_alerts(limit=100)
    html_text = DataExporter.export_forensic_report_html(devices, alerts)
    return Response(
        content=html_text,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=airsentinel-adli-kanit-raporu.html"},
    )


async def _broadcast_full_state():
    """Sends a full INITIAL_STATE refresh to all connected WebSocket clients."""
    await broadcast_ws({
        "type": "INITIAL_STATE",
        "data": {
            "stats": db.get_stats(),
            "sentry_mode": correlation_engine.sentry_mode,
            "alerts": [a.model_dump(mode="json") for a in db.get_alerts(limit=30)],
            "devices": [d.model_dump(mode="json") for d in db.get_devices(limit=250)],
        },
    })


@app.post("/api/reset")
async def reset_data():
    """Clears all discovered devices, sightings, alerts, and in-memory detector state on user request."""
    res = db.clear_data()
    correlation_engine.reset()
    await _broadcast_full_state()
    return {"status": "CLEARED", **res}


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    logger.info(f"WebSocket client connected. Total clients: {len(connected_clients)}")

    try:
        init_stats = db.get_stats()
        recent_alerts = [a.model_dump(mode="json") for a in db.get_alerts(limit=30)]
        active_devices = [d.model_dump(mode="json") for d in db.get_devices(limit=250)]

        await websocket.send_text(json.dumps({
            "type": "INITIAL_STATE",
            "data": {
                "stats": init_stats,
                "sentry_mode": correlation_engine.sentry_mode,
                "alerts": recent_alerts,
                "devices": active_devices,
            }
        }))

        while True:
            raw_msg = await websocket.receive_text()
            try:
                cmd = json.loads(raw_msg)
                if cmd.get("action") == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
            except Exception:
                pass

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected.")
    except Exception as e:
        logger.debug(f"WebSocket connection error: {e}")
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# Static Files & PWA Mount
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
