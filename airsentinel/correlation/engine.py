"""Correlation and Threat Analysis Engine.

Orchestrates radio observations, signature matching, protocol decoding,
attack detection, Signal Hunt telemetry, persistence, and real-time alert broadcasts.
"""
import logging
from time import monotonic
from typing import Callable, Coroutine, Dict, List

from airsentinel.correlation.flood_detector import FloodDetector
from airsentinel.correlation.hunt import signal_hunter
from airsentinel.correlation.tracker_detector import TrackerDetector
from airsentinel.models import (
    Alert,
    AlertLevel,
    DeviceClass,
    Observation,
    ThreatCategory,
    TrackedDevice,
)
from airsentinel.scanners.wifi_scanner import WifiScanner
from airsentinel.signatures.catalog import catalog
from airsentinel.signatures.decoder import AdvPayloadDecoder
from airsentinel.signatures.remote_id import RemoteIdParser
from airsentinel.storage.db import db

logger = logging.getLogger("airsentinel.correlation")

BroadcastCallback = Callable[[dict], Coroutine]


class CorrelationEngine:
    def __init__(self):
        self.flood_detector = FloodDetector()
        self.tracker_detector = TrackerDetector()
        self._broadcast_listeners: List[BroadcastCallback] = []
        self._known_drones: set[str] = set()
        self.sentry_mode: bool = False
        self.sentry_rssi_threshold: int = -58
        self._sentry_alerted: Dict[str, float] = {}
        self._camera_alerted: set[str] = set()
        self._ssid_security_map: Dict[str, tuple[str, str]] = {}
        self._evil_twin_alerted: set[str] = set()
        self._gateway_mac_baseline: Dict[str, str] = {}
        self._arp_mitm_alerted: set[str] = set()
        self._dns_hijack_alerted: set[str] = set()
        self._rf_baseline_history: Dict[str, List[int]] = {}
        self._rf_motion_alerted: Dict[str, float] = {}

    def reset(self):
        """Resets all in-memory correlation, alert deduplication, and signal hunter state."""
        self.flood_detector.reset()
        self.tracker_detector.reset()
        signal_hunter.reset()
        self._known_drones.clear()
        self._sentry_alerted.clear()
        self._camera_alerted.clear()
        self._ssid_security_map.clear()
        self._evil_twin_alerted.clear()
        self._gateway_mac_baseline.clear()
        self._arp_mitm_alerted.clear()
        self._dns_hijack_alerted.clear()
        self._rf_baseline_history.clear()
        self._rf_motion_alerted.clear()

    def register_broadcast_listener(self, cb: BroadcastCallback):
        self._broadcast_listeners.append(cb)

    async def _emit_alert(self, alert: Alert):
        """Records alert and notifies all subscribers."""
        alert_id = db.insert_alert(alert)
        alert.id = alert_id
        logger.warning(f"[{alert.level.value}] {alert.title}: {alert.description}")

        await self._broadcast({
            "type": "ALERT",
            "data": alert.model_dump(mode="json"),
        })

    async def _broadcast(self, message: dict):
        for listener in self._broadcast_listeners:
            try:
                await listener(message)
            except Exception as e:
                logger.error(f"Error in broadcast listener: {e}")

    def check_arp_table_anomalies(self, arp_peers: List[tuple[str, str, str]]) -> List[Dict[str, str]]:
        """Inspects ARP table for Gateway MAC changes and duplicate MAC addresses across multiple IPs (ARP Spoofing / MITM)."""
        anomalies: List[Dict[str, str]] = []
        mac_to_ips: Dict[str, List[str]] = {}

        for ip, mac, _ in arp_peers:
            if not mac or mac == "FF:FF:FF:FF:FF:FF":
                continue
            mac_to_ips.setdefault(mac, [])
            if ip not in mac_to_ips[mac]:
                mac_to_ips[mac].append(ip)

            if ip.endswith(".1"):
                prev_gw_mac = self._gateway_mac_baseline.get(ip)
                if prev_gw_mac and prev_gw_mac != mac:
                    anomalies.append({
                        "type": "GATEWAY_MAC_CHANGED",
                        "ip": ip,
                        "mac": mac,
                        "old_mac": prev_gw_mac,
                        "title": f"ARP Spoofing / MITM Saldırısı: Modem ({ip}) MAC Adresi Değişti!",
                        "description": (
                            f"Ağ geçidi ({ip}) daha önce {prev_gw_mac} adresindeyken aniden {mac} adresine geçti! "
                            f"Ağdaki bir saldırgan trafiğinizi dinliyor (Man-in-the-Middle) olabilir."
                        ),
                    })
                else:
                    self._gateway_mac_baseline[ip] = mac

        for mac, ips in mac_to_ips.items():
            if len(ips) >= 2:
                ips_str = ", ".join(sorted(ips))
                anomalies.append({
                    "type": "DUPLICATE_MAC_MITM",
                    "ip": ips[0],
                    "mac": mac,
                    "title": f"ARP Zehirleme (MITM) Tespiti: Aynı MAC ({mac}) Birden Fazla IP'de!",
                    "description": (
                        f"Yerel ağda {ips_str} IP adresleri aynı donanım kimliğini ({mac}) kullanıyor. "
                        f"Bu durum aktif bir ARP Spoofing / paket dinleme saldırısının en güçlü işaretidir."
                    ),
                })

        return anomalies

    async def process_arp_table(self, arp_peers: List[tuple[str, str, str]]) -> List[Dict[str, str]]:
        """Checks ARP table for MITM anomalies and emits CRITICAL alerts when detected."""
        anomalies = self.check_arp_table_anomalies(arp_peers)
        for anom in anomalies:
            dedup_key = f"{anom['type']}:{anom['mac']}:{anom['ip']}"
            if dedup_key not in self._arp_mitm_alerted:
                self._arp_mitm_alerted.add(dedup_key)
                alert = Alert(
                    level=AlertLevel.CRITICAL,
                    category=ThreatCategory.ARP_SPOOFING_MITM,
                    title=anom["title"],
                    description=anom["description"],
                    device_id=anom["mac"],
                    device_name=f"ARP MITM ({anom['ip']})",
                    device_class=DeviceClass.ATTACK_TOOL,
                    rssi=-45,
                    details=anom,
                )
                await self._emit_alert(alert)
        return anomalies

    async def process_dns_anomalies(self, anomalies: List[Dict[str, str]]) -> List[Alert]:
        """Emits CRITICAL DNS_HIJACK_MITM alerts when canary domains resolve to private/local IPs."""
        emitted: List[Alert] = []
        for anom in anomalies:
            if not anom:
                continue
            dedup_key = f"{anom.get('type')}:{anom.get('domain')}:{anom.get('ips')}"
            if dedup_key not in self._dns_hijack_alerted:
                self._dns_hijack_alerted.add(dedup_key)
                alert = Alert(
                    level=AlertLevel.CRITICAL,
                    category=ThreatCategory.DNS_HIJACK_MITM,
                    title=anom["title"],
                    description=anom["description"],
                    device_id=anom.get("ips", "DNS"),
                    device_name=f"DNS Hijack ({anom.get('domain')})",
                    device_class=DeviceClass.ATTACK_TOOL,
                    rssi=-45,
                    details=anom,
                )
                await self._emit_alert(alert)
                emitted.append(alert)
        return emitted

    @staticmethod
    def _extract_clean_ssid(name: str | None) -> str | None:
        if not name:
            return None
        s = name.strip()
        for prefix in ("Wi-Fi AP (", "Connected Gateway ("):
            if s.startswith(prefix) and s.endswith(")"):
                s = s[len(prefix) : -1].strip()
        if not s or any(
            g in s.lower()
            for g in ("gizli", "hidden", "unknown", "lan wireless peer", "gateway router", "ip kamera")
        ):
            return None
        return s

    async def process_observation(self, obs: Observation) -> TrackedDevice:
        """Processes an incoming radio observation through all correlation pipelines."""
        # 1. Signature Matching (9 rule kinds + disambiguation)
        if not obs.matched_signature:
            matched = catalog.match(
                radio=obs.radio,
                mac=obs.mac_or_uuid,
                name=obs.name,
                company_id=obs.company_id,
                service_uuids=obs.service_uuids,
                manufacturer_data_hex=obs.manufacturer_data_hex,
                service_data=obs.service_data,
                vendor_ie_ouis=obs.vendor_ie_ouis,
            )
            if matched:
                obs.matched_signature = matched

        # 1b. Hardware Silicon OUI Intelligence Lookup (Camera / IoT Chipsets)
        oui_intel = WifiScanner.lookup_oui_intel(obs.mac_or_uuid)
        if oui_intel:
            existing_labels = {
                f.get("label") for f in (obs.decoded_fields or []) if isinstance(f, dict)
            }
            if "Donanım Çip Üreticisi (OUI)" not in existing_labels:
                obs.decoded_fields = list(obs.decoded_fields or []) + [
                    {"label": "Donanım Çip Üreticisi (OUI)", "value": oui_intel}
                ]

        # 2. Deep BLE Advertisement Protocol Decoding (Apple Continuity, MS CDP, Fast Pair, etc.)
        analysis = AdvPayloadDecoder.analyze(
            company_id=obs.company_id,
            manufacturer_data_hex=obs.manufacturer_data_hex,
            service_data=obs.service_data,
            device_name=obs.name,
        )
        if analysis.fields:
            obs.decoded_fields = list(obs.decoded_fields or []) + [f.model_dump() for f in analysis.fields]
        if analysis.role_hint and not obs.role_hint:
            obs.role_hint = analysis.role_hint
        if analysis.inferred_name and not obs.name:
            obs.name = analysis.inferred_name
        if analysis.fingerprint_id and not obs.fingerprint_id:
            obs.fingerprint_id = analysis.fingerprint_id
        obs.is_pairing_popup = analysis.is_pairing_popup
        obs.pairing_family = analysis.pairing_family

        # 3. Drone Remote ID Parsing (Service Data 0xFFFA or Manufacturer Data)
        if not obs.drone_data:
            for suuid, sdata_hex in (obs.service_data or {}).items():
                if "fffa" in suuid.lower() and sdata_hex:
                    try:
                        drone = RemoteIdParser.parse_payload(bytes.fromhex(sdata_hex))
                        if drone:
                            obs.drone_data = drone
                            break
                    except ValueError:
                        pass
            if not obs.drone_data and "fffa" in [u.lower() for u in obs.service_uuids]:
                if obs.manufacturer_data_hex:
                    try:
                        raw_bytes = bytes.fromhex(obs.manufacturer_data_hex)
                        drone = RemoteIdParser.parse_payload(raw_bytes)
                        if drone:
                            obs.drone_data = drone
                    except ValueError:
                        pass

        # 4. Signal Hunt (Geiger Counter) Live RSSI Telemetry
        signal_hunter.record_sample(obs.mac_or_uuid, obs.rssi)

        # 5. Check Drone Appearance Alert
        if obs.drone_data or (obs.matched_signature and obs.matched_signature.device_class == DeviceClass.DRONE):
            drone_id = obs.drone_data.uas_id if obs.drone_data else obs.mac_or_uuid
            if drone_id not in self._known_drones:
                self._known_drones.add(drone_id)
                mfg = obs.drone_data.manufacturer if obs.drone_data else (
                    obs.matched_signature.fleet_name if obs.matched_signature else "Unknown"
                )
                alt_str = f" at {obs.drone_data.altitude_m}m altitude" if obs.drone_data and obs.drone_data.altitude_m else ""

                alert = Alert(
                    level=AlertLevel.HIGH,
                    category=ThreatCategory.DRONE_REMOTE_ID,
                    title=f"Unmanned Aircraft Detected ({mfg})",
                    description=f"Drone Remote ID broadcast detected ({drone_id}){alt_str}.",
                    device_id=obs.mac_or_uuid,
                    device_name=obs.name or f"{mfg} Drone",
                    device_class=DeviceClass.DRONE,
                    rssi=obs.rssi,
                    details=obs.drone_data.model_dump(mode="json") if obs.drone_data else {},
                )
                await self._emit_alert(alert)

        # 6. Check RF Flood Attacks (Flipper Zero / BLE spam / Wi-Fi storms)
        flood_alert = self.flood_detector.process_observation(obs)
        if flood_alert:
            await self._emit_alert(flood_alert)

        # 7. Check Persistent Tracker / Stalker Co-Travel
        tracker_alert = self.tracker_detector.process_observation(obs)
        if tracker_alert:
            await self._emit_alert(tracker_alert)

        # 8. Database Storage & Device Aggregation (with BLE MAC-rotation re-identification)
        tracked_dev = db.upsert_observation(obs)

        # 8b. Evil Twin / Rogue AP Detection (Encrypted SSID cloned as Open/Unencrypted AP)
        if obs.radio.value == "WIFI" and obs.decoded_fields:
            clean_ssid = self._extract_clean_ssid(obs.name)
            if clean_ssid:
                sec_val = None
                for df in obs.decoded_fields:
                    if isinstance(df, dict) and df.get("label") == "Wi-Fi Güvenliği":
                        sec_val = str(df.get("value", ""))
                        break
                if sec_val:
                    ssid_key = clean_ssid.lower()
                    is_encrypted = any(k in sec_val.upper() for k in ("WPA", "WEP", "ŞİFRELİ", "SAE"))
                    is_open = "AÇIK" in sec_val.upper() or "OPEN" in sec_val.upper()
                    prev_entry = self._ssid_security_map.get(ssid_key)
                    if prev_entry:
                        prev_bssid, prev_sec = prev_entry
                        dedup_et = f"{ssid_key}:{obs.mac_or_uuid}"
                        if prev_bssid != obs.mac_or_uuid and is_open and dedup_et not in self._evil_twin_alerted:
                            self._evil_twin_alerted.add(dedup_et)
                            et_alert = Alert(
                                level=AlertLevel.CRITICAL,
                                category=ThreatCategory.EVIL_TWIN_AP,
                                title=f"Sahte Baz İstasyonu (Evil Twin AP): {clean_ssid}",
                                description=(
                                    f"Normalde şifreli ({prev_sec}) olan '{clean_ssid}' Wi-Fi ağı, "
                                    f"farklı bir BSSID ({obs.mac_or_uuid}) üzerinden ŞİFRESİZ (AÇIK) olarak yayın yapıyor! "
                                    f"Araya girme (MITM / Wi-Fi Pineapple) saldırısı olabilir."
                                ),
                                device_id=obs.mac_or_uuid,
                                device_name=clean_ssid,
                                device_class=tracked_dev.device_class,
                                rssi=obs.rssi,
                                details={
                                    "ssid": clean_ssid,
                                    "legit_bssid": prev_bssid,
                                    "legit_security": prev_sec,
                                    "rogue_bssid": obs.mac_or_uuid,
                                    "rogue_security": sec_val,
                                },
                            )
                            await self._emit_alert(et_alert)
                            tracked_dev.is_threat = True
                            tracked_dev.threat_reason = et_alert.title
                            tracked_dev.risk_score = max(tracked_dev.risk_score, 95)
                    if is_encrypted and ssid_key not in self._ssid_security_map:
                        self._ssid_security_map[ssid_key] = (obs.mac_or_uuid, sec_val)

        # 9. Surveillance / Hidden Camera Stream Alert (RTSP / ONVIF / GoPro / Axon)
        if (
            tracked_dev.device_class == DeviceClass.SURVEILLANCE
            and not tracked_dev.is_trusted
            and tracked_dev.mac_or_uuid not in self._camera_alerted
        ):
            self._camera_alerted.add(tracked_dev.mac_or_uuid)
            cam_alert = Alert(
                level=AlertLevel.CRITICAL,
                category=ThreatCategory.SURVEILLANCE_CAMERA,
                title="Ağda / Çevrede Kamera Yayını Tespit Edildi",
                description=(
                    f"{tracked_dev.name or tracked_dev.mac_or_uuid} cihazında aktif kamera / "
                    f"görüntü akışı ({tracked_dev.role_hint or 'RTSP/ONVIF'}) tespit edildi."
                ),
                device_id=tracked_dev.mac_or_uuid,
                device_name=tracked_dev.name or "Kamera Cihazı",
                device_class=DeviceClass.SURVEILLANCE,
                rssi=obs.rssi,
            )
            await self._emit_alert(cam_alert)
            tracked_dev.is_threat = True
            tracked_dev.threat_reason = cam_alert.title
            tracked_dev.risk_score = max(tracked_dev.risk_score, 85)

        # 10. Sentry Mode (Bekçi Modu): Alert on close-range untrusted non-infrastructure devices
        if (
            self.sentry_mode
            and not tracked_dev.is_trusted
            and tracked_dev.device_class != DeviceClass.INFRASTRUCTURE
            and obs.rssi >= self.sentry_rssi_threshold
        ):
            now_mono = monotonic()
            dedup_key = tracked_dev.fingerprint_id or tracked_dev.mac_or_uuid
            last_al = self._sentry_alerted.get(dedup_key, 0.0)
            if (now_mono - last_al) >= 300.0:
                self._sentry_alerted[dedup_key] = now_mono
                dev_label = tracked_dev.name or tracked_dev.matched_fleet or tracked_dev.mac_or_uuid
                sentry_alert = Alert(
                    level=AlertLevel.HIGH,
                    category=ThreatCategory.INTRUDER_PROXIMITY,
                    title="Bekçi Modu: Yakında Yabancı Cihaz Algılandı",
                    description=(
                        f"Ev halkı (güvenli) listesinde olmayan bir cihaz ({dev_label}) "
                        f"çok yakın mesafede ({obs.rssi} dBm) tespit edildi."
                    ),
                    device_id=tracked_dev.mac_or_uuid,
                    device_name=dev_label,
                    device_class=tracked_dev.device_class,
                    rssi=obs.rssi,
                )
                await self._emit_alert(sentry_alert)
                tracked_dev.is_threat = True
                tracked_dev.threat_reason = sentry_alert.title
                tracked_dev.risk_score = max(tracked_dev.risk_score, 85)

        # 10b. Sentry Mode RF Body-Shadowing (Airplane-Mode Intruder Physical Motion Detection)
        prior_samples = self._rf_baseline_history.get(obs.mac_or_uuid, [])
        if self.sentry_mode and len(prior_samples) >= 4:
            window = prior_samples[-5:]
            prior_mean = sum(window) / len(window)
            prior_std = (sum((x - prior_mean) ** 2 for x in window) / len(window)) ** 0.5
            delta_db = abs(obs.rssi - prior_mean)
            if prior_std <= 2.5 and delta_db >= 12.0:
                now_mono = monotonic()
                last_m = self._rf_motion_alerted.get(obs.mac_or_uuid, 0.0)
                if (now_mono - last_m) >= 60.0:
                    self._rf_motion_alerted[obs.mac_or_uuid] = now_mono
                    dev_label = tracked_dev.name or obs.mac_or_uuid
                    motion_alert = Alert(
                        level=AlertLevel.HIGH,
                        category=ThreatCategory.RF_PRESENCE_MOTION,
                        title="Bekçi Modu: Fiziksel Hareket / RF Sinyal Gölgeleme Algılandı",
                        description=(
                            f"Odadaki sabit referans sinyalinde ({dev_label}) aniden {delta_db:.1f} dB "
                            f"kırılma ({prior_mean:.0f} dBm -> {obs.rssi} dBm) yaşandı! "
                            f"Uçak modunda (cihazsız) bir kişinin odada hareket ederek RF dalgalarını perdelediği değerlendiriliyor."
                        ),
                        device_id=tracked_dev.mac_or_uuid,
                        device_name=dev_label,
                        device_class=tracked_dev.device_class,
                        rssi=obs.rssi,
                        details={"prior_mean_dbm": round(prior_mean, 1), "current_dbm": obs.rssi, "delta_db": round(delta_db, 1)},
                    )
                    await self._emit_alert(motion_alert)

        hist = self._rf_baseline_history.setdefault(obs.mac_or_uuid, [])
        hist.append(obs.rssi)
        if len(hist) > 10:
            del hist[:-10]

        # 11. Real-Time WebSocket Telemetry Broadcast
        await self._broadcast({
            "type": "OBSERVATION",
            "data": tracked_dev.model_dump(mode="json"),
        })

        return tracked_dev


# Singleton instance
correlation_engine = CorrelationEngine()
