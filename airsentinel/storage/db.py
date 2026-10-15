"""SQLite persistence layer with WAL mode, Forensic Device Storage, and Sit / SitDiff Sessions."""
import json
import logging
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from airsentinel.config import settings
from airsentinel.models import (
    Alert,
    AlertLevel,
    DeviceClass,
    DroneRemoteID,
    Observation,
    RadioType,
    SitSession,
    ThreatCategory,
    TrackedDevice,
)

logger = logging.getLogger("airsentinel.storage")


class Database:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self):
        """Initializes tables, safe column migrations, and indexes."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac_or_uuid TEXT PRIMARY KEY,
                    radio TEXT NOT NULL,
                    name TEXT,
                    device_class TEXT NOT NULL,
                    matched_fleet TEXT,
                    all_fleets_json TEXT,
                    role_hint TEXT,
                    decoded_fields_json TEXT,
                    channel_or_freq TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1,
                    last_rssi INTEGER NOT NULL,
                    avg_rssi REAL NOT NULL,
                    drone_info_json TEXT,
                    is_threat INTEGER NOT NULL DEFAULT 0,
                    threat_reason TEXT,
                    is_bookmarked INTEGER NOT NULL DEFAULT 0,
                    is_trusted INTEGER NOT NULL DEFAULT 0,
                    fingerprint_id TEXT,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_reasons_json TEXT,
                    mobility_profile TEXT,
                    estimated_distance_m REAL
                );

                CREATE TABLE IF NOT EXISTS sightings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac_or_uuid TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    rssi INTEGER NOT NULL,
                    radio TEXT NOT NULL,
                    details_json TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    device_id TEXT,
                    device_name TEXT,
                    device_class TEXT NOT NULL,
                    rssi INTEGER,
                    details_json TEXT,
                    acknowledged INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS sits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    notes TEXT DEFAULT '',
                    snapshot_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
                CREATE INDEX IF NOT EXISTS idx_devices_class ON devices(device_class);
                CREATE INDEX IF NOT EXISTS idx_sightings_mac ON sightings(mac_or_uuid);
                CREATE INDEX IF NOT EXISTS idx_sightings_ts ON sightings(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
            """)
            # Safe migrations for pre-existing SQLite databases
            existing_cols = {
                row["name"] for row in conn.execute("PRAGMA table_info(devices)").fetchall()
            }
            migrations = [
                ("risk_score", "INTEGER NOT NULL DEFAULT 0"),
                ("risk_reasons_json", "TEXT"),
                ("mobility_profile", "TEXT"),
                ("estimated_distance_m", "REAL"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def}")

    @staticmethod
    def _estimate_distance_m(rssi: int, tx_power: Optional[int], radio: RadioType) -> float:
        """Estimates indoor distance in meters using the log-distance path loss model."""
        ref_power = tx_power if (tx_power is not None and -80 <= tx_power <= -20) else (
            -45 if radio == RadioType.WIFI else -59
        )
        path_loss_exp = 2.4
        raw_dist = 10.0 ** ((ref_power - float(rssi)) / (10.0 * path_loss_exp))
        return round(max(0.2, min(80.0, raw_dist)), 1)

    @staticmethod
    def _compute_mobility_profile(recent_rssis: List[int]) -> Optional[str]:
        """Classifies physical device stationarity vs movement from RSSI variance."""
        if len(recent_rssis) < 4:
            return None
        mean_val = sum(recent_rssis) / len(recent_rssis)
        variance = sum((x - mean_val) ** 2 for x in recent_rssis) / len(recent_rssis)
        std_dev = math.sqrt(variance)
        if std_dev <= 2.5:
            return "📌 Sabit / Yerleştirilmiş Cihaz"
        if std_dev >= 5.0:
            return "🚶 Hareketli / Geçici Cihaz"
        return "⚖️ Yarı-Sabit / Oda İçi"

    @staticmethod
    def _compute_risk_assessment(
        dev_class: DeviceClass,
        role_hint: Optional[str],
        decoded_fields: List[Dict[str, Any]],
        is_trusted: bool,
        is_threat: bool,
        threat_reason: Optional[str],
        last_rssi: int,
        mobility_profile: Optional[str],
    ) -> Tuple[int, List[str]]:
        """Computes a 0..100 multi-factor forensic risk score and human-readable Turkish reasons."""
        if is_trusted:
            return 0, ["Güvenli Liste (Ev Halkı)"]

        score = 0
        reasons: List[str] = []

        if dev_class == DeviceClass.SURVEILLANCE:
            score += 60
            reasons.append("Gözetleme / Kamera Sınıfı Cihaz")
        elif dev_class == DeviceClass.DRONE:
            score += 50
            reasons.append("İnsansız Hava Aracı (Drone)")
        elif dev_class == DeviceClass.TRACKER:
            score += 40
            reasons.append("Konum Takip Cihazı (AirTag / SmartTag / Tile)")

        fields_blob = " ".join(
            f"{f.get('label', '')} {f.get('value', '')}"
            for f in decoded_fields
            if isinstance(f, dict)
        ).lower()
        rh_lower = (role_hint or "").lower()

        if any(k in fields_blob or k in rh_lower for k in ("rtsp", "onvif", "açık kamera portu", "ağ kamerası", "spycam", "casus kamera ağı")):
            score += 25
            reasons.append("Ağda Açık Kamera / Video Portu veya SpyCam Yayını")

        if any(k in fields_blob or k in rh_lower for k in ("gizli ssid uyarısı", "ismini gizleyen wi-fi")):
            score += 40
            reasons.append("Oda İçi Gizli (İsimsiz) Wi-Fi Vericisi")

        if "donanım çip üreticisi (oui)" in fields_blob and any(
            k in fields_blob for k in ("kamera", "bilian", "espressif", "hisilicon", "tuya", "reolink", "wyze")
        ):
            score += 30
            reasons.append("Gizli Kamera / IoT Radyo Çipi Üreticisi (OUI)")

        if "hid klavye/fare" in fields_blob:
            score += 35
            reasons.append("Bluetooth HID Klavye/Fare Enjeksiyon Riski")

        if any(k in fields_blob for k in ("separated", "sahibinden uzak")):
            score += 30
            reasons.append("Sahibinden Uzak / Başıboş Takip Cihazı")

        if "açık (şifresiz ağ)" in fields_blob:
            score += 20
            reasons.append("Şifresiz (Açık) Wi-Fi Yayını")

        if (
            mobility_profile
            and "Sabit" in mobility_profile
            and dev_class in (DeviceClass.SURVEILLANCE, DeviceClass.TRACKER, DeviceClass.IOT, DeviceClass.UNKNOWN)
            and last_rssi >= -68
        ):
            score += 15
            reasons.append("Oda İçinde Sabit Sinyal (Yerleştirilmiş Cihaz Profili)")

        if last_rssi >= -50 and dev_class != DeviceClass.INFRASTRUCTURE:
            score += 10
            reasons.append("Çok Yakın Mesafe Sinyali (< 2m)")

        if is_threat:
            score = max(score, 85)
            if threat_reason and threat_reason not in reasons:
                reasons.insert(0, threat_reason)

        return min(100, score), reasons

    def upsert_observation(self, obs: Observation) -> TrackedDevice:
        """Updates device aggregation record, performs BLE MAC-rotation re-identification, and records sighting."""
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        dev_class = DeviceClass.UNKNOWN
        fleet_name = None
        all_fleets: List[str] = []
        if obs.matched_signature:
            dev_class = obs.matched_signature.device_class
            fleet_name = obs.matched_signature.fleet_name
            all_fleets = obs.matched_signature.all_fleets or [fleet_name]
        elif obs.drone_data:
            dev_class = DeviceClass.DRONE
            fleet_name = f"Drone ({obs.drone_data.manufacturer})"
            all_fleets = [fleet_name]

        role_hint = obs.role_hint
        nm_lower = (obs.name or "").lower()
        if any(k in nm_lower for k in ("macbook", "mac-mini", "macmini", "imac", "mac-pro", "macstudio")):
            dev_class = DeviceClass.PC
        if dev_class == DeviceClass.UNKNOWN:
            if obs.radio == RadioType.WIFI:
                nm = (obs.name or "")
                if (
                    nm.startswith("Wi-Fi AP")
                    or nm.startswith("Connected Gateway")
                    or nm.startswith("Gateway Router")
                    or obs.mac_or_uuid.startswith("00:57:46:")
                ):
                    dev_class = DeviceClass.INFRASTRUCTURE
                    fleet_name = fleet_name or "Wi-Fi Access Point"
                elif role_hint and ("kamera" in role_hint.lower() or "rtsp" in role_hint.lower() or "onvif" in role_hint.lower()):
                    dev_class = DeviceClass.SURVEILLANCE
                    fleet_name = fleet_name or "Network IP Camera (RTSP)"
                elif any(k in nm.lower() for k in ("macbook", "mac-mini", "macmini", "imac", "mac-pro", "macstudio", "desktop", "laptop")):
                    dev_class = DeviceClass.PC
                    fleet_name = fleet_name or "Apple Mac / Bilgisayar"
                elif nm.startswith("LAN Wireless Peer") or (role_hint and "yerel ağ" in role_hint.lower()):
                    dev_class = DeviceClass.IOT
                    fleet_name = fleet_name or "LAN Wireless Device"
            elif role_hint:
                rh_lower = role_hint.lower()
                if any(k in rh_lower for k in ("airtag", "tracker", "find hub")):
                    dev_class = DeviceClass.TRACKER
                elif any(k in rh_lower for k in ("camera", "kamera", "rtsp", "onvif", "gopro", "axon")):
                    dev_class = DeviceClass.SURVEILLANCE
                elif any(k in rh_lower for k in ("windows", "desktop", "laptop")):
                    dev_class = DeviceClass.PC
                elif any(k in rh_lower for k in ("iphone", "ipad", "apple device")):
                    dev_class = DeviceClass.PHONE
                elif any(k in rh_lower for k in ("airpods", "beats", "watch", "buds")):
                    dev_class = DeviceClass.WEARABLE
                elif any(k in rh_lower for k in ("sensor", "ruuvi", "govee", "homekit", "tesla", "switchbot", "mibeacon")):
                    dev_class = DeviceClass.IOT

        drone_json = obs.drone_data.model_dump_json() if obs.drone_data else None
        decoded_fields = list(obs.decoded_fields or [])
        chan = obs.channel_or_freq
        fp_id = obs.fingerprint_id

        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM devices WHERE mac_or_uuid = ?", (obs.mac_or_uuid,)
            )
            existing = cursor.fetchone()

            # BLE Behavioral Fingerprinting & MAC-Rotation Re-Identification
            if not existing and obs.radio == RadioType.BLE and fp_id:
                candidates = conn.execute(
                    "SELECT * FROM devices WHERE radio = 'BLE' AND fingerprint_id = ? ORDER BY last_seen DESC LIMIT 5",
                    (fp_id,),
                ).fetchall()
                for cand in candidates:
                    try:
                        cand_last = datetime.fromisoformat(cand["last_seen"])
                        idle_sec = (now_dt - cand_last).total_seconds()
                    except Exception:
                        idle_sec = 0.0
                    is_strong = fp_id.startswith("fp-strong:")
                    rssi_diff = abs(int(cand["last_rssi"]) - obs.rssi)
                    if (is_strong and idle_sec <= 1800.0) or (
                        not is_strong and 4.0 <= idle_sec <= 1500.0 and rssi_diff <= 10
                    ):
                        old_mac = cand["mac_or_uuid"]
                        conn.execute(
                            "UPDATE devices SET mac_or_uuid = ? WHERE mac_or_uuid = ?",
                            (obs.mac_or_uuid, old_mac),
                        )
                        conn.execute(
                            "UPDATE sightings SET mac_or_uuid = ? WHERE mac_or_uuid = ?",
                            (obs.mac_or_uuid, old_mac),
                        )
                        decoded_fields.append(
                            {
                                "label": "MAC Rotasyonu",
                                "value": f"Önceki kimlik ({old_mac[:8]}…) ile birleştirildi",
                            }
                        )
                        existing = conn.execute(
                            "SELECT * FROM devices WHERE mac_or_uuid = ?", (obs.mac_or_uuid,)
                        ).fetchone()
                        break

            # Fetch recent sightings to compute RSSI variance for mobility profiling
            prev_sightings = conn.execute(
                "SELECT rssi FROM sightings WHERE mac_or_uuid = ? ORDER BY id DESC LIMIT 9",
                (obs.mac_or_uuid,),
            ).fetchall()
            recent_rssis = [int(r["rssi"]) for r in prev_sightings] + [obs.rssi]
            mobility_profile = self._compute_mobility_profile(recent_rssis)
            estimated_distance_m = self._estimate_distance_m(obs.rssi, obs.tx_power, obs.radio)

            if existing:
                hit_count = existing["hit_count"] + 1
                new_avg_rssi = (existing["avg_rssi"] * (hit_count - 1) + obs.rssi) / hit_count

                name = obs.name or existing["name"]
                prev_class = DeviceClass(existing["device_class"])
                if dev_class == DeviceClass.UNKNOWN:
                    dev_class = prev_class
                elif prev_class == DeviceClass.PHONE and dev_class == DeviceClass.TRACKER:
                    # An active iPhone/iPad/Mac that already emitted Continuity (0x10/0x05/0x0C)
                    # also emits 0x12 Find My frames; never downgrade it to an AirTag tracker.
                    dev_class = DeviceClass.PHONE
                    fleet_name = existing["matched_fleet"] or "Apple Device"
                    role_hint = existing["role_hint"] or "iPhone / iPad / Mac"

                if not fleet_name:
                    fleet_name = existing["matched_fleet"]
                if not all_fleets and existing["all_fleets_json"]:
                    try:
                        all_fleets = json.loads(existing["all_fleets_json"])
                    except Exception:
                        all_fleets = [fleet_name] if fleet_name else []
                if not role_hint or (
                    existing["role_hint"]
                    and "iPhone" in existing["role_hint"]
                    and role_hint == "Apple AirTag / Find My Tracker"
                ):
                    role_hint = existing["role_hint"]

                # Merge decoded_fields by label so alternating BLE frames enrich rather than overwrite
                prev_fields = []
                if existing["decoded_fields_json"]:
                    try:
                        prev_fields = json.loads(existing["decoded_fields_json"])
                    except Exception:
                        prev_fields = []
                if decoded_fields and prev_fields:
                    merged_map = {
                        (f.get("label") if isinstance(f, dict) else str(f)): f
                        for f in prev_fields
                    }
                    for nf in decoded_fields:
                        lbl = nf.get("label") if isinstance(nf, dict) else str(nf)
                        merged_map[lbl] = nf
                    decoded_fields = list(merged_map.values())[-8:]
                elif not decoded_fields:
                    decoded_fields = prev_fields

                if not chan:
                    chan = existing["channel_or_freq"]
                if not drone_json:
                    drone_json = existing["drone_info_json"]
                if not fp_id:
                    fp_id = existing["fingerprint_id"]
                if not mobility_profile:
                    mobility_profile = existing["mobility_profile"]

                is_threat = bool(existing["is_threat"])
                threat_reason = existing["threat_reason"]
                is_bookmarked = bool(existing["is_bookmarked"])
                is_trusted = bool(existing["is_trusted"])

                risk_score, risk_reasons = self._compute_risk_assessment(
                    dev_class=dev_class,
                    role_hint=role_hint,
                    decoded_fields=decoded_fields,
                    is_trusted=is_trusted,
                    is_threat=is_threat,
                    threat_reason=threat_reason,
                    last_rssi=obs.rssi,
                    mobility_profile=mobility_profile,
                )

                conn.execute(
                    """
                    UPDATE devices SET
                        name = ?,
                        device_class = ?,
                        matched_fleet = ?,
                        all_fleets_json = ?,
                        role_hint = ?,
                        decoded_fields_json = ?,
                        channel_or_freq = ?,
                        last_seen = ?,
                        hit_count = ?,
                        last_rssi = ?,
                        avg_rssi = ?,
                        drone_info_json = ?,
                        fingerprint_id = ?,
                        risk_score = ?,
                        risk_reasons_json = ?,
                        mobility_profile = ?,
                        estimated_distance_m = ?
                    WHERE mac_or_uuid = ?
                    """,
                    (
                        name,
                        dev_class.value,
                        fleet_name,
                        json.dumps(all_fleets),
                        role_hint,
                        json.dumps(decoded_fields),
                        chan,
                        now_iso,
                        hit_count,
                        obs.rssi,
                        round(new_avg_rssi, 1),
                        drone_json,
                        fp_id,
                        risk_score,
                        json.dumps(risk_reasons),
                        mobility_profile,
                        estimated_distance_m,
                        obs.mac_or_uuid,
                    ),
                )
                first_seen = datetime.fromisoformat(existing["first_seen"])
            else:
                hit_count = 1
                new_avg_rssi = float(obs.rssi)
                first_seen = now_dt
                name = obs.name
                is_threat = False
                threat_reason = None
                is_bookmarked = False
                is_trusted = False
                risk_score, risk_reasons = self._compute_risk_assessment(
                    dev_class=dev_class,
                    role_hint=role_hint,
                    decoded_fields=decoded_fields,
                    is_trusted=is_trusted,
                    is_threat=is_threat,
                    threat_reason=threat_reason,
                    last_rssi=obs.rssi,
                    mobility_profile=mobility_profile,
                )
                conn.execute(
                    """
                    INSERT INTO devices (
                        mac_or_uuid, radio, name, device_class, matched_fleet,
                        all_fleets_json, role_hint, decoded_fields_json, channel_or_freq,
                        first_seen, last_seen, hit_count, last_rssi, avg_rssi,
                        drone_info_json, is_threat, threat_reason, is_bookmarked, is_trusted,
                        fingerprint_id, risk_score, risk_reasons_json, mobility_profile, estimated_distance_m
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, 0, 0, ?, ?, ?, ?, ?)
                    """,
                    (
                        obs.mac_or_uuid,
                        obs.radio.value,
                        name,
                        dev_class.value,
                        fleet_name,
                        json.dumps(all_fleets),
                        role_hint,
                        json.dumps(decoded_fields),
                        chan,
                        now_iso,
                        now_iso,
                        hit_count,
                        obs.rssi,
                        round(new_avg_rssi, 1),
                        drone_json,
                        fp_id,
                        risk_score,
                        json.dumps(risk_reasons),
                        mobility_profile,
                        estimated_distance_m,
                    ),
                )

            # Insert sighting
            details = {
                "channel_or_freq": chan,
                "company_id": obs.company_id,
                "service_uuids": obs.service_uuids,
                "role_hint": role_hint,
            }
            cur_s = conn.execute(
                """
                INSERT INTO sightings (mac_or_uuid, timestamp, rssi, radio, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (obs.mac_or_uuid, now_iso, obs.rssi, obs.radio.value, json.dumps(details)),
            )

            # Every 100 sightings, prune rotated/stale unbookmarked & untrusted devices (>10m old) and old sightings (>20m old)
            if cur_s.lastrowid and (cur_s.lastrowid % 100 == 0):
                stale_dev_cutoff = (now_dt - timedelta(minutes=10)).isoformat()
                stale_sight_cutoff = (now_dt - timedelta(minutes=20)).isoformat()
                conn.execute(
                    "DELETE FROM devices WHERE is_bookmarked = 0 AND is_trusted = 0 AND is_threat = 0 AND last_seen < ?",
                    (stale_dev_cutoff,),
                )
                conn.execute(
                    "DELETE FROM sightings WHERE timestamp < ?",
                    (stale_sight_cutoff,),
                )

        drone_obj = obs.drone_data
        if not drone_obj and drone_json:
            try:
                drone_obj = DroneRemoteID.model_validate_json(drone_json)
            except Exception:
                drone_obj = None

        return TrackedDevice(
            mac_or_uuid=obs.mac_or_uuid,
            radio=obs.radio,
            name=name,
            device_class=dev_class,
            matched_fleet=fleet_name,
            all_fleets=all_fleets,
            role_hint=role_hint,
            decoded_fields=decoded_fields,
            channel_or_freq=chan,
            first_seen=first_seen,
            last_seen=now_dt,
            hit_count=hit_count,
            last_rssi=obs.rssi,
            avg_rssi=round(new_avg_rssi, 1),
            drone_info=drone_obj,
            is_threat=is_threat,
            threat_reason=threat_reason,
            is_bookmarked=is_bookmarked,
            is_trusted=is_trusted,
            fingerprint_id=fp_id,
            risk_score=risk_score,
            risk_reasons=risk_reasons,
            mobility_profile=mobility_profile,
            estimated_distance_m=estimated_distance_m,
        )

    def _row_to_device(self, r: sqlite3.Row) -> TrackedDevice:
        drone_info = None
        if r["drone_info_json"]:
            try:
                drone_info = DroneRemoteID.model_validate_json(r["drone_info_json"])
            except Exception:
                pass

        all_fleets = []
        if r["all_fleets_json"]:
            try:
                all_fleets = json.loads(r["all_fleets_json"])
            except Exception:
                pass

        decoded_fields = []
        if r["decoded_fields_json"]:
            try:
                decoded_fields = json.loads(r["decoded_fields_json"])
            except Exception:
                pass

        risk_reasons = []
        if "risk_reasons_json" in r.keys() and r["risk_reasons_json"]:
            try:
                risk_reasons = json.loads(r["risk_reasons_json"])
            except Exception:
                pass

        return TrackedDevice(
            mac_or_uuid=r["mac_or_uuid"],
            radio=RadioType(r["radio"]),
            name=r["name"],
            device_class=DeviceClass(r["device_class"]),
            matched_fleet=r["matched_fleet"],
            all_fleets=all_fleets,
            role_hint=r["role_hint"],
            decoded_fields=decoded_fields,
            channel_or_freq=r["channel_or_freq"],
            first_seen=datetime.fromisoformat(r["first_seen"]),
            last_seen=datetime.fromisoformat(r["last_seen"]),
            hit_count=r["hit_count"],
            last_rssi=r["last_rssi"],
            avg_rssi=r["avg_rssi"],
            drone_info=drone_info,
            is_threat=bool(r["is_threat"]),
            threat_reason=r["threat_reason"],
            is_bookmarked=bool(r["is_bookmarked"]),
            is_trusted=bool(r["is_trusted"]),
            fingerprint_id=r["fingerprint_id"],
            risk_score=int(r["risk_score"]) if "risk_score" in r.keys() and r["risk_score"] is not None else 0,
            risk_reasons=risk_reasons,
            mobility_profile=r["mobility_profile"] if "mobility_profile" in r.keys() else None,
            estimated_distance_m=float(r["estimated_distance_m"]) if "estimated_distance_m" in r.keys() and r["estimated_distance_m"] is not None else None,
        )

    def get_device(self, mac_or_uuid: str) -> Optional[Dict[str, Any]]:
        """Fetches a single device along with its recent RSSI sighting history."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE mac_or_uuid = ?", (mac_or_uuid,)
            ).fetchone()
            if not row:
                return None
            dev = self._row_to_device(row)
            s_rows = conn.execute(
                "SELECT timestamp, rssi FROM sightings WHERE mac_or_uuid = ? ORDER BY id DESC LIMIT 40",
                (mac_or_uuid,),
            ).fetchall()
            history = [{"timestamp": s["timestamp"], "rssi": s["rssi"]} for s in reversed(s_rows)]
            out = dev.model_dump(mode="json")
            out["sightings_history"] = history
            return out

    def toggle_bookmark(self, mac_or_uuid: str) -> Optional[bool]:
        """Toggles the bookmarked/watchlist flag for a device."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT is_bookmarked FROM devices WHERE mac_or_uuid = ?", (mac_or_uuid,)
            ).fetchone()
            if not row:
                return None
            new_val = 0 if row["is_bookmarked"] else 1
            conn.execute(
                "UPDATE devices SET is_bookmarked = ? WHERE mac_or_uuid = ?",
                (new_val, mac_or_uuid),
            )
            return bool(new_val)

    def toggle_trust(self, mac_or_uuid: str) -> Optional[bool]:
        """Toggles the trusted household (Ev Halkı / Beyaz Liste) flag for a device."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT is_trusted FROM devices WHERE mac_or_uuid = ?", (mac_or_uuid,)
            ).fetchone()
            if not row:
                return None
            new_val = 0 if row["is_trusted"] else 1
            conn.execute(
                "UPDATE devices SET is_trusted = ?, is_threat = CASE WHEN ? = 1 THEN 0 ELSE is_threat END WHERE mac_or_uuid = ?",
                (new_val, new_val, mac_or_uuid),
            )
            return bool(new_val)

    def trust_all_current_devices(self, active_within_seconds: int = 180) -> int:
        """Marks all currently active non-threat devices as trusted household devices."""
        cutoff_iso = (
            datetime.now(timezone.utc) - timedelta(seconds=active_within_seconds)
        ).isoformat()
        with self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE devices SET is_trusted = 1 WHERE last_seen >= ? AND is_threat = 0",
                (cutoff_iso,),
            )
            return cur.rowcount

    def update_gatt_profile(
        self,
        mac_or_uuid: str,
        name: Optional[str] = None,
        role_hint: Optional[str] = None,
        gatt_fields: Optional[List[Dict[str, str]]] = None,
    ) -> Optional[TrackedDevice]:
        """Enriches a BLE device record with active GATT interrogation results."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE mac_or_uuid = ?", (mac_or_uuid,)
            ).fetchone()
            if not row:
                return None

            new_name = name or row["name"]
            new_role = role_hint or row["role_hint"]
            prev_fields = []
            if row["decoded_fields_json"]:
                try:
                    prev_fields = json.loads(row["decoded_fields_json"])
                except Exception:
                    prev_fields = []

            merged_map = {
                (f.get("label") if isinstance(f, dict) else str(f)): f
                for f in prev_fields
            }
            for nf in (gatt_fields or []):
                lbl = nf.get("label") if isinstance(nf, dict) else str(nf)
                merged_map[lbl] = nf
            merged_fields = list(merged_map.values())[-7:]

            conn.execute(
                """
                UPDATE devices SET
                    name = ?,
                    role_hint = ?,
                    decoded_fields_json = ?
                WHERE mac_or_uuid = ?
                """,
                (new_name, new_role, json.dumps(merged_fields), mac_or_uuid),
            )
            updated_row = conn.execute(
                "SELECT * FROM devices WHERE mac_or_uuid = ?", (mac_or_uuid,)
            ).fetchone()
            return self._row_to_device(updated_row) if updated_row else None

    def insert_alert(self, alert: Alert) -> int:
        """Stores a generated threat alert."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, level, category, title, description,
                    device_id, device_name, device_class, rssi, details_json, acknowledged
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    alert.timestamp.isoformat(),
                    alert.level.value,
                    alert.category.value,
                    alert.title,
                    alert.description,
                    alert.device_id,
                    alert.device_name,
                    alert.device_class.value,
                    alert.rssi,
                    json.dumps(alert.details),
                ),
            )
            alert_id = cursor.lastrowid

            if alert.level in (AlertLevel.HIGH, AlertLevel.CRITICAL) and alert.device_id:
                conn.execute(
                    "UPDATE devices SET is_threat = 1, threat_reason = ? WHERE mac_or_uuid = ?",
                    (alert.title, alert.device_id),
                )

            return alert_id

    def acknowledge_alert(self, alert_id: int) -> bool:
        with self._get_connection() as conn:
            cur = conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            return cur.rowcount > 0

    def get_devices(
        self,
        limit: int = 200,
        class_filter: Optional[DeviceClass] = None,
        bookmarked_only: bool = False,
        active_within_seconds: Optional[int] = 180,
    ) -> List[TrackedDevice]:
        """Fetches active devices ordered by last seen."""
        query = "SELECT * FROM devices"
        clauses = []
        params: List[Any] = []
        if active_within_seconds is not None and not bookmarked_only:
            cutoff_iso = (
                datetime.now(timezone.utc) - timedelta(seconds=active_within_seconds)
            ).isoformat()
            clauses.append("(last_seen >= ? OR is_bookmarked = 1 OR is_trusted = 1 OR is_threat = 1)")
            params.append(cutoff_iso)
        if class_filter:
            clauses.append("device_class = ?")
            params.append(class_filter.value)
        if bookmarked_only:
            clauses.append("is_bookmarked = 1")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_device(r) for r in rows]

    def get_alerts(self, limit: int = 50) -> List[Alert]:
        """Fetches recent security alerts."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            alerts = []
            for r in rows:
                details = json.loads(r["details_json"]) if r["details_json"] else {}
                alerts.append(
                    Alert(
                        id=r["id"],
                        timestamp=datetime.fromisoformat(r["timestamp"]),
                        level=AlertLevel(r["level"]),
                        category=ThreatCategory(r["category"]),
                        title=r["title"],
                        description=r["description"],
                        device_id=r["device_id"],
                        device_name=r["device_name"],
                        device_class=DeviceClass(r["device_class"]),
                        rssi=r["rssi"],
                        details=details,
                        acknowledged=bool(r["acknowledged"]),
                    )
                )
            return alerts

    def get_stats(self, active_within_seconds: int = 180) -> Dict[str, Any]:
        """Returns overall radio landscape stats for currently active devices."""
        cutoff_iso = (
            datetime.now(timezone.utc) - timedelta(seconds=active_within_seconds)
        ).isoformat()
        active_clause = "(last_seen >= ? OR is_bookmarked = 1 OR is_trusted = 1 OR is_threat = 1)"
        with self._get_connection() as conn:
            total_devs = conn.execute(
                f"SELECT COUNT(*) FROM devices WHERE {active_clause}", (cutoff_iso,)
            ).fetchone()[0]
            drones = conn.execute(
                f"SELECT COUNT(*) FROM devices WHERE device_class = 'DRONE' AND {active_clause}",
                (cutoff_iso,),
            ).fetchone()[0]
            trackers = conn.execute(
                f"SELECT COUNT(*) FROM devices WHERE device_class = 'TRACKER' AND {active_clause}",
                (cutoff_iso,),
            ).fetchone()[0]
            threats = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE is_threat = 1"
            ).fetchone()[0]
            alerts_count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
            ).fetchone()[0]
            bookmarked = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE is_bookmarked = 1"
            ).fetchone()[0]
            trusted = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE is_trusted = 1"
            ).fetchone()[0]

            return {
                "total_devices": total_devs,
                "drones_count": drones,
                "trackers_count": trackers,
                "threats_count": threats,
                "alerts_count": alerts_count,
                "bookmarked_count": bookmarked,
                "trusted_count": trusted,
            }

    # --- Sit (Observation Session) & SitDiff Management ---
    def start_sit(self, name: str, notes: str = "") -> SitSession:
        """Starts a new observation Sit session, closing any currently active Sit."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        clean_name = (name or "").strip()[:40] or now.strftime("Sit %d %b %H:%M")

        current_devs = [d.model_dump(mode="json") for d in self.get_devices(limit=1000)]

        with self._get_connection() as conn:
            # Close any open sits with current device snapshot
            open_rows = conn.execute("SELECT id FROM sits WHERE is_active = 1").fetchall()
            for r in open_rows:
                conn.execute(
                    "UPDATE sits SET is_active = 0, end_time = ?, snapshot_json = ? WHERE id = ?",
                    (now_iso, json.dumps(current_devs), r["id"]),
                )

            cur = conn.execute(
                """
                INSERT INTO sits (name, start_time, end_time, is_active, notes, snapshot_json)
                VALUES (?, ?, NULL, 1, ?, ?)
                """,
                (clean_name, now_iso, notes, json.dumps(current_devs)),
            )
            sit_id = cur.lastrowid

        return SitSession(
            id=sit_id,
            name=clean_name,
            start_time=now,
            is_active=True,
            device_count=len(current_devs),
            notes=notes,
            snapshot_devices=current_devs,
        )

    def stop_sit(self, sit_id: int) -> Optional[SitSession]:
        """Closes an active Sit session and saves the final device snapshot."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        current_devs = [d.model_dump(mode="json") for d in self.get_devices(limit=1000)]

        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM sits WHERE id = ?", (sit_id,)).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE sits SET is_active = 0, end_time = ?, snapshot_json = ? WHERE id = ?",
                (now_iso, json.dumps(current_devs), sit_id),
            )
            return SitSession(
                id=sit_id,
                name=row["name"],
                start_time=datetime.fromisoformat(row["start_time"]),
                end_time=now,
                is_active=False,
                device_count=len(current_devs),
                notes=row["notes"] or "",
                snapshot_devices=current_devs,
            )

    def get_sits(self) -> List[SitSession]:
        """Lists all recorded Sit sessions."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM sits ORDER BY id DESC LIMIT 30").fetchall()
            out = []
            for r in rows:
                snap = json.loads(r["snapshot_json"]) if r["snapshot_json"] else []
                out.append(
                    SitSession(
                        id=r["id"],
                        name=r["name"],
                        start_time=datetime.fromisoformat(r["start_time"]),
                        end_time=datetime.fromisoformat(r["end_time"]) if r["end_time"] else None,
                        is_active=bool(r["is_active"]),
                        device_count=len(snap),
                        notes=r["notes"] or "",
                        snapshot_devices=snap,
                    )
                )
            return out

    def compare_sits(self, base_sit_id: int, target_sit_id: int) -> Optional[Dict[str, Any]]:
        """Compares two Sits (SitDiff): identifies newly arrived, gone, and persistent radios."""
        with self._get_connection() as conn:
            r_a = conn.execute("SELECT * FROM sits WHERE id = ?", (base_sit_id,)).fetchone()
            r_b = conn.execute("SELECT * FROM sits WHERE id = ?", (target_sit_id,)).fetchone()
            if not r_a or not r_b:
                return None

            snap_a = {d["mac_or_uuid"]: d for d in (json.loads(r_a["snapshot_json"]) if r_a["snapshot_json"] else [])}
            snap_b = {d["mac_or_uuid"]: d for d in (json.loads(r_b["snapshot_json"]) if r_b["snapshot_json"] else [])}

            keys_a = set(snap_a.keys())
            keys_b = set(snap_b.keys())

            new_keys = keys_b - keys_a
            gone_keys = keys_a - keys_b
            stayed_keys = keys_a & keys_b

            new_devices = [snap_b[k] for k in new_keys]
            gone_devices = [snap_a[k] for k in gone_keys]
            stayed_devices = []
            for k in stayed_keys:
                da = snap_a[k]
                db_item = dict(snap_b[k])
                db_item["rssi_delta"] = db_item.get("last_rssi", -90) - da.get("last_rssi", -90)
                stayed_devices.append(db_item)

            return {
                "base_sit": {"id": r_a["id"], "name": r_a["name"], "start_time": r_a["start_time"], "count": len(snap_a)},
                "target_sit": {"id": r_b["id"], "name": r_b["name"], "start_time": r_b["start_time"], "count": len(snap_b)},
                "new_count": len(new_devices),
                "gone_count": len(gone_devices),
                "stayed_count": len(stayed_devices),
                "new_devices": new_devices,
                "gone_devices": gone_devices,
                "stayed_devices": stayed_devices,
            }

    def clear_data(self) -> Dict[str, int]:
        """Clears the entire device, sighting, and alert history."""
        with self._get_connection() as conn:
            c_dev = conn.execute("DELETE FROM devices").rowcount
            conn.execute("DELETE FROM sightings")
            c_al = conn.execute("DELETE FROM alerts").rowcount
            return {"deleted_devices": c_dev, "deleted_alerts": c_al}


# Singleton instance
db = Database()
