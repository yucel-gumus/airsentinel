"""Persistent Tracker & Co-Travel Stalking Detector ("Moving with you")."""
import time
from collections import defaultdict
from typing import Dict, List, Optional
from airsentinel.config import settings
from airsentinel.models import Alert, AlertLevel, DeviceClass, Observation, ThreatCategory


class TrackerDetector:
    def __init__(self):
        # mac -> list of (timestamp, rssi)
        self._sighting_history: Dict[str, List[tuple[float, int]]] = defaultdict(list)
        # mac -> last alert timestamp
        self._alerted_trackers: Dict[str, float] = {}

    def reset(self):
        self._sighting_history.clear()
        self._alerted_trackers.clear()

    def process_observation(self, obs: Observation) -> Optional[Alert]:
        # Only evaluate confirmed tracker classes (AirTags, SmartTags, Tile, Pebblebee, Find My)
        is_tracker = bool(
            obs.matched_signature and obs.matched_signature.device_class == DeviceClass.TRACKER
        )
        if not is_tracker:
            return None

        # Exclude short 0x1202 Find My frames (owner is nearby / personal Apple device in room)
        mfg_hex = (obs.manufacturer_data_hex or "").upper()
        if obs.company_id == 0x004C and mfg_hex.startswith("1202"):
            return None

        now = time.time()
        mac = obs.mac_or_uuid
        history = self._sighting_history[mac]
        history.append((now, obs.rssi))

        # Keep last 1 hour of history
        one_hour_ago = now - 3600
        self._sighting_history[mac] = [item for item in history if item[0] >= one_hour_ago]
        history = self._sighting_history[mac]

        if len(history) >= settings.stalking_min_observations:
            first_seen_ts = history[0][0]
            time_span_min = (now - first_seen_ts) / 60.0

            if time_span_min >= (settings.stalking_time_span_minutes / 2.0):
                recent_rssi = [h[1] for h in history[-5:]]
                avg_rssi = sum(recent_rssi) / len(recent_rssi)

                if avg_rssi >= settings.stalking_rssi_threshold:
                    last_alert_ts = self._alerted_trackers.get(mac, 0.0)
                    if (now - last_alert_ts) > 600.0:
                        self._alerted_trackers[mac] = now
                        tracker_type = (
                            obs.matched_signature.fleet_name
                            if obs.matched_signature
                            else "BLE Tracker"
                        )
                        return Alert(
                            level=AlertLevel.HIGH,
                            category=ThreatCategory.STALKING_CO_TRAVEL,
                            title="Persistent Tracker Detected (Possible Stalker / Co-Travel)",
                            description=(
                                f"A {tracker_type} ({mac}) has been detected continuously in close "
                                f"proximity (avg signal {avg_rssi:.0f} dBm) over the past {time_span_min:.1f} minutes."
                            ),
                            device_id=mac,
                            device_name=obs.name or tracker_type,
                            device_class=DeviceClass.TRACKER,
                            rssi=obs.rssi,
                            details={
                                "first_seen_minutes_ago": round(time_span_min, 1),
                                "observations_count": len(history),
                                "avg_rssi": round(avg_rssi, 1),
                            },
                        )

        return None
