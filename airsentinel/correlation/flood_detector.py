"""RF Flood and Denial-of-Service Attack Detector.

Ported from Fieldwatch's PairingFlood and WifiBeaconFlood.
Counts distinct advertising addresses within a sliding window that emit
pairing popups (Apple Proximity Pairing 0x07, Nearby Action 0x0F, Swift Pair 0x03,
Google Fast Pair 3-byte model, Samsung Easy Setup, LoveSpouse 0x00FF) while
explicitly excluding benign Windows CDP (0x0006 + 0x01) and Find My (0x12).
"""
import statistics
import time
from collections import deque
from typing import Deque, Optional, Set, Tuple

from airsentinel.config import settings
from airsentinel.models import Alert, AlertLevel, DeviceClass, Observation, ThreatCategory
from airsentinel.signatures.decoder import AdvPayloadDecoder


class FloodDetector:
    def __init__(self):
        # Sliding window of (timestamp, mac_or_uuid, rssi, family_label)
        self._ble_pairing_history: Deque[Tuple[float, str, int, str]] = deque()
        self._wifi_beacon_history: Deque[Tuple[float, str, int, str]] = deque()
        self._last_ble_alert_time: float = 0.0
        self._last_wifi_alert_time: float = 0.0
        self._alert_cooldown_sec: float = 15.0

    def reset(self):
        self._ble_pairing_history.clear()
        self._wifi_beacon_history.clear()
        self._last_ble_alert_time = 0.0
        self._last_wifi_alert_time = 0.0

    @staticmethod
    def _classify_pairing_popup(obs: Observation) -> Optional[str]:
        """Returns the pairing popup family if the observation is a popup trigger, else None."""
        if obs.is_pairing_popup and obs.pairing_family:
            return obs.pairing_family
        analysis = AdvPayloadDecoder.analyze(
            company_id=obs.company_id,
            manufacturer_data_hex=obs.manufacturer_data_hex,
            service_data=obs.service_data,
        )
        return analysis.pairing_family if analysis.is_pairing_popup else None

    def process_observation(self, obs: Observation) -> Optional[Alert]:
        now = time.time()
        window = float(settings.flood_window_seconds)

        if obs.radio.value == "BLE":
            family = self._classify_pairing_popup(obs)
            if family:
                self._ble_pairing_history.append((now, obs.mac_or_uuid, obs.rssi, family))

                while self._ble_pairing_history and (now - self._ble_pairing_history[0][0]) > window:
                    self._ble_pairing_history.popleft()

                # Count DISTINCT addresses in the window (a real flood rotates MAC on every packet)
                distinct_macs: Set[str] = {item[1] for item in self._ble_pairing_history}
                if len(distinct_macs) >= settings.flood_threshold_count:
                    if (now - self._last_ble_alert_time) > self._alert_cooldown_sec:
                        self._last_ble_alert_time = now
                        rssi_vals = [x[2] for x in self._ble_pairing_history]
                        median_rssi = int(statistics.median(rssi_vals))
                        families = sorted({x[3] for x in self._ble_pairing_history})

                        return Alert(
                            level=AlertLevel.HIGH,
                            category=ThreatCategory.BLE_PAIRING_FLOOD,
                            title="Bluetooth Pairing Flood Attack Detected",
                            description=(
                                f"Detected {len(distinct_macs)} distinct BLE addresses advertising "
                                f"{', '.join(families)} within {window:.1f}s (median {median_rssi} dBm). "
                                "Characteristic of Flipper Zero or ESP32 BLE spam tools."
                            ),
                            device_id=obs.mac_or_uuid,
                            device_name="BLE Spam Burst",
                            device_class=DeviceClass.ATTACK_TOOL,
                            rssi=median_rssi,
                            details={
                                "burst_count": len(distinct_macs),
                                "families": families,
                                "window_sec": window,
                                "median_rssi": median_rssi,
                            },
                        )

        elif obs.radio.value == "WIFI" and obs.is_randomized_mac:
            self._wifi_beacon_history.append((now, obs.mac_or_uuid, obs.rssi, obs.name or ""))
            while self._wifi_beacon_history and (now - self._wifi_beacon_history[0][0]) > window:
                self._wifi_beacon_history.popleft()

            distinct_bssids = {item[1] for item in self._wifi_beacon_history}
            if len(distinct_bssids) >= 20:
                if (now - self._last_wifi_alert_time) > self._alert_cooldown_sec:
                    self._last_wifi_alert_time = now
                    return Alert(
                        level=AlertLevel.MEDIUM,
                        category=ThreatCategory.WIFI_BEACON_FLOOD,
                        title="Wi-Fi Beacon Flood Detected",
                        description=(
                            f"Surge of {len(distinct_bssids)} distinct randomized Wi-Fi AP beacons detected "
                            f"within {window:.1f}s."
                        ),
                        device_id=obs.mac_or_uuid,
                        device_name="Wi-Fi Beacon Storm",
                        device_class=DeviceClass.ATTACK_TOOL,
                        rssi=obs.rssi,
                    )

        return None
