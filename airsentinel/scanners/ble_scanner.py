"""Native macOS Bluetooth LE Scanner using Bleak / CoreBluetooth."""
import asyncio
import logging
from time import monotonic
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple
from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from airsentinel.correlation.hunt import signal_hunter
from airsentinel.models import Observation, RadioType
from airsentinel.signatures.catalog import SignatureCatalog

logger = logging.getLogger("airsentinel.scanner.ble")
ObservationCallback = Callable[[Observation], Coroutine[Any, Any, None]]

GATT_CHAR_DEVICE_NAME = "00002a00-0000-1000-8000-00805f9b34fb"
GATT_CHAR_MANUFACTURER = "00002a29-0000-1000-8000-00805f9b34fb"
GATT_CHAR_MODEL_NUMBER = "00002a24-0000-1000-8000-00805f9b34fb"
GATT_CHAR_FIRMWARE_REV = "00002a26-0000-1000-8000-00805f9b34fb"
GATT_CHAR_HARDWARE_REV = "00002a27-0000-1000-8000-00805f9b34fb"
GATT_CHAR_SOFTWARE_REV = "00002a28-0000-1000-8000-00805f9b34fb"
GATT_CHAR_BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"

APPLE_MODEL_MAP: Dict[str, str] = {
    "iPhone11,8": "iPhone XR",
    "iPhone11,2": "iPhone XS",
    "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,5": "iPhone 13",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,7": "iPhone 14",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "Mac14,2": "MacBook Air (M2, 2022)",
    "Mac14,15": "MacBook Air (15-inch, M2, 2023)",
    "Mac16,10": "Mac mini (M4, 2024)",
    "Mac16,11": "Mac mini (M4 Pro, 2024)",
    "AudioAccessory5,1": "HomePod mini",
    "AudioAccessory6,1": "HomePod (2nd gen)",
}


class BleScanner:
    def __init__(self, callback: ObservationCallback):
        self.callback = callback
        self.is_running = False
        self._scanner: Optional[BleakScanner] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # mac_or_uuid -> (last_emit_mono, last_rssi, last_mfg_hex)
        self._last_emitted: Dict[str, Tuple[float, int, Optional[str]]] = {}
        self._last_hunt_sample: Dict[str, float] = {}
        self._ble_devices: Dict[str, BLEDevice] = {}

    @staticmethod
    def analyze_gatt_service_risks(services: List[str]) -> List[Dict[str, str]]:
        """Identifies high-risk GATT services such as HID Keyboard/Mouse Injection (0x1812) or BLE UART."""
        out: List[Dict[str, str]] = []
        blob = " ".join(s.lower() for s in services)
        if "1812" in blob or "human interface device" in blob:
            out.append({
                "label": "GATT Güvenlik Uyarısı",
                "value": "⚠️ HID Klavye/Fare Servisi (Tuş Enjeksiyonu / BadBLE Riski)",
            })
        if "6e400001" in blob or "ffe0" in blob:
            out.append({
                "label": "GATT Komut Kanalı",
                "value": "Kablosuz Seri Port (BLE UART / Özel Komut Kanalı)",
            })
        if "1819" in blob or "location and navigation" in blob:
            out.append({
                "label": "GATT Konum Servisi",
                "value": "Canlı Konum / Navigasyon Servisi (0x1819)",
            })
        return out

    def _on_detection(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """Callback invoked whenever a BLE advertisement packet is received."""
        try:
            mac_or_uuid = device.address or "UNKNOWN_BLE"
            self._ble_devices[mac_or_uuid] = device
            rssi = advertisement_data.rssi if advertisement_data.rssi is not None else -100
            now_mono = monotonic()

            # Always feed SignalHunter at up to 3 Hz for smooth Geiger counter response
            last_h = self._last_hunt_sample.get(mac_or_uuid, 0.0)
            if (now_mono - last_h) >= 0.35:
                self._last_hunt_sample[mac_or_uuid] = now_mono
                signal_hunter.record_sample(mac_or_uuid, rssi)

            company_id = None
            mfg_hex = None
            if advertisement_data.manufacturer_data:
                for cid, m_bytes in advertisement_data.manufacturer_data.items():
                    company_id = cid
                    mfg_hex = m_bytes.hex().upper()
                    break

            # Throttle redundant packets from the same stationary BLE address (emit at most every 2.5s
            # unless payload changed or RSSI jumped by >= 8 dB). New MACs (e.g. Flipper flood) pass immediately.
            prev = self._last_emitted.get(mac_or_uuid)
            if prev is not None:
                prev_ts, prev_rssi, prev_mfg = prev
                if (now_mono - prev_ts) < 2.5 and mfg_hex == prev_mfg and abs(rssi - prev_rssi) < 8:
                    return
            self._last_emitted[mac_or_uuid] = (now_mono, rssi, mfg_hex)

            # Bound cache size
            if len(self._last_emitted) > 1000:
                cutoff = now_mono - 120.0
                self._last_emitted = {k: v for k, v in self._last_emitted.items() if v[0] >= cutoff}
                self._last_hunt_sample = {k: v for k, v in self._last_hunt_sample.items() if v >= cutoff}
                if len(self._ble_devices) > 1000:
                    self._ble_devices = {k: v for k, v in self._ble_devices.items() if k in self._last_emitted}

            service_uuids = [str(u).lower() for u in (advertisement_data.service_uuids or [])]
            service_data = {}
            if advertisement_data.service_data:
                for s_uuid, s_bytes in advertisement_data.service_data.items():
                    service_data[str(s_uuid).lower()] = s_bytes.hex().upper()

            is_random = SignatureCatalog.is_locally_administered_mac(mac_or_uuid)

            obs = Observation(
                radio=RadioType.BLE,
                mac_or_uuid=mac_or_uuid,
                name=advertisement_data.local_name or device.name,
                rssi=rssi,
                tx_power=advertisement_data.tx_power,
                company_id=company_id,
                manufacturer_data_hex=mfg_hex,
                service_uuids=service_uuids,
                service_data=service_data,
                is_randomized_mac=is_random,
            )

            if self._loop and self._loop.is_running():
                self._loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(self.callback(obs))
                )
            else:
                asyncio.create_task(self.callback(obs))
        except Exception as e:
            logger.debug(f"Error processing BLE packet: {e}")

    async def inspect_gatt(self, mac_or_uuid: str, timeout: float = 6.0) -> Dict[str, Any]:
        """Connects to a BLE device and reads GATT Device Information (0x180A), Battery (0x180F), and Service Risks."""
        target = self._ble_devices.get(mac_or_uuid, mac_or_uuid)
        gatt_fields: List[Dict[str, str]] = []
        manufacturer: Optional[str] = None
        model_str: Optional[str] = None
        device_name: Optional[str] = None
        battery_pct: Optional[int] = None
        services_found: List[str] = []
        raw_service_tokens: List[str] = []

        try:
            async with BleakClient(target, timeout=timeout) as client:
                for svc in client.services:
                    raw_service_tokens.append(f"{svc.uuid} {svc.description or ''}")
                    desc = svc.description or svc.uuid
                    if desc and desc != "Unknown" and desc not in services_found:
                        services_found.append(desc)

                async def _read_utf8(char_uuid: str) -> Optional[str]:
                    try:
                        raw = await client.read_gatt_char(char_uuid)
                        val = bytes(raw).decode("utf-8", errors="ignore").strip("\x00").strip()
                        return val if val else None
                    except Exception:
                        return None

                device_name = await _read_utf8(GATT_CHAR_DEVICE_NAME)
                manufacturer = await _read_utf8(GATT_CHAR_MANUFACTURER)
                raw_model = await _read_utf8(GATT_CHAR_MODEL_NUMBER)
                if raw_model:
                    friendly = APPLE_MODEL_MAP.get(raw_model)
                    model_str = f"{friendly} ({raw_model})" if friendly else raw_model

                fw_rev = await _read_utf8(GATT_CHAR_FIRMWARE_REV) or await _read_utf8(GATT_CHAR_SOFTWARE_REV)
                hw_rev = await _read_utf8(GATT_CHAR_HARDWARE_REV)
                try:
                    batt_raw = await client.read_gatt_char(GATT_CHAR_BATTERY_LEVEL)
                    if batt_raw and len(batt_raw) >= 1 and 0 <= batt_raw[0] <= 100:
                        battery_pct = int(batt_raw[0])
                except Exception:
                    pass

                if manufacturer:
                    gatt_fields.append({"label": "GATT Üretici", "value": manufacturer})
                if model_str:
                    gatt_fields.append({"label": "GATT Model", "value": model_str})
                if battery_pct is not None:
                    gatt_fields.append({"label": "GATT Pil Seviyesi", "value": f"%{battery_pct}"})
                if fw_rev:
                    gatt_fields.append({"label": "GATT Yazılım", "value": fw_rev})
                if hw_rev:
                    gatt_fields.append({"label": "GATT Donanım Rev", "value": hw_rev})
                gatt_fields.extend(self.analyze_gatt_service_risks(raw_service_tokens))
                if services_found and not gatt_fields:
                    gatt_fields.append({"label": "GATT Servisleri", "value": ", ".join(services_found[:3])})

                return {
                    "connected": True,
                    "mac_or_uuid": mac_or_uuid,
                    "device_name": device_name,
                    "manufacturer": manufacturer,
                    "model": model_str,
                    "battery_pct": battery_pct,
                    "services": services_found[:6],
                    "gatt_fields": gatt_fields,
                }
        except Exception as e:
            return {
                "connected": False,
                "mac_or_uuid": mac_or_uuid,
                "error": f"Cihaz dış bağlantıyı reddetti veya sadece tek yönlü sinyal yayıyor ({type(e).__name__}).",
                "gatt_fields": [],
            }

    async def start(self):
        """Starts scanning for BLE broadcasts."""
        if self.is_running:
            return

        self._loop = asyncio.get_running_loop()
        logger.info("Initializing native macOS BLE CoreBluetooth scanner...")
        try:
            self._scanner = BleakScanner(
                detection_callback=self._on_detection,
                scanning_mode="active",
            )
            await self._scanner.start()
            self.is_running = True
            logger.info("macOS BLE CoreBluetooth scanner is actively listening.")
        except Exception as e:
            logger.warning(
                f"Failed to start hardware BLE scanner (may require Bluetooth permission in Terminal): {e}. "
                "Will continue and allow simulated or external radio injections."
            )
            self.is_running = False

    async def stop(self):
        """Stops the BLE scanner."""
        if not self.is_running:
            return
        logger.info("Stopping BLE scanner...")
        self.is_running = False
        if self._scanner:
            try:
                await self._scanner.stop()
            except Exception as e:
                logger.debug(f"Error stopping Bleak scanner: {e}")
            self._scanner = None
