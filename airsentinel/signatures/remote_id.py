"""ASTM F3411 & OpenDroneID Remote ID Protocol Parser with ANSI/CTA-2063-A Serial Decoding.

Parses drone broadcasts from Bluetooth LE Service 0xFFFA and Wi-Fi Vendor IEs,
extracting aircraft telemetry, specific model stems, serial numbers, and pilot coordinates.
"""
import struct
from typing import Optional, Tuple
from airsentinel.models import DroneRemoteID

# ANSI/CTA-2063-A Specific Model & Manufacturer Prefixes (Longest prefix wins)
CTA2063_PREFIXES = [
    ("18179132", "Freefly", "Freefly Alta X Gen2"),
    ("1817913", "Freefly", "Freefly Astro"),
    ("181792", "Freefly", "Freefly Alta X"),
    ("181793", "Freefly", "Freefly Alta X Broadcast Kit"),
    ("1817", "Freefly Systems", None),
    ("1617B", "Freefly Systems", None),
    ("1914CL2D", "BRINC Drones", "BRINC Lemur 2"),
    ("1914CR1D", "BRINC Drones", "BRINC Responder"),
    ("1914", "BRINC Drones", None),
    ("1885C", "BRINC Drones", None),
    ("1839FTD", "Teal Drones", "Teal 2"),
    ("1839", "Teal Drones", None),
    ("1805A", "Teal Drones", None),
    ("1581F", "DJI", None),
    ("1748C", "Autel Robotics", None),
    ("1668B", "Skydio", None),
    ("1646E", "Parrot", None),
    ("1786A", "Holy Stone", None),
]

STATUS_MAP = {
    0: "Undeclared",
    1: "Ground",
    2: "Airborne",
    3: "Emergency",
    4: "Remote ID System Failure",
}


class RemoteIdParser:
    @staticmethod
    def identify_manufacturer_and_model(uas_id: str) -> Tuple[str, Optional[str]]:
        clean = uas_id.strip().upper()
        for prefix, mfg, model in CTA2063_PREFIXES:
            if clean.startswith(prefix):
                return mfg, model
        if clean.startswith("DJI"):
            return "DJI", None
        return "Generic UAS", None

    @classmethod
    def identify_manufacturer(cls, uas_id: str) -> str:
        mfg, _ = cls.identify_manufacturer_and_model(uas_id)
        return mfg

    @classmethod
    def parse_payload(cls, raw_bytes: bytes) -> Optional[DroneRemoteID]:
        """Parses an OpenDroneID byte payload (Bluetooth LE 0xFFFA or Wi-Fi Vendor IE)."""
        if not raw_bytes:
            return None

        # Strip 0xFFFA Service Data 2-byte header (0x0D app code + 1-byte counter) if present
        if len(raw_bytes) >= 27 and raw_bytes[0] == 0x0D:
            raw_bytes = raw_bytes[2:]

        # Unwrap Message Pack (Message Type 0xF) if present:
        # Byte 0: 0xF0 | proto, Byte 1: single_msg_size (25), Byte 2: msg_count
        if len(raw_bytes) >= 28 and ((raw_bytes[0] >> 4) & 0x0F) == 0x0F and raw_bytes[1] == 25:
            raw_bytes = raw_bytes[3:]

        if len(raw_bytes) < 25:
            return None

        try:
            uas_id = "UNKNOWN-UAS"
            pilot_lat = None
            pilot_lon = None
            ac_lat = None
            ac_lon = None
            altitude_m = None
            height_m = None
            speed_mps = None
            heading_deg = None
            operator_id = None
            status = "Airborne"

            offset = 0
            while offset + 25 <= len(raw_bytes):
                msg = raw_bytes[offset : offset + 25]
                m_type = (msg[0] >> 4) & 0x0F

                # Message Type 0: Basic ID Message
                if m_type == 0x0:
                    raw_id = msg[2:22].decode("ascii", errors="ignore").strip("\x00").strip()
                    if raw_id:
                        uas_id = raw_id

                # Message Type 1: Location/Vector Message
                elif m_type == 0x1:
                    status_raw = (msg[1] >> 4) & 0x0F
                    status = STATUS_MAP.get(status_raw, "Airborne")

                    direction_raw = msg[2]
                    heading_deg = float(direction_raw) if direction_raw <= 360 else None

                    speed_raw = msg[3]
                    speed_mps = round(speed_raw * 0.25, 2)

                    raw_lat, raw_lon = struct.unpack("<ii", msg[5:13])
                    if raw_lat != 0 and raw_lon != 0:
                        ac_lat = round(raw_lat / 1e7, 6)
                        ac_lon = round(raw_lon / 1e7, 6)

                    raw_geo_alt = struct.unpack("<H", msg[13:15])[0]
                    if raw_geo_alt != 0xFFFF:
                        altitude_m = round((raw_geo_alt * 0.5) - 1000.0, 1)

                    raw_height = struct.unpack("<H", msg[15:17])[0]
                    if raw_height != 0xFFFF:
                        height_m = round((raw_height * 0.5) - 1000.0, 1)

                # Message Type 4: System Message (Operator / Pilot Position)
                elif m_type == 0x4:
                    raw_p_lat, raw_p_lon = struct.unpack("<ii", msg[2:10])
                    if raw_p_lat != 0 and raw_p_lon != 0:
                        pilot_lat = round(raw_p_lat / 1e7, 6)
                        pilot_lon = round(raw_p_lon / 1e7, 6)

                # Message Type 5: Operator ID Message
                elif m_type == 0x5:
                    op_str = msg[2:22].decode("ascii", errors="ignore").strip("\x00").strip()
                    if op_str:
                        operator_id = op_str

                offset += 25

            if uas_id == "UNKNOWN-UAS" and ac_lat is None:
                return None

            manufacturer, model_name = cls.identify_manufacturer_and_model(uas_id)

            return DroneRemoteID(
                uas_id=uas_id,
                uas_type="Multirotor",
                manufacturer=manufacturer,
                model_name=model_name,
                pilot_lat=pilot_lat,
                pilot_lon=pilot_lon,
                aircraft_lat=ac_lat,
                aircraft_lon=ac_lon,
                altitude_m=altitude_m,
                height_above_ground_m=height_m,
                speed_mps=speed_mps,
                heading_deg=heading_deg,
                operator_id=operator_id,
                status=status,
            )

        except Exception:
            return None
