"""Deep BLE & Wi-Fi Advertisement Payload Decoder.

Ported from Fieldwatch's AdvPayloadDecoder, CatalogDecodes, FastPair, and Cta2063.
Extracts human-readable telemetry and forensic fields from raw BLE manufacturer
data, service data, and device identifiers.
"""
import struct
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel

class DecodedField(BaseModel):
    label: str
    value: str

class PayloadAnalysis(BaseModel):
    role_hint: Optional[str] = None
    inferred_name: Optional[str] = None
    is_apple_continuity_device: bool = False
    is_pairing_popup: bool = False
    pairing_family: Optional[str] = None
    is_windows_cdp: bool = False
    is_unmaintained_find_my: bool = False
    fingerprint_id: Optional[str] = None
    fields: List[DecodedField] = []

# Apple AirPods / Beats 16-bit device model IDs in Proximity Pairing (0x07)
AIRPODS_MODELS: Dict[int, str] = {
    0x0220: "AirPods (1st gen)",
    0x0F20: "AirPods (2nd gen)",
    0x1320: "AirPods (3rd gen)",
    0x1920: "AirPods (4th gen)",
    0x1B20: "AirPods (4th gen, ANC)",
    0x0E20: "AirPods Pro (1st gen)",
    0x1420: "AirPods Pro (2nd gen, Lightning)",
    0x2420: "AirPods Pro (2nd gen, USB-C)",
    0x0A20: "AirPods Max (Lightning)",
    0x1F20: "AirPods Max (USB-C)",
    0x0520: "BeatsX",
    0x0620: "Beats Solo3",
    0x0920: "Beats Studio3",
    0x1020: "Beats Flex",
    0x1120: "Beats Studio Buds",
    0x1220: "Beats Fit Pro",
    0x1620: "Beats Studio Buds+",
    0x1720: "Beats Studio Pro",
    0x2620: "Beats Solo 4",
    0x0320: "Powerbeats3",
    0x0B20: "Powerbeats Pro",
    0x0C20: "Beats Solo Pro",
}

# Google Fast Pair 24-bit model IDs (Service 0xFE2C)
FAST_PAIR_MODELS: Dict[int, str] = {
    0x000001: "Google Pixel Buds",
    0x000006: "Google Pixel Buds A-Series",
    0x92BBBD: "Google Pixel Buds Pro",
    0xD829B7: "Google Pixel Buds Pro 2",
    0xF00000: "Bose QuietComfort 35 II",
    0xCD8256: "Bose NC 700",
    0x0082DA: "Jabees Firefly",
    0x00AA48: "JBL Live 400BT",
    0x00AA91: "Beoplay E8 2.0",
    0x01EEB4: "Sony WH-1000XM4",
    0x2D7A23: "Sony WF-1000XM4",
    0xD446A7: "Sony WH-1000XM5",
    0x583C73: "Beats Studio Buds",
}

# Microsoft CDP (0x0006, type 0x01) Device Types
MS_CDP_TYPES: Dict[int, str] = {
    0x01: "Xbox One / Series",
    0x06: "Apple iPhone (Microsoft App)",
    0x07: "Apple iPad (Microsoft App)",
    0x08: "Android Device",
    0x09: "Windows 10/11 Desktop",
    0x0B: "Windows Phone",
    0x0C: "Linux Device",
    0x0D: "Windows IoT Core",
    0x0E: "Surface Hub",
    0x0F: "Windows 10/11 Laptop",
    0x10: "Windows Tablet",
}

# Apple Nearby Action (0x0F) Types
APPLE_NEARBY_ACTIONS: Dict[int, str] = {
    0x01: "Apple TV setup",
    0x04: "Mobile backup",
    0x05: "Apple Watch setup",
    0x06: "Apple TV pair",
    0x08: "Wi-Fi password sharing",
    0x09: "iOS quick start setup",
    0x0A: "Device repair",
    0x0B: "HomePod speaker setup",
    0x0C: "Apple Pay proximity",
    0x0D: "Whole-home audio setup",
    0x0F: "Answered a call",
    0x10: "Ended a call",
    0x13: "Remote AutoFill",
    0x14: "Companion Link proximity",
    0x17: "Remote display",
}

TESLA_IBEACON_PREFIX = "021574278BDAB64445208F0C720EAF059935"
ATRIUS_IBEACON_PREFIX = "02155993A94C7D974DF79ABFE493BFD5D000"


class AdvPayloadDecoder:
    """Decodes BLE manufacturer data and service data into structured intelligence."""

    @classmethod
    def analyze(
        cls,
        company_id: Optional[int] = None,
        manufacturer_data_hex: Optional[str] = None,
        service_data: Optional[Dict[str, str]] = None,
        device_name: Optional[str] = None,
    ) -> PayloadAnalysis:
        analysis = PayloadAnalysis()
        service_data = service_data or {}

        # Explicit user-defined BLE local_name (e.g. "Kullanıcı iPhone’u") is a strong identity fingerprint
        if device_name:
            clean_nm = device_name.strip()
            if clean_nm and clean_nm.lower() not in (
                "apple device",
                "microsoft device",
                "bluetooth",
                "unknown",
                "iphone",
                "ipad",
                "mac",
            ):
                analysis.fingerprint_id = f"fp-strong:name:{clean_nm.lower()}"

        # 1. Manufacturer Specific Data Decoding
        if company_id is not None and manufacturer_data_hex:
            clean_hex = "".join(c for c in manufacturer_data_hex if c in "0123456789abcdefABCDEF").upper()
            try:
                raw = bytes.fromhex(clean_hex)
            except ValueError:
                raw = b""

            if company_id == 0x004C and raw:  # Apple Inc.
                cls._decode_apple(raw, clean_hex, analysis)
            elif company_id == 0x0006 and raw:  # Microsoft
                cls._decode_microsoft(raw, analysis)
            elif company_id == 0x0499 and raw:  # Ruuvi Innovations
                cls._decode_ruuvi(raw, analysis)
            elif company_id == 0x0075 and raw:  # Samsung Electronics
                cls._decode_samsung(raw, clean_hex, analysis)
            elif company_id in (0xF202, 0x02F2) and raw:  # GoPro
                cls._decode_gopro(raw, analysis)
            elif company_id in (0xEC88, 0x88EC) and raw:  # Govee
                cls._decode_govee(raw, analysis)
            elif (company_id == 0x0157 or (len(raw) >= 24 and raw[0:2] == b"\xBE\xAC")) and raw:  # AltBeacon
                cls._decode_altbeacon(raw, analysis)
            elif company_id == 0x00FF and raw:  # LoveSpouse / Generic 0x00FF
                if len(raw) >= 6 and clean_hex.startswith("FFFF"):
                    analysis.is_pairing_popup = True
                    analysis.pairing_family = "0x00FF Broadcast"
            elif company_id == 0x08AA and raw:  # SZ DJI Technology Co., Ltd.
                analysis.role_hint = "DJI Drone / Gimbal BLE"
                analysis.inferred_name = analysis.inferred_name or "DJI BLE Device"
                analysis.fields.append(
                    DecodedField(label="DJI BLE", value="DJI drone / gimbal telemetry broadcast")
                )
            elif company_id == 0x0969 and raw:  # Woan Technology (SwitchBot)
                analysis.role_hint = "SwitchBot Smart Home Device"
                analysis.inferred_name = analysis.inferred_name or "SwitchBot Device"
                analysis.fields.append(
                    DecodedField(label="SwitchBot BLE", value="Smart home actuator / sensor telemetry")
                )

        # 2. Service Data Decoding (Fast Pair 0xFE2C, Find My 0xFD44, Eddystone 0xFEAA, Tile 0xFEED, SmartTag 0xFD5A, Axon)
        for uuid_str, s_hex in service_data.items():
            clean_shex = "".join(c for c in s_hex if c in "0123456789abcdefABCDEF").upper()
            try:
                s_bytes = bytes.fromhex(clean_shex)
            except ValueError:
                continue

            u16 = cls._uuid16(uuid_str)
            if u16 == 0xFE2C:  # Google Fast Pair
                cls._decode_fast_pair(s_bytes, analysis)
            elif u16 == 0xFEAA:  # Eddystone / Google Find Hub
                cls._decode_eddystone(s_bytes, analysis)
            elif u16 == 0xFD44:  # Apple Find My Accessory (AirTag / 3rd-party Find My)
                analysis.role_hint = "Apple Find My Tracker / AirTag"
                analysis.fields.append(
                    DecodedField(label="Find My Service (FD44)", value="Active accessory advertisement")
                )
            elif u16 == 0xFEED:  # Tile Bluetooth Tracker
                analysis.role_hint = "Tile Bluetooth Tracker"
                analysis.inferred_name = analysis.inferred_name or "Tile Tracker"
                if clean_shex and not analysis.fingerprint_id:
                    analysis.fingerprint_id = f"fp-strong:tile:{clean_shex[:16]}"
                analysis.fields.append(
                    DecodedField(label="Tile Tracker (FEED)", value=f"Active Tile locator beacon ({clean_shex[:12]}…)")
                )
            elif u16 in (0xFD5A, 0xFD59):  # Samsung SmartTag
                analysis.role_hint = "Samsung SmartTag Tracker"
                analysis.inferred_name = analysis.inferred_name or "Samsung SmartTag"
                state_str = "Active SmartTag beacon"
                if s_bytes:
                    state_b = s_bytes[0]
                    separated = bool(state_b & 0x60)
                    if separated:
                        analysis.is_unmaintained_find_my = True
                        state_str = "Sahibinden Uzak (Separated / Unattended)"
                    else:
                        state_str = "Sahibi Yakında (Owner Nearby)"
                if clean_shex and not analysis.fingerprint_id:
                    analysis.fingerprint_id = f"fp-strong:smarttag:{clean_shex[2:18]}"
                analysis.fields.append(
                    DecodedField(label="Samsung SmartTag (FD5A)", value=state_str)
                )
            elif u16 == 0xFE65:  # Chipolo Tracker
                analysis.role_hint = "Chipolo Bluetooth Tracker"
                analysis.inferred_name = analysis.inferred_name or "Chipolo Tracker"
                analysis.fields.append(
                    DecodedField(label="Chipolo Tracker (FE65)", value="Active Chipolo locator beacon")
                )
            elif u16 == 0xFE95:  # Xiaomi MiBeacon
                analysis.role_hint = analysis.role_hint or "Xiaomi MiBeacon Smart Device"
                analysis.inferred_name = analysis.inferred_name or "Xiaomi MiBeacon"
                analysis.fields.append(
                    DecodedField(label="Xiaomi MiBeacon (FE95)", value=f"Mi Home BLE frame ({clean_shex[:12]}…)")
                )
            elif u16 == 0xFD3D:  # SwitchBot Service Data
                analysis.role_hint = analysis.role_hint or "SwitchBot Smart Home Device"
                analysis.inferred_name = analysis.inferred_name or "SwitchBot"
                analysis.fields.append(
                    DecodedField(label="SwitchBot (FD3D)", value="Smart home status frame")
                )
            elif clean_shex.startswith("425743444556494345"):  # "BWCDEVICE" in ASCII hex -> Axon Body Cam
                analysis.role_hint = "Axon Body-Worn Camera"
                analysis.inferred_name = "Axon Body Camera"
                analysis.fields.append(
                    DecodedField(label="Axon Signature", value="BWCDEVICE service payload")
                )

        return analysis

    @classmethod
    def _decode_apple(cls, raw: bytes, clean_hex: str, out: PayloadAnalysis):
        """Parses Apple Continuity TLV sequence."""
        idx = 0
        has_find_my = False
        has_continuity_host = False

        while idx + 2 <= len(raw):
            tlv_type = raw[idx]
            tlv_len = raw[idx + 1]
            tlv_data = raw[idx + 2 : idx + 2 + tlv_len]
            if len(tlv_data) < tlv_len:
                # Fallback if not strict TLV (e.g. raw prefix)
                tlv_data = raw[idx + 2 :]
                idx = len(raw)
            else:
                idx += 2 + tlv_len

            if tlv_type == 0x02:  # iBeacon
                if clean_hex.startswith(TESLA_IBEACON_PREFIX):
                    out.role_hint = "Tesla Vehicle / Phone Key"
                    out.inferred_name = "Tesla Vehicle"
                    out.fields.append(DecodedField(label="Tesla iBeacon", value="Tesla phone-as-key proximity beacon"))
                elif clean_hex.startswith(ATRIUS_IBEACON_PREFIX):
                    out.role_hint = "Atrius Retail Cart Tag"
                    out.inferred_name = "Atrius Cart Tag"
                    out.fields.append(DecodedField(label="iBeacon", value="Atrius retail tracking beacon"))
                elif len(tlv_data) >= 20:
                    u_bytes = tlv_data[1:17]
                    uuid_str = f"{u_bytes[0:4].hex()}-{u_bytes[4:6].hex()}-{u_bytes[6:8].hex()}-{u_bytes[8:10].hex()}-{u_bytes[10:16].hex()}"
                    major, minor = struct.unpack(">HH", tlv_data[17:21]) if len(tlv_data) >= 21 else (0, 0)
                    out.role_hint = out.role_hint or "Apple iBeacon"
                    if not out.fingerprint_id:
                        out.fingerprint_id = f"fp-strong:ibeacon:{uuid_str}:{major}:{minor}"
                    out.fields.append(DecodedField(label="iBeacon UUID", value=f"{uuid_str} (Major: {major}, Minor: {minor})"))

            elif tlv_type == 0x05:  # AirDrop
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.role_hint = out.role_hint or "iPhone / iPad / Mac (AirDrop)"
                out.fields.append(DecodedField(label="AirDrop", value="Offering AirDrop discovery"))

            elif tlv_type == 0x06:  # HomeKit
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.role_hint = out.role_hint or "Apple HomeKit Accessory"
                out.fields.append(DecodedField(label="HomeKit", value="HomeKit accessory status broadcast"))

            elif tlv_type == 0x07:  # Proximity Pairing (AirPods / Beats)
                out.is_pairing_popup = True
                out.pairing_family = "Apple Proximity Pairing"
                model_name = "AirPods / Beats Audio"
                if len(tlv_data) >= 3:
                    model_id = (tlv_data[1] << 8) | tlv_data[2]
                    model_name = AIRPODS_MODELS.get(model_id, f"Apple Audio (0x{model_id:04X})")
                    if not out.fingerprint_id:
                        out.fingerprint_id = f"fp-behav:airpods:{model_id:04X}"
                out.role_hint = model_name
                out.inferred_name = out.inferred_name or model_name

                # Decode battery nibbles if available
                batt_info = []
                if len(tlv_data) >= 7:
                    b_raw = tlv_data[5]
                    left_b = (b_raw >> 4) & 0x0F
                    right_b = b_raw & 0x0F
                    case_b = tlv_data[6] & 0x0F
                    if left_b <= 10:
                        batt_info.append(f"L: {left_b * 10}%")
                    if right_b <= 10:
                        batt_info.append(f"R: {right_b * 10}%")
                    if case_b <= 10:
                        batt_info.append(f"Case: {case_b * 10}%")
                val_str = f"{model_name}" + (f" ({', '.join(batt_info)})" if batt_info else "")
                out.fields.append(DecodedField(label="Proximity Pairing", value=val_str))

            elif tlv_type == 0x08:  # Hey Siri
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.fields.append(DecodedField(label="Hey Siri", value="Voice trigger hash broadcast"))

            elif tlv_type == 0x09:  # AirPlay
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.role_hint = out.role_hint or "AirPlay Speaker / Apple TV"
                ip_suffix = ""
                if len(tlv_data) >= 6 and tlv_data[2] > 0:
                    ip_candidate = f"{tlv_data[2]}.{tlv_data[3]}.{tlv_data[4]}.{tlv_data[5]}"
                    ip_suffix = f" (LAN IP: {ip_candidate})"
                out.fields.append(DecodedField(label="AirPlay", value=f"AirPlay target discovery{ip_suffix}"))

            elif tlv_type == 0x0A:  # Magic Switch (Apple Watch)
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.role_hint = out.role_hint or "Apple Watch (Magic Switch)"
                out.fields.append(DecodedField(label="Magic Switch", value="Apple Watch auto-switch advertisement"))

            elif tlv_type in (0x0B, 0x0C):  # Handoff
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.role_hint = out.role_hint or "Apple Device (Handoff)"
                out.fields.append(DecodedField(label="Handoff", value="Encrypted Continuity Handoff state"))

            elif tlv_type in (0x0D, 0x0E):  # Instant Hotspot
                has_continuity_host = True
                out.is_apple_continuity_device = True
                out.role_hint = out.role_hint or "iPhone / iPad (Instant Hotspot)"
                if tlv_type == 0x0E and len(tlv_data) >= 6:
                    batt = tlv_data[2]
                    bars = tlv_data[5]
                    out.fields.append(
                        DecodedField(label="Instant Hotspot", value=f"Battery {batt}% · Signal {bars}/4 bars")
                    )
                else:
                    out.fields.append(DecodedField(label="Instant Hotspot", value="Tethering availability"))

            elif tlv_type == 0x0F:  # Nearby Action
                has_continuity_host = True
                out.is_apple_continuity_device = True
                action_id = tlv_data[1] if len(tlv_data) >= 2 else (tlv_data[0] if tlv_data else 0)
                act_name = APPLE_NEARBY_ACTIONS.get(action_id, f"Action 0x{action_id:02X}")
                # Setup actions (0x01, 0x05, 0x06, 0x09, 0x0B) trigger iOS popups in Flipper floods
                if action_id in (0x01, 0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B, 0x0D):
                    out.is_pairing_popup = True
                    out.pairing_family = f"Apple Nearby Action ({act_name})"
                out.role_hint = out.role_hint or f"Apple Device ({act_name})"
                out.fields.append(DecodedField(label="Nearby Action", value=act_name))

            elif tlv_type == 0x10:  # Nearby Info (Phone / Mac state)
                has_continuity_host = True
                out.is_apple_continuity_device = True
                if len(tlv_data) >= 1:
                    status = tlv_data[0]
                    act_code = status & 0x0F
                    flags_hi = (status >> 4) & 0x0F
                    data_flags = tlv_data[1] if len(tlv_data) > 1 else 0
                    if not out.fingerprint_id:
                        # Stable structural flags across iOS/macOS BLE MAC rotations
                        out.fingerprint_id = f"fp-behav:apple-10:{flags_hi & 0x05:02X}:{data_flags & 0x25:02X}"
                    act_map = {
                        0x00: "Activity unknown",
                        0x01: "Activity reporting disabled",
                        0x03: "Idle (screen locked)",
                        0x05: "Audio playing (screen locked)",
                        0x07: "Active (screen on)",
                        0x09: "Screen on (video playing)",
                        0x0A: "Apple Watch on wrist & unlocked",
                        0x0B: "Recent user interaction",
                        0x0D: "User is driving",
                        0x0E: "Active phone / FaceTime call",
                    }
                    act_str = act_map.get(act_code, f"State 0x{act_code:X}")
                    extras = []
                    if flags_hi & 0x01:
                        extras.append("Primary iCloud device")
                    if flags_hi & 0x04:
                        extras.append("AirDrop receiving ON")
                    if data_flags & 0x04:
                        extras.append("Wi-Fi ON")
                    if data_flags & 0x01:
                        extras.append("AirPods connected")
                    if data_flags & 0x20:
                        extras.append("Watch locked")

                    full_state = act_str + (f" · {', '.join(extras)}" if extras else "")
                    out.role_hint = out.role_hint or "iPhone / iPad / Mac"
                    out.fields.append(DecodedField(label="Apple Continuity State", value=full_state))

            elif tlv_type == 0x12:  # Find My / Offline Finding
                has_find_my = True
                if len(tlv_data) >= 1:
                    status = tlv_data[0]
                    # 2-byte 0x1202 frames are "Owner Nearby" (maintained) advertisements from Apple devices.
                    # 25-byte 0x1219 frames are Offline Finding (separated key) advertisements.
                    is_short_nearby = len(tlv_data) <= 2
                    maintained = is_short_nearby or bool(status & 0x04)
                    batt_bits = (status >> 6) & 0x03
                    batt_map = {0: "Full", 1: "Medium", 2: "Low", 3: "Critical"}
                    batt_str = batt_map.get(batt_bits, "Unknown")
                    owner_str = "Owner nearby (maintained)" if maintained else "Separated from owner"
                    if is_short_nearby:
                        has_continuity_host = True
                        out.is_apple_continuity_device = True
                        out.role_hint = out.role_hint or "iPhone / iPad / Mac (Find My Nearby)"
                    elif not maintained:
                        out.is_unmaintained_find_my = True
                    out.fields.append(
                        DecodedField(
                            label="Find My Network (0x12)",
                            value=f"{owner_str} · Battery: {batt_str}",
                        )
                    )

        # If a packet ONLY has 25-byte Offline Finding (0x1219) and NO Continuity host TLVs,
        # it behaves like a standalone Find My tag/AirTag rather than an active iPhone.
        if has_find_my and not has_continuity_host:
            out.role_hint = out.role_hint or "Apple AirTag / Find My Tracker"
        elif has_find_my and has_continuity_host:
            # Find My (0x12) on an active iPhone/Mac should NOT trigger pairing flood
            out.is_pairing_popup = False

    @classmethod
    def _decode_microsoft(cls, raw: bytes, out: PayloadAnalysis):
        """Parses Microsoft (0x0006) CDP vs Swift Pair beacons."""
        if not raw:
            return
        beacon_type = raw[0]
        if beacon_type == 0x01 and len(raw) >= 2:
            # Connected Devices Platform (Windows background beacon — NOT a pairing flood!)
            out.is_windows_cdp = True
            out.is_pairing_popup = False
            dev_type_code = raw[1] & 0x1F
            dev_label = MS_CDP_TYPES.get(dev_type_code, f"Microsoft CDP Device (0x{dev_type_code:02X})")
            out.role_hint = dev_label
            out.inferred_name = dev_label
            if not out.fingerprint_id:
                out.fingerprint_id = f"fp-behav:ms-cdp:{dev_type_code:02X}"
            out.fields.append(
                DecodedField(label="Microsoft CDP", value=f"{dev_label} (Near Share / Cross-Device)")
            )
        elif beacon_type == 0x03 and len(raw) >= 2:
            # Microsoft Swift Pair
            out.is_pairing_popup = True
            out.pairing_family = "Microsoft Swift Pair"
            out.role_hint = "Swift Pair Accessory"
            name_part = raw[6:].decode("utf-8", errors="ignore").strip("\x00").strip() if len(raw) > 6 else ""
            if name_part:
                out.inferred_name = name_part
            out.fields.append(
                DecodedField(label="Microsoft Swift Pair", value=name_part or "Advertising quick pairing")
            )

    @classmethod
    def _decode_samsung(cls, raw: bytes, clean_hex: str, out: PayloadAnalysis):
        """Parses Samsung (0x0075) Easy Setup vs SmartTag."""
        if clean_hex.startswith("010002"):
            out.is_pairing_popup = True
            out.pairing_family = "Samsung Easy Setup"
            out.role_hint = "Samsung Galaxy Buds / Watch Setup"
            out.fields.append(DecodedField(label="Samsung Easy Setup", value="Proximity pairing advertisement"))

    @classmethod
    def _decode_fast_pair(cls, raw: bytes, out: PayloadAnalysis):
        """Parses Google Fast Pair (0xFE2C) 3-byte model ID vs account key filter."""
        if len(raw) == 3:
            model_id = (raw[0] << 16) | (raw[1] << 8) | raw[2]
            model_name = FAST_PAIR_MODELS.get(model_id, f"Fast Pair Device (0x{model_id:06X})")
            out.is_pairing_popup = True
            out.pairing_family = "Google Fast Pair"
            out.role_hint = model_name
            out.inferred_name = model_name
            out.fields.append(DecodedField(label="Google Fast Pair", value=f"{model_name} (Pairing Mode)"))
        else:
            out.fields.append(DecodedField(label="Google Fast Pair", value="Account-key background filter (idle)"))

    @classmethod
    def _decode_eddystone(cls, raw: bytes, out: PayloadAnalysis):
        """Parses Eddystone (0xFEAA) UID, URL, TLM, EID, and Google Find Hub (0x40/0x41) frames."""
        if not raw:
            return
        frame_type = raw[0]
        if frame_type in (0x40, 0x41):
            out.role_hint = "Google Find Hub Tracker"
            out.inferred_name = out.inferred_name or "Google Find Hub Tag"
            out.fields.append(
                DecodedField(label="Google Find Hub (FEAA)", value=f"Find My Device Network EID frame (0x{frame_type:02X})")
            )
        elif frame_type == 0x00 and len(raw) >= 18:
            ns = raw[2:12].hex().upper()
            inst = raw[12:18].hex().upper()
            out.role_hint = out.role_hint or "Eddystone-UID Beacon"
            if not out.fingerprint_id:
                out.fingerprint_id = f"fp-strong:eddystone:{ns}:{inst}"
            out.fields.append(DecodedField(label="Eddystone-UID", value=f"NS: {ns[:12]}… · Inst: {inst}"))
        elif frame_type == 0x10 and len(raw) >= 3:
            prefixes = {0: "http://www.", 1: "https://www.", 2: "http://", 3: "https://"}
            url_str = prefixes.get(raw[2], "https://") + raw[3:].decode("ascii", errors="ignore")
            out.role_hint = out.role_hint or "Eddystone-URL Beacon"
            out.fields.append(DecodedField(label="Eddystone-URL", value=url_str))
        elif frame_type == 0x20 and len(raw) >= 14:
            batt_mv = struct.unpack(">H", raw[2:4])[0]
            temp_c = round(raw[4] + (raw[5] / 256.0), 1)
            out.role_hint = out.role_hint or "Eddystone-TLM Sensor Beacon"
            out.fields.append(DecodedField(label="Eddystone-TLM", value=f"{temp_c}°C · Battery: {batt_mv} mV"))

    @classmethod
    def _decode_gopro(cls, raw: bytes, out: PayloadAnalysis):
        """Parses GoPro Action Camera BLE status payload."""
        out.role_hint = "GoPro Action Camera"
        out.inferred_name = out.inferred_name or "GoPro Camera"
        if len(raw) >= 1:
            recording = bool(raw[0] & 0x01)
            state_str = "Recording active" if recording else "Idle / Standby"
            out.fields.append(DecodedField(label="GoPro Status", value=state_str))

    @classmethod
    def _decode_govee(cls, raw: bytes, out: PayloadAnalysis):
        """Parses Govee (0xEC88) Smart Thermo-Hygrometer broadcast."""
        out.role_hint = "Govee Smart Thermo-Hygrometer"
        out.inferred_name = out.inferred_name or "Govee Sensor"
        if len(raw) >= 5:
            raw_val = (raw[1] << 16) | (raw[2] << 8) | raw[3]
            is_neg = bool(raw_val & 0x800000)
            mag = raw_val & 0x7FFFFF
            temp_c = round((mag // 1000) / 10.0 * (-1 if is_neg else 1), 1)
            hum_pct = round((mag % 1000) / 10.0, 1)
            batt = raw[4] & 0x7F
            out.fields.append(
                DecodedField(label="Govee Telemetry", value=f"{temp_c}°C · {hum_pct}% RH · Battery: {batt}%")
            )

    @classmethod
    def _decode_altbeacon(cls, raw: bytes, out: PayloadAnalysis):
        """Parses AltBeacon (0xBEAC) proximity beacon."""
        out.role_hint = out.role_hint or "AltBeacon Proximity Tag"
        if len(raw) >= 22:
            beacon_id = raw[2:18].hex().upper()
            major, minor = struct.unpack(">HH", raw[18:22])
            if not out.fingerprint_id:
                out.fingerprint_id = f"fp-strong:altbeacon:{beacon_id}:{major}:{minor}"
            out.fields.append(DecodedField(label="AltBeacon", value=f"ID: {beacon_id[:12]}… (Major: {major}, Minor: {minor})"))

    @classmethod
    def _decode_ruuvi(cls, raw: bytes, out: PayloadAnalysis):
        """Parses RuuviTag (0x0499) RAWv2 weather & motion telemetry."""
        if len(raw) >= 18 and raw[0] == 0x05:
            temp_raw = struct.unpack(">h", raw[1:3])[0]
            hum_raw = struct.unpack(">H", raw[3:5])[0]
            pres_raw = struct.unpack(">H", raw[5:7])[0]
            temp_c = round(temp_raw * 0.005, 2)
            hum_pct = round(hum_raw * 0.0025, 1)
            pres_hpa = round((pres_raw * 0.01) + 500.0, 1)
            out.role_hint = "RuuviTag Environmental Sensor"
            out.inferred_name = "RuuviTag Sensor"
            out.fields.append(
                DecodedField(label="Ruuvi Telemetry", value=f"{temp_c}°C · {hum_pct}% RH · {pres_hpa} hPa")
            )

    @staticmethod
    def _uuid16(uuid_str: str) -> Optional[int]:
        clean = "".join(c for c in uuid_str if c in "0123456789abcdefABCDEF").upper()
        if len(clean) == 4:
            return int(clean, 16)
        if len(clean) == 32 and clean.startswith("0000") and clean.endswith("00001000800000805F9B34FB"):
            return int(clean[4:8], 16)
        return None
