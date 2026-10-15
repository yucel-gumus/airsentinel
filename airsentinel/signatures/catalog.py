"""Signature Catalog Engine for AirSentinel.

Compiles and provides O(1) and pattern lookups across all 6,973+ rules
extracted from the Fieldwatch signature dataset, supporting all 9 rule kinds:
OUI, MAC_PREFIX, VENDOR_IE_OUI, NAME_GLOB, NAME_CONTAINS, SERVICE_UUID,
MANUFACTURER_ID, MANUFACTURER_DATA, and SERVICE_DATA.
"""
import fnmatch
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from airsentinel.config import settings
from airsentinel.models import DeviceClass, MatchedSignature, RadioType

logger = logging.getLogger("airsentinel.signatures")

WIFI_PROTOCOL_IE_OUIS = {"00:50:F2", "00:0F:AC"}


class SignatureCatalog:
    def __init__(self, json_path: Optional[Path] = None):
        self.json_path = json_path or settings.signatures_path
        self.catalog_version: int = 0
        self.fleets_count: int = 0
        self.rules_count: int = 0

        # OUI (3-byte) -> List of (fleet_dict, rule_dict)
        self._oui_wifi: Dict[str, List[Tuple[dict, dict]]] = {}
        self._oui_ble: Dict[str, List[Tuple[dict, dict]]] = {}

        # Long MAC prefixes (e.g. Pwnagotchi DE:AD:BE:EF:DE:AD) -> List of (prefix, radio, fleet, rule)
        self._mac_prefixes: List[Tuple[str, str, dict, dict]] = []

        # Vendor IE OUIs -> Dict[oui, List[(fleet, rule)]]
        self._vendor_ie_map: Dict[str, List[Tuple[dict, dict]]] = {}

        # Company ID -> List of (fleet_dict, rule_dict)
        self._company_id_map: Dict[int, List[Tuple[dict, dict]]] = {}

        # Service UUID -> List of (fleet_dict, rule_dict)
        self._service_uuid_map: Dict[str, List[Tuple[dict, dict]]] = {}

        # Service Data -> List of (uuid_norm, hex_prefix, radio, fleet_dict, rule_dict)
        self._service_data_rules: List[Tuple[str, str, str, dict, dict]] = []

        # Name Globs -> List of (pattern, fleet_dict, rule_dict)
        self._name_globs_wifi: List[Tuple[str, dict, dict]] = []
        self._name_globs_ble: List[Tuple[str, dict, dict]] = []

        # Name Contains -> List of (substring_lower, fleet_dict, rule_dict)
        self._name_contains_wifi: List[Tuple[str, dict, dict]] = []
        self._name_contains_ble: List[Tuple[str, dict, dict]] = []

        self.fleets: List[dict] = []
        self.load_signatures()

    def _determine_device_class(self, fleet_name: str) -> DeviceClass:
        name_lower = fleet_name.lower()
        if any(
            k in name_lower
            for k in [
                "drone",
                "dji",
                "remote id",
                "parrot",
                "skydio",
                "autel",
                "brinc",
                "teal",
                "holy stone",
                "potensic",
                "yuneec",
                "swellpro",
                "freefly",
                "tello",
                "crazyflie",
            ]
        ):
            if "dji power" in name_lower:
                return DeviceClass.IOT
            return DeviceClass.DRONE
        if any(
            k in name_lower
            for k in [
                "airtag",
                "smarttag",
                "tag",
                "tile",
                "pebblebee",
                "chipolo",
                "find my",
                "eufy smarttrack",
            ]
        ):
            return DeviceClass.TRACKER
        if any(
            k in name_lower
            for k in [
                "axon",
                "flock",
                "camera",
                "alpr",
                "surveillance",
                "body camera",
                "verkada",
                "ring",
                "arlo",
                "wyze",
                "nest cam",
                "blink",
                "hikvision",
                "dahua",
                "axis",
                "vivotek",
                "reolink",
            ]
        ):
            return DeviceClass.SURVEILLANCE
        if any(
            k in name_lower
            for k in [
                "flipper",
                "deauther",
                "marauder",
                "hackrf",
                "pwnagotchi",
                "hak5",
                "wifi pineapple",
            ]
        ):
            return DeviceClass.ATTACK_TOOL
        if any(
            k in name_lower
            for k in [
                "glasses",
                "ray-ban",
                "rayneo",
                "even g1",
                "wearable",
                "polar",
                "watch",
                "buds",
                "headphone",
                "garmin",
                "fitbit",
                "whoop",
                "oura",
                "apple audio",
                "bose",
                "sony audio",
                "jbl",
            ]
        ):
            return DeviceClass.WEARABLE
        if any(k in name_lower for k in ["apple device", "iphone", "pixel", "galaxy"]):
            return DeviceClass.PHONE
        if any(k in name_lower for k in ["microsoft device", "windows", "macbook", "thinkpad"]):
            return DeviceClass.PC
        if any(
            k in name_lower
            for k in [
                "router",
                "access point",
                "mesh",
                "gateway",
                "switch",
                "cisco",
                "meraki",
                "netgear",
                "tp-link",
                "actiontec",
                "aruba",
                "ubiquiti",
                "unifi",
                "ruckus",
                "mikrotik",
                "fortinet",
                "juniper",
                "eero",
                "orbi",
                "asus",
                "linksys",
                "d-link",
                "zyxel",
                "tenda",
                "cambium",
            ]
        ):
            return DeviceClass.INFRASTRUCTURE
        if any(
            k in name_lower
            for k in [
                "tv",
                "printer",
                "speaker",
                "plug",
                "thermostat",
                "iot",
                "smart",
                "sonos",
                "roku",
                "chromecast",
                "ecobee",
                "nest",
                "tesla",
                "ruuvi",
                "govee",
                "shelly",
                "switchbot",
                "philips hue",
            ]
        ):
            return DeviceClass.IOT
        return DeviceClass.UNKNOWN

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        """Normalizes a MAC string, padding 1-digit hex octets (e.g. from macOS arp -an)."""
        clean = mac.strip().upper().replace("-", ":")
        parts = clean.split(":")
        if len(parts) >= 3 and all(len(p) in (1, 2) and all(c in "0123456789ABCDEF" for c in p) for p in parts):
            return ":".join(f"{int(p, 16):02X}" for p in parts)
        return clean

    @staticmethod
    def is_locally_administered_mac(addr: str) -> bool:
        """Checks if a 6-octet MAC address has the locally-administered bit (0x02) set."""
        parts = addr.replace("-", ":").split(":")
        if len(parts) == 6:
            try:
                return (int(parts[0], 16) & 0x02) != 0
            except ValueError:
                return False
        return False

    @staticmethod
    def _universal_oui_from_virtual_bssid(oui: str) -> Optional[str]:
        """Recovers burned-in universal 24-bit OUI if virtual BSSID set locally-administered bit (0x02)."""
        parts = oui.split(":")
        if len(parts) != 3:
            return None
        try:
            b0 = int(parts[0], 16)
            if (b0 & 0x02) != 0:
                univ_b0 = b0 & ~0x02
                return f"{univ_b0:02X}:{parts[1]}:{parts[2]}"
        except ValueError:
            pass
        return None

    def load_signatures(self):
        """Loads and indexes the signatures JSON."""
        if not self.json_path.exists():
            logger.warning(f"Signature file not found at {self.json_path}")
            return

        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse signature JSON: {e}")
            return

        self.catalog_version = data.get("catalogVersion", 0)
        self.fleets = data.get("fleets", [])
        self.fleets_count = len(self.fleets)
        total_rules = 0

        for fleet in self.fleets:
            if not fleet.get("enabled", True):
                continue

            fleet_rules = fleet.get("rules", [])
            total_rules += len(fleet_rules)

            for rule in fleet_rules:
                if not rule.get("enabled", True):
                    continue

                kind = (rule.get("kind") or "").upper()
                raw_radio = rule.get("radio")
                radio = raw_radio.upper() if raw_radio else "ALL"
                text = (rule.get("text") or "").strip()
                company_id = rule.get("companyId", 0)
                data_prefix = (rule.get("dataPrefixHex") or "").strip().upper()

                if kind == "OUI" and text:
                    norm_oui = self._normalize_mac(text)
                    if len(norm_oui) == 8:
                        if radio in ("WIFI", "ALL"):
                            self._oui_wifi.setdefault(norm_oui, []).append((fleet, rule))
                        if radio in ("BLE", "ALL"):
                            self._oui_ble.setdefault(norm_oui, []).append((fleet, rule))
                        self._vendor_ie_map.setdefault(norm_oui, []).append((fleet, rule))
                    else:
                        self._mac_prefixes.append((norm_oui, radio, fleet, rule))

                elif kind == "MAC_PREFIX" and text:
                    norm_prefix = self._normalize_mac(text)
                    self._mac_prefixes.append((norm_prefix, radio, fleet, rule))

                elif kind == "VENDOR_IE_OUI" and text:
                    norm_oui = self._normalize_mac(text)
                    self._vendor_ie_map.setdefault(norm_oui, []).append((fleet, rule))

                elif kind == "NAME_GLOB" and text:
                    glob_entry = (text, fleet, rule)
                    if radio in ("WIFI", "ALL"):
                        self._name_globs_wifi.append(glob_entry)
                    if radio in ("BLE", "ALL"):
                        self._name_globs_ble.append(glob_entry)

                elif kind == "NAME_CONTAINS" and text:
                    contains_entry = (text.lower(), fleet, rule)
                    if radio in ("WIFI", "ALL"):
                        self._name_contains_wifi.append(contains_entry)
                    if radio in ("BLE", "ALL"):
                        self._name_contains_ble.append(contains_entry)

                elif kind == "SERVICE_UUID" and text:
                    norm_uuid = text.lower().replace("-", "")
                    self._service_uuid_map.setdefault(norm_uuid, []).append((fleet, rule))

                elif kind == "SERVICE_DATA":
                    norm_uuid = text.lower().replace("-", "")
                    self._service_data_rules.append((norm_uuid, data_prefix, radio, fleet, rule))

                elif kind in ("MANUFACTURER_ID", "MANUFACTURER_DATA") or company_id > 0:
                    self._company_id_map.setdefault(company_id, []).append((fleet, rule))

        self.rules_count = total_rules
        logger.info(
            f"Loaded Fieldwatch catalog v{self.catalog_version}: "
            f"{self.fleets_count} fleets, {self.rules_count} rules indexed across all 9 rule kinds."
        )

    def match(
        self,
        radio: RadioType,
        mac: Optional[str] = None,
        name: Optional[str] = None,
        company_id: Optional[int] = None,
        service_uuids: Optional[List[str]] = None,
        manufacturer_data_hex: Optional[str] = None,
        service_data: Optional[Dict[str, str]] = None,
        vendor_ie_ouis: Optional[List[str]] = None,
    ) -> Optional[MatchedSignature]:
        """Matches an observed radio frame against all 9 rule kinds and applies Fieldwatch disambiguation."""
        hits: Dict[str, Tuple[dict, str]] = {}  # fleet_id -> (fleet_dict, matched_rule_desc)

        clean_mfg_hex = (
            "".join(c for c in manufacturer_data_hex if c in "0123456789abcdefABCDEF").upper()
            if manufacturer_data_hex
            else ""
        )

        # 0. Specialized Threat & Tracker Heuristics (Immediate evaluation for known binary frames)
        if company_id == 0x004C and clean_mfg_hex:
            if clean_mfg_hex.startswith("0713") or clean_mfg_hex.startswith("0512"):
                return MatchedSignature(
                    fleet_id="threat-apple-flood",
                    fleet_name="Apple Proximity Pairing (Possible Flood)",
                    device_class=DeviceClass.ATTACK_TOOL,
                    matched_rule="Continuity Pairing Beacon",
                    color_index=1,
                    all_fleets=["Apple Proximity Pairing (Possible Flood)"],
                )
            if clean_mfg_hex.startswith("1219"):
                hits["fleet-airtag"] = (
                    {"id": "fleet-airtag", "name": "Apple AirTags", "colorIndex": 3},
                    "Apple Find My Payload (0x12)",
                )

        if company_id == 0x0075 and clean_mfg_hex:
            if "FD5A" in clean_mfg_hex or "FD59" in clean_mfg_hex:
                hits["fleet-samsung-smarttags"] = (
                    {"id": "fleet-samsung-smarttags", "name": "Samsung SmartTags", "colorIndex": 3},
                    "Samsung SmartTag Beacon",
                )

        # 1. Match by Long MAC Prefix (e.g. Pwnagotchi DE:AD:BE:EF:DE:AD) & 3-byte OUI
        if mac:
            norm_mac = self._normalize_mac(mac)
            for prefix, p_radio, fleet, rule in self._mac_prefixes:
                if p_radio in ("ALL", radio.value) and norm_mac.startswith(prefix):
                    hits[fleet.get("id", fleet["name"])] = (fleet, f"MACPrefix: {prefix}")

            parts = norm_mac.split(":")
            if len(parts) >= 3 and len(parts[0]) == 2 and len(parts[1]) == 2 and len(parts[2]) == 2:
                oui = ":".join(parts[:3])
                oui_table = self._oui_wifi if radio == RadioType.WIFI else self._oui_ble
                if oui in oui_table:
                    for fleet, rule in oui_table[oui]:
                        hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"OUI: {oui}"))
                elif radio == RadioType.WIFI:
                    # Virtual BSSID recovery (clear locally-administered bit 0x02)
                    univ_oui = self._universal_oui_from_virtual_bssid(oui)
                    if univ_oui and univ_oui in self._oui_wifi:
                        for fleet, rule in self._oui_wifi[univ_oui]:
                            hits.setdefault(
                                fleet.get("id", fleet["name"]),
                                (fleet, f"VirtualBSSID-OUI: {univ_oui}"),
                            )

        # 2. Match by Wi-Fi Vendor IE OUIs
        if vendor_ie_ouis and radio == RadioType.WIFI:
            for ie_oui in vendor_ie_ouis:
                norm_ie = self._normalize_mac(ie_oui)
                if norm_ie in WIFI_PROTOCOL_IE_OUIS:
                    continue
                if norm_ie in self._vendor_ie_map:
                    for fleet, rule in self._vendor_ie_map[norm_ie]:
                        hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"VendorIE: {norm_ie}"))

        # 3. Match by Advertised Name (Glob & Substring Contains)
        if name and name != "<redacted>":
            name_lower = name.lower()
            globs = self._name_globs_wifi if radio == RadioType.WIFI else self._name_globs_ble
            for pattern, fleet, rule in globs:
                if fnmatch.fnmatchcase(name_lower, pattern.lower()):
                    hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"NameGlob: {pattern}"))

            contains_list = self._name_contains_wifi if radio == RadioType.WIFI else self._name_contains_ble
            for substr, fleet, rule in contains_list:
                if substr in name_lower:
                    hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"NameContains: {substr}"))

        # 4. Match by Bluetooth Service UUID (from both service_uuids and service_data keys)
        all_uuids = list(service_uuids or [])
        if service_data:
            all_uuids.extend(service_data.keys())

        if all_uuids:
            for s_uuid in all_uuids:
                norm_uuid = s_uuid.lower().replace("-", "")
                for indexed_uuid, matches in self._service_uuid_map.items():
                    if indexed_uuid in norm_uuid or norm_uuid in indexed_uuid:
                        for fleet, rule in matches:
                            hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"ServiceUUID: {s_uuid}"))

        # 5. Match by Bluetooth Service Data Payload
        if service_data:
            for s_uuid, s_hex in service_data.items():
                norm_uuid = s_uuid.lower().replace("-", "")
                clean_shex = "".join(c for c in s_hex if c in "0123456789abcdefABCDEF").upper()
                for rule_uuid, rule_prefix, r_radio, fleet, rule in self._service_data_rules:
                    if r_radio not in ("ALL", radio.value):
                        continue
                    uuid_ok = (not rule_uuid) or (rule_uuid in norm_uuid) or (norm_uuid in rule_uuid)
                    if not uuid_ok:
                        continue
                    if not rule_prefix:
                        hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"ServiceData: {s_uuid}"))
                    elif not rule_uuid and rule_prefix in clean_shex:
                        # Contains check when UUID is blank (e.g. Axon BWCDEVICE)
                        hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"ServiceData: {rule_prefix}"))
                    elif clean_shex.startswith(rule_prefix):
                        hits.setdefault(fleet.get("id", fleet["name"]), (fleet, f"ServiceData: {s_uuid}+{rule_prefix}"))

        # 6. Match by Bluetooth Company ID & Manufacturer Data Hex Prefix
        if company_id is not None and company_id in self._company_id_map:
            matches = self._company_id_map[company_id]
            for fleet, rule in matches:
                data_prefix = (rule.get("dataPrefixHex") or "").upper()
                if data_prefix and clean_mfg_hex.startswith(data_prefix):
                    hits.setdefault(
                        fleet.get("id", fleet["name"]),
                        (fleet, f"CompanyID: 0x{company_id:04X}+{data_prefix}"),
                    )
                elif not data_prefix:
                    hits.setdefault(
                        fleet.get("id", fleet["name"]),
                        (fleet, f"CompanyID: 0x{company_id:04X}"),
                    )

        if not hits:
            return None

        # 7. Fieldwatch Disambiguation Rules
        # - Drop generic iBeacon if a specific product (Tesla, Atrius, etc.) matched
        if "fleet-ibeacon" in hits and len(hits) > 1:
            del hits["fleet-ibeacon"]
        # - Drop DJI drone when Osmo camera or DJI Power station matched
        if ("fleet-osmo" in hits or "fleet-dji-power" in hits) and "fleet-dji" in hits:
            del hits["fleet-dji"]
        # - Drop GoPro when Polar strap matched
        if "fleet-polar" in hits and "fleet-gopro" in hits:
            del hits["fleet-gopro"]
        # - Drop Cisco when Meraki matched
        if "fleet-meraki" in hits and "fleet-cisco" in hits:
            del hits["fleet-cisco"]
        # - Drop AirTags when an active Apple Device (Nearby Info 0x10 / AirDrop 0x05 / short 2-byte 0x1202 Nearby)
        #   or Apple Audio matched, unless advertised name contains AirTag or UUID FD44 is present
        has_airtag_name = bool(name and "airtag" in name.lower())
        has_fd44 = any("fd44" in u.lower() for u in all_uuids)
        if not has_airtag_name and not has_fd44:
            if company_id == 0x004C and clean_mfg_hex.startswith("1202"):
                hits["fleet-apple-device"] = (
                    {"id": "fleet-apple-device", "name": "Apple Device", "colorIndex": 5},
                    "Apple Find My Nearby (0x1202)",
                )
            if "fleet-apple-device" in hits or "fleet-apple-audio" in hits:
                hits.pop("fleet-airtag", None)
                hits.pop("fleet-airtags", None)

        # Prioritize specific threat/tracker/drone/camera fleets over generic vendor rows
        priority_order = {
            DeviceClass.DRONE: 100,
            DeviceClass.ATTACK_TOOL: 95,
            DeviceClass.SURVEILLANCE: 90,
            DeviceClass.TRACKER: 85,
            DeviceClass.WEARABLE: 70,
            DeviceClass.PHONE: 60,
            DeviceClass.PC: 55,
            DeviceClass.IOT: 50,
            DeviceClass.INFRASTRUCTURE: 40,
            DeviceClass.UNKNOWN: 10,
        }

        all_fleet_names = [f[0].get("name", "Unknown") for f in hits.values()]
        best_id, (best_fleet, best_rule) = max(
            hits.items(),
            key=lambda item: priority_order.get(
                self._determine_device_class(item[1][0].get("name", "")), 0
            ),
        )

        return MatchedSignature(
            fleet_id=best_fleet.get("id", best_id),
            fleet_name=best_fleet.get("name", "Unknown"),
            device_class=self._determine_device_class(best_fleet.get("name", "")),
            matched_rule=best_rule,
            color_index=best_fleet.get("colorIndex", 0),
            all_fleets=all_fleet_names,
        )


# Singleton instance
catalog = SignatureCatalog()
