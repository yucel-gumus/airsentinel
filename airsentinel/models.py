"""Data models for AirSentinel Core."""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class RadioType(str, Enum):
    WIFI = "WIFI"
    BLE = "BLE"

class DeviceClass(str, Enum):
    DRONE = "DRONE"
    TRACKER = "TRACKER"
    SURVEILLANCE = "SURVEILLANCE"
    WEARABLE = "WEARABLE"
    ATTACK_TOOL = "ATTACK_TOOL"
    IOT = "IOT"
    PHONE = "PHONE"
    PC = "PC"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"

class AlertLevel(str, Enum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatCategory(str, Enum):
    DRONE_REMOTE_ID = "DRONE_REMOTE_ID"
    STALKING_CO_TRAVEL = "STALKING_CO_TRAVEL"
    BLE_PAIRING_FLOOD = "BLE_PAIRING_FLOOD"
    WIFI_BEACON_FLOOD = "WIFI_BEACON_FLOOD"
    SURVEILLANCE_CAMERA = "SURVEILLANCE_CAMERA"
    INTRUDER_PROXIMITY = "INTRUDER_PROXIMITY"
    EVIL_TWIN_AP = "EVIL_TWIN_AP"
    ARP_SPOOFING_MITM = "ARP_SPOOFING_MITM"
    DNS_HIJACK_MITM = "DNS_HIJACK_MITM"
    RF_PRESENCE_MOTION = "RF_PRESENCE_MOTION"

class HuntCue(str, Enum):
    VERY_CLOSE = "VERY_CLOSE"
    CLOSER = "CLOSER"
    FURTHER = "FURTHER"
    SAME = "SAME"
    WAITING = "WAITING"
    QUIET = "QUIET"
    GONE = "GONE"

class MatchedSignature(BaseModel):
    fleet_id: str
    fleet_name: str
    device_class: DeviceClass
    matched_rule: str
    color_index: int = 0
    all_fleets: List[str] = Field(default_factory=list)

class DroneRemoteID(BaseModel):
    uas_id: str
    uas_type: str = "UAS"
    manufacturer: str = "Unknown"
    model_name: Optional[str] = None
    pilot_lat: Optional[float] = None
    pilot_lon: Optional[float] = None
    aircraft_lat: Optional[float] = None
    aircraft_lon: Optional[float] = None
    altitude_m: Optional[float] = None
    height_above_ground_m: Optional[float] = None
    speed_mps: Optional[float] = None
    heading_deg: Optional[float] = None
    operator_id: Optional[str] = None
    status: str = "Airborne"

class Observation(BaseModel):
    radio: RadioType
    mac_or_uuid: str
    name: Optional[str] = None
    rssi: int
    snr: Optional[int] = None
    tx_power: Optional[int] = None
    channel_or_freq: Optional[str] = None
    company_id: Optional[int] = None
    manufacturer_data_hex: Optional[str] = None
    service_uuids: List[str] = Field(default_factory=list)
    service_data: Dict[str, str] = Field(default_factory=dict)
    vendor_ie_ouis: List[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    matched_signature: Optional[MatchedSignature] = None
    drone_data: Optional[DroneRemoteID] = None
    is_randomized_mac: bool = False
    is_pairing_popup: bool = False
    pairing_family: Optional[str] = None
    role_hint: Optional[str] = None
    decoded_fields: List[Dict[str, str]] = Field(default_factory=list)
    fingerprint_id: Optional[str] = None

class Alert(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    level: AlertLevel
    category: ThreatCategory
    title: str
    description: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    device_class: DeviceClass = DeviceClass.UNKNOWN
    rssi: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = False

class TrackedDevice(BaseModel):
    mac_or_uuid: str
    radio: RadioType
    name: Optional[str] = None
    device_class: DeviceClass = DeviceClass.UNKNOWN
    matched_fleet: Optional[str] = None
    all_fleets: List[str] = Field(default_factory=list)
    role_hint: Optional[str] = None
    decoded_fields: List[Dict[str, str]] = Field(default_factory=list)
    channel_or_freq: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    hit_count: int = 1
    last_rssi: int
    avg_rssi: float
    drone_info: Optional[DroneRemoteID] = None
    is_threat: bool = False
    threat_reason: Optional[str] = None
    is_bookmarked: bool = False
    is_trusted: bool = False
    fingerprint_id: Optional[str] = None
    risk_score: int = 0
    risk_reasons: List[str] = Field(default_factory=list)
    mobility_profile: Optional[str] = None
    estimated_distance_m: Optional[float] = None

class SitSession(BaseModel):
    id: int
    name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    is_active: bool = True
    device_count: int = 0
    notes: str = ""
    snapshot_devices: List[Dict[str, Any]] = Field(default_factory=list)
