"""Tests for Drone Remote ID parser."""
import struct
import pytest
from airsentinel.signatures.remote_id import RemoteIdParser

def test_identify_manufacturer():
    assert RemoteIdParser.identify_manufacturer("1581F49A2B11") == "DJI"
    assert RemoteIdParser.identify_manufacturer("1748C0001234") == "Autel Robotics"
    assert RemoteIdParser.identify_manufacturer("1668B9999999") == "Skydio"
    assert RemoteIdParser.identify_manufacturer("1646E1234567") == "Parrot"

def test_parse_basic_id_and_location():
    # Construct a synthetic 25-byte ASTM F3411 Basic ID Message (Type 0x0)
    # Byte 0: Msg type 0x0
    # Byte 1: ID type 0x1 (Serial Number)
    # Bytes 2..22: ASCII serial "1581F49A2B11002348"
    msg_basic = bytearray(25)
    msg_basic[0] = 0x00 # Type 0x0
    msg_basic[1] = 0x10 # Serial Number
    serial_bytes = b"1581F49A2B11002348"
    msg_basic[2 : 2 + len(serial_bytes)] = serial_bytes

    # Construct a 25-byte Location & Vector Message (Type 0x1)
    msg_loc = bytearray(25)
    msg_loc[0] = 0x10 # Type 0x1
    msg_loc[1] = 0x20 # Status: Airborne (2)
    msg_loc[2] = 90   # Heading 90 deg
    msg_loc[3] = 40   # Speed: 40 * 0.25 = 10.0 m/s
    
    # Lat: 41.0082 * 1e7 = 410082000, Lon: 28.9784 * 1e7 = 289784000
    lat_val = 410082000
    lon_val = 289784000
    struct.pack_into("<ii", msg_loc, 5, lat_val, lon_val)
    
    # Alt: (120m + 1000m) / 0.5 = 2240
    struct.pack_into("<H", msg_loc, 13, 2240)

    # Combined payload
    payload = bytes(msg_basic + msg_loc)

    parsed = RemoteIdParser.parse_payload(payload)
    assert parsed is not None
    assert parsed.manufacturer == "DJI"
    assert parsed.uas_id == "1581F49A2B11002348"
    assert parsed.aircraft_lat == 41.0082
    assert parsed.aircraft_lon == 28.9784
    assert parsed.altitude_m == 120.0
    assert parsed.speed_mps == 10.0
    assert parsed.heading_deg == 90.0
    assert parsed.status == "Airborne"
