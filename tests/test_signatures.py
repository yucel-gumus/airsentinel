"""Tests for Signature Catalog Engine."""
import pytest
from airsentinel.models import DeviceClass, RadioType
from airsentinel.signatures.catalog import SignatureCatalog

@pytest.fixture
def catalog():
    return SignatureCatalog()

def test_catalog_load(catalog):
    assert catalog.catalog_version >= 90
    assert catalog.fleets_count > 100
    assert catalog.rules_count > 5000

def test_match_oui(catalog):
    # Actiontec OUI 00:0F:B3
    matched = catalog.match(radio=RadioType.WIFI, mac="00:0F:B3:12:34:56")
    assert matched is not None
    assert matched.fleet_name == "Actiontec"

def test_match_name_glob(catalog):
    matched = catalog.match(radio=RadioType.WIFI, name="Actiontec_Router_5G")
    assert matched is not None
    assert matched.fleet_name == "Actiontec"

def test_match_airtag_payload(catalog):
    # Apple Inc (0x004C) with Find My payload (0x12...)
    matched = catalog.match(
        radio=RadioType.BLE,
        mac="AA:BB:CC:DD:EE:FF",
        company_id=0x004C,
        manufacturer_data_hex="1219102B4F09187389AA0102030405",
    )
    assert matched is not None
    assert matched.device_class == DeviceClass.TRACKER
    assert "AirTag" in matched.fleet_name

def test_match_flipper_pairing_spam(catalog):
    # Apple Continuity Proximity pairing popup payload (0x0713...)
    matched = catalog.match(
        radio=RadioType.BLE,
        mac="11:22:33:44:55:66",
        company_id=0x004C,
        manufacturer_data_hex="0713010203040506070809",
    )
    assert matched is not None
    assert matched.device_class == DeviceClass.ATTACK_TOOL
