import os

import pytest

from acpi_mcp import aml

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "tables")


def dsdt_body(machine: str) -> bytes:
    with open(os.path.join(FIX, machine, "DSDT"), "rb") as fh:
        return fh.read()[36:]


def test_pkg_length_encodings():
    assert aml.pkg_length(b"\x3f", 0) == (0x3F, 1)
    assert aml.pkg_length(b"\x4a\x07", 0) == (0x07 << 4 | 0xA, 2)
    assert aml.pkg_length(b"\x81\x34\x12", 0) == (0x12 << 12 | 0x34 << 4 | 1, 3)


def test_name_string_forms():
    assert aml.name_string(b"_SB_", 0) == ("_SB_", 4)
    assert aml.name_string(b"\\_SB_", 0) == ("\\_SB_", 5)
    assert aml.name_string(b"^^PCI0", 0) == ("^^PCI0", 6)
    assert aml.name_string(b"\x2e_SB_PCI0", 0) == ("_SB_.PCI0", 9)
    assert aml.name_string(b"\\\x2f\x03_SB_PCI0S08_", 0) == ("\\_SB_.PCI0.S08_", 15)
    assert aml.name_string(b"\x00", 0) == ("", 1)
    assert aml.name_string(b"1BAD", 0) is None  # name can't start with a digit
    assert aml.name_string(b"ab__", 0) is None  # lowercase isn't valid AML


def test_eisa_id_decoding():
    assert aml.decode_eisa_id(0x0303D041) == "PNP0303"
    assert aml.decode_eisa_id(0x0105D041) == "PNP0501"


@pytest.mark.parametrize("machine,isa_bridge", [("pc", "S08_"), ("q35", "SF8_")])
def test_real_dsdt_devices(machine, isa_bridge):
    devs, heuristic = aml.scan_devices(dsdt_body(machine))
    assert heuristic == 0, "QEMU's DSDT should parse structurally end to end"
    by_path = {d.path: d for d in devs}
    assert by_path[f"\\_SB_.PCI0.{isa_bridge}.KBD_"].hid == "PNP0303"
    assert by_path[f"\\_SB_.PCI0.{isa_bridge}.MOU_"].hid == "PNP0F13"
    com1 = by_path[f"\\_SB_.PCI0.{isa_bridge}.COM1"]
    assert com1.hid == "PNP0501" and com1.uid == 1
    assert by_path["\\_SB_.HPET"].description == "HPET"
    assert by_path["\\_SB_.PCI0.FWCF"].hid == "QEMU0002"
    assert by_path["\\_SB_.CPUS"].cids == ["PNP0A05"]
    # Regression: a Field's PkgLength byte (0x10) used to be mistaken for a
    # Scope opcode, inventing \_SB_.PCI0.STCP.MRCB containers.
    assert not any("STCP" in p or "MRCB" in p for p in by_path)


def test_q35_is_pcie():
    devs = {d.path: d for d in aml.devices(dsdt_body("q35"))}
    assert devs["\\_SB_.PCI0"].hid == "PNP0A08" and devs["\\_SB_.PCI0"].cids == ["PNP0A03"]


def test_real_s5():
    assert aml.sleep_package(dsdt_body("pc")) == (0, 0)


# Device(DEV0){ Name(_HID, "ACPI0003") Name(_CID, Package(){EisaId PNP0C02, "X1"}) }
HID = b"\x08_HID\x0dACPI0003\x00"
CID_ITEMS = b"\x02" + b"\x0c\x41\xd0\x0c\x02" + b"\x0dX1\x00"  # NumElements, DWord, String


def device(body: bytes) -> bytes:
    return b"\x5b\x82" + bytes([1 + 4 + len(body)]) + b"DEV0" + body


def test_synthetic_s5_and_cid_package():
    # Name(\_S5_, Package(4){0x05, 0x05, Zero, Zero})
    s5 = b"\x08\\_S5_\x12\x0a\x04\x0a\x05\x0a\x05\x00\x00"
    assert aml.sleep_package(s5) == (5, 5)
    cid = b"\x08_CID\x12" + bytes([1 + len(CID_ITEMS)]) + CID_ITEMS
    (d,) = aml.devices(device(HID + cid))
    assert d.path == "\\DEV0" and d.hid == "ACPI0003"
    assert d.cids == ["PNP0C02", "X1"] and d.description == "AC adapter"


def test_corrupt_package_length_does_not_crash():
    # The _CID Package claims 15 bytes, but the table ends after 11.
    cid = b"\x08_CID\x12\x0f" + CID_ITEMS
    (d,) = aml.devices(device(cid))
    assert d.cids == ["PNP0C02", "X1"]


def test_unparseable_region_falls_back_and_says_so():
    # An If() at scope level: the predicate isn't parsed, so the walker
    # byte-scans the rest - and still finds the device inside.
    inner = b"\x5b\x82\x0f" + b"KBD_" + b"\x08_HID\x0c\x41\xd0\x03\x03"
    blob = b"\xa0" + bytes([1 + 1 + len(inner)]) + b"\x01" + inner
    devs, heuristic = aml.scan_devices(blob)
    assert heuristic == 1
    assert [(d.path, d.hid) for d in devs] == [("\\KBD_", "PNP0303")]
