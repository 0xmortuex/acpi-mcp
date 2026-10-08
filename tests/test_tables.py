"""Parsers against real QEMU tables (tests/fixtures/tables) and synthetic edge cases."""

import os
import struct

import pytest

from acpi_mcp import tables as t

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "tables")


def load(machine: str, sig: str) -> bytes:
    with open(os.path.join(FIX, machine, sig), "rb") as fh:
        return fh.read()


def fix_checksum(b: bytearray, at: int = 9, span: int | None = None) -> bytes:
    """Set the checksum byte so the structure sums to zero."""
    b[at] = 0
    b[at] = (-sum(b[: span or len(b)])) % 256
    return bytes(b)


def make_table(sig: bytes, body: bytes, revision: int = 1) -> bytes:
    hdr = bytearray(sig + struct.pack("<I", 36 + len(body)) + bytes([revision, 0])
                    + b"TESTOE" + b"TESTTABL" + struct.pack("<I", 1) + b"TEST" + struct.pack("<I", 1))
    return fix_checksum(hdr + body)


@pytest.mark.parametrize("machine", ["pc", "q35"])
def test_every_real_table_checksums(machine):
    for name in os.listdir(os.path.join(FIX, machine)):
        if name in ("FACS", "RSDP"):
            continue
        h = t.parse_header(load(machine, name))
        assert h.checksum_ok, name
        assert h.oem_id == "BOCHS"


def test_rsdp_v1_real():
    r = t.parse_rsdp(load("pc", "RSDP"))
    assert r.revision == 0 and r.acpi_version == "1.0"
    assert r.checksum_ok and r.xsdt_address is None and r.ext_checksum_ok is None
    assert r.rsdt_address == 0x7FE2383


def test_rsdp_v2_with_xsdt():
    b = bytearray(b"RSD PTR " + b"\x00" + b"OEMID " + b"\x02" + struct.pack("<I", 0x1000)
                  + struct.pack("<I", 36) + struct.pack("<Q", 0x2000) + b"\x00" + b"\x00" * 3)
    b[8] = (-sum(b[:20])) % 256
    b[32] = (-sum(b)) % 256
    r = t.parse_rsdp(bytes(b))
    assert r.acpi_version == "2.0+" and r.xsdt_address == 0x2000
    assert r.checksum_ok and r.ext_checksum_ok


def test_rsdp_rejects_garbage():
    with pytest.raises(t.ACPIError, match="RSD PTR"):
        t.parse_rsdp(b"x" * 36)


def test_xsdt_pointers_are_64_bit():
    xsdt = make_table(b"XSDT", struct.pack("<QQ", 0x1_0000_0000, 0x2000))
    assert t.parse_sdt_pointers(xsdt) == [0x1_0000_0000, 0x2000]


def test_rsdt_pointers_real():
    assert len(t.parse_sdt_pointers(load("q35", "RSDT"))) == 5  # FACP APIC HPET MCFG WAET


def test_bad_checksum_detected():
    b = bytearray(load("pc", "APIC"))
    b[50] ^= 0xFF
    assert not t.parse_header(bytes(b)).checksum_ok


def test_header_length_errors():
    with pytest.raises(t.ACPIError, match="too short"):
        t.parse_header(b"APIC")
    b = bytearray(load("pc", "APIC"))
    struct.pack_into("<I", b, 4, 4096)
    with pytest.raises(t.ACPIError, match="only 128 are available"):
        t.parse_header(bytes(b))


def test_fadt_rev1_pc():
    f = t.parse_fadt(load("pc", "FACP"))
    assert f.header.revision == 1
    assert f.reset_reg is None and f.iapc_boot_arch is None and f.x_dsdt is None
    assert (f.sci_int, f.smi_cmd, f.acpi_enable) == (9, 0xB2, 0xF1)
    assert (f.pm1a_cnt_blk, f.pm_tmr_blk, f.century) == (0x604, 0x608, 0x32)
    assert "SLP_BUTTON" in f.flag_names()


def test_fadt_rev3_q35_reset_register():
    f = t.parse_fadt(load("q35", "FACP"))
    assert f.header.revision == 3
    assert f.reset_reg is not None and f.reset_reg.space == 1 and f.reset_reg.address == 0xCF9
    assert f.reset_value == 0x0F and "RESET_REG_SUP" in f.flag_names()
    assert f.boot_arch_names() == ["8042"]
    assert f.dsdt_address == 0x7FE0040


@pytest.mark.parametrize("machine", ["pc", "q35"])
def test_madt_real(machine):
    m = t.parse_madt(load(machine, "APIC"))
    assert m.lapic_address == 0xFEE00000 and m.pcat_compat
    assert [e.fields["apic_id"] for e in m.of("lapic")] == [0, 1]
    (io,) = m.of("ioapic")
    assert io.fields["address"] == 0xFEC00000 and io.fields["gsi_base"] == 0
    iso0 = [e for e in m.of("iso") if e.fields["source_irq"] == 0]
    assert iso0[0].fields["gsi"] == 2
    assert m.of("lapic_nmi")[0].fields["lint"] == 1


def test_madt_synthetic_entry_types():
    body = struct.pack("<II", 0xFEE00000, 1)
    body += bytes([0, 8, 0, 0]) + struct.pack("<I", 0)          # disabled LAPIC
    body += bytes([0, 8, 1, 1]) + struct.pack("<I", 2)          # online-capable LAPIC
    body += bytes([5, 12, 0, 0]) + struct.pack("<Q", 0xFEE10000)  # LAPIC address override
    body += bytes([9, 16, 0, 0]) + struct.pack("<III", 300, 1, 7)  # x2APIC
    body += bytes([3, 8]) + struct.pack("<HI", 0xF, 4)          # NMI source, active low level
    body += bytes([0x7F, 4, 0, 0])                              # unknown type
    m = t.parse_madt(make_table(b"APIC", body, 4))
    kinds = [e.kind for e in m.entries]
    assert kinds == ["lapic", "lapic", "lapic_override", "x2apic", "nmi_source", "type_0x7f"]
    assert m.of("x2apic")[0].fields == {"x2apic_id": 300, "flags": 1, "processor_uid": 7}
    assert t.polarity_trigger(m.of("nmi_source")[0].fields["flags"]) == ("active low", "level")


def test_madt_bad_entry_length():
    body = struct.pack("<II", 0xFEE00000, 1) + bytes([0, 40, 0, 0])
    with pytest.raises(t.ACPIError, match="invalid length"):
        t.parse_madt(make_table(b"APIC", body))


def test_mcfg_q35():
    (e,) = t.parse_mcfg(load("q35", "MCFG"))
    assert (e.base, e.segment, e.start_bus, e.end_bus) == (0xB0000000, 0, 0, 255)


def test_hpet_real():
    h = t.parse_hpet(load("pc", "HPET"))
    assert h.base.address == 0xFED00000 and h.base.space == 0
    assert h.comparators == 3 and h.counter_64bit and h.legacy_replacement
    assert h.pci_vendor == 0x8086


def test_facs_and_waet():
    f = t.parse_facs(load("pc", "FACS"))
    assert f.length == 64
    assert t.parse_waet(load("pc", "WAET")) == {"rtc_good": False, "pm_timer_good": True}


def test_wrong_signature_errors():
    with pytest.raises(t.ACPIError, match="expected FACP"):
        t.parse_fadt(load("pc", "APIC"))
    with pytest.raises(t.ACPIError, match="not a FACS"):
        t.parse_facs(load("pc", "APIC"))
