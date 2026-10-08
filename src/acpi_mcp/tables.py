"""Pure-Python parsers for the ACPI tables an OS developer meets first.

Everything here works on raw bytes, so it doesn't matter whether the
tables came from a live VM's memory, /sys/firmware/acpi/tables, or
`acpidump -b`. Offsets follow the ACPI 6.x specification; older/shorter
revisions are handled by checking the table length before reading a field.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


class ACPIError(ValueError):
    pass


def checksum_ok(data: bytes) -> bool:
    """ACPI checksums make the byte sum of the whole structure 0 mod 256."""
    return sum(data) % 256 == 0


def _u8(b: bytes, off: int) -> int:
    return b[off]


def _u16(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", b, off)[0])


def _u32(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", b, off)[0])


def _u64(b: bytes, off: int) -> int:
    return int(struct.unpack_from("<Q", b, off)[0])


def _text(b: bytes) -> str:
    return b.rstrip(b"\x00 ").decode("ascii", errors="replace")


# --- RSDP ---------------------------------------------------------------------


@dataclass
class RSDP:
    revision: int
    oem_id: str
    rsdt_address: int
    xsdt_address: int | None
    checksum_ok: bool
    ext_checksum_ok: bool | None
    raw: bytes

    @property
    def acpi_version(self) -> str:
        return "1.0" if self.revision == 0 else "2.0+"


def parse_rsdp(b: bytes) -> RSDP:
    if len(b) < 20 or b[:8] != b"RSD PTR ":
        raise ACPIError("not an RSDP: missing 'RSD PTR ' signature")
    revision = _u8(b, 15)
    if revision >= 2:
        if len(b) < 36:
            raise ACPIError(f"RSDP revision {revision} needs 36 bytes, got {len(b)}")
        length = _u32(b, 20)
        raw = b[: max(length, 36)]
        return RSDP(revision, _text(b[9:15]), _u32(b, 16), _u64(b, 24),
                    checksum_ok(b[:20]), checksum_ok(raw), raw)
    return RSDP(revision, _text(b[9:15]), _u32(b, 16), None, checksum_ok(b[:20]), None, b[:20])


# --- generic SDT header ---------------------------------------------------------


@dataclass
class Header:
    signature: str
    length: int
    revision: int
    checksum_ok: bool
    oem_id: str
    oem_table_id: str
    oem_revision: int
    creator_id: str
    creator_revision: int


def parse_header(b: bytes) -> Header:
    if len(b) < 36:
        raise ACPIError(f"table too short for an ACPI header ({len(b)} bytes, need 36)")
    sig = b[:4].decode("ascii", errors="replace")
    length = _u32(b, 4)
    if length > len(b):
        raise ACPIError(f"{sig}: header says {length} bytes but only {len(b)} are available")
    return Header(
        signature=sig,
        length=length,
        revision=_u8(b, 8),
        checksum_ok=checksum_ok(b[:length]),
        oem_id=_text(b[10:16]),
        oem_table_id=_text(b[16:24]),
        oem_revision=_u32(b, 24),
        creator_id=_text(b[28:32]),
        creator_revision=_u32(b, 32),
    )


def parse_sdt_pointers(b: bytes) -> list[int]:
    """Entries of an RSDT (32-bit pointers) or XSDT (64-bit pointers)."""
    h = parse_header(b)
    size = 8 if h.signature == "XSDT" else 4
    count = (h.length - 36) // size
    reader = _u64 if size == 8 else _u32
    return [reader(b, 36 + i * size) for i in range(count)]


# --- Generic Address Structure ------------------------------------------------

ADDRESS_SPACES = {0: "memory", 1: "I/O port", 2: "PCI config", 3: "embedded controller",
                  4: "SMBus", 0x0A: "PCC", 0x7F: "functional fixed hardware"}


@dataclass
class GAS:
    space: int
    bit_width: int
    bit_offset: int
    access_size: int
    address: int

    @property
    def present(self) -> bool:
        return self.address != 0

    def describe(self) -> str:
        if not self.present:
            return "not present"
        space = ADDRESS_SPACES.get(self.space, f"space {self.space:#x}")
        width = f" ({self.bit_width}-bit)" if self.bit_width else ""
        return f"{space} {self.address:#x}{width}"


def parse_gas(b: bytes, off: int) -> GAS:
    return GAS(_u8(b, off), _u8(b, off + 1), _u8(b, off + 2), _u8(b, off + 3), _u64(b, off + 4))


# --- FADT (signature FACP) ----------------------------------------------------

FADT_FLAGS = [
    "WBINVD", "WBINVD_FLUSH", "PROC_C1", "P_LVL2_UP", "PWR_BUTTON", "SLP_BUTTON", "FIX_RTC",
    "RTC_S4", "TMR_VAL_EXT", "DCK_CAP", "RESET_REG_SUP", "SEALED_CASE", "HEADLESS",
    "CPU_SW_SLP", "PCI_EXP_WAK", "USE_PLATFORM_CLOCK", "S4_RTC_STS_VALID",
    "REMOTE_POWER_ON_CAPABLE", "FORCE_APIC_CLUSTER_MODEL", "FORCE_APIC_PHYSICAL_DESTINATION_MODE",
    "HW_REDUCED_ACPI", "LOW_POWER_S0_IDLE_CAPABLE",
]
BOOT_ARCH_FLAGS = ["LEGACY_DEVICES", "8042", "VGA_NOT_PRESENT", "MSI_NOT_SUPPORTED",
                   "PCIE_ASPM_CONTROLS", "CMOS_RTC_NOT_PRESENT"]
PM_PROFILES = ["Unspecified", "Desktop", "Mobile", "Workstation", "Enterprise Server",
               "SOHO Server", "Appliance PC", "Performance Server", "Tablet"]


@dataclass
class FADT:
    header: Header
    firmware_ctrl: int
    dsdt: int
    x_dsdt: int | None
    x_firmware_ctrl: int | None
    pm_profile: int
    sci_int: int
    smi_cmd: int
    acpi_enable: int
    acpi_disable: int
    pm1a_evt_blk: int
    pm1a_cnt_blk: int
    pm1b_cnt_blk: int
    pm_tmr_blk: int
    gpe0_blk: int
    pm1_cnt_len: int
    pm_tmr_len: int
    century: int
    iapc_boot_arch: int | None
    flags: int
    reset_reg: GAS | None
    reset_value: int | None
    x_pm_tmr_blk: GAS | None

    def flag_names(self) -> list[str]:
        return [n for i, n in enumerate(FADT_FLAGS) if self.flags >> i & 1]

    def boot_arch_names(self) -> list[str]:
        if self.iapc_boot_arch is None:
            return []
        return [n for i, n in enumerate(BOOT_ARCH_FLAGS) if self.iapc_boot_arch >> i & 1]

    @property
    def dsdt_address(self) -> int:
        return self.x_dsdt if self.x_dsdt else self.dsdt

    @property
    def facs_address(self) -> int:
        return self.x_firmware_ctrl if self.x_firmware_ctrl else self.firmware_ctrl


def parse_fadt(b: bytes) -> FADT:
    h = parse_header(b)
    if h.signature != "FACP":
        raise ACPIError(f"expected FACP, got {h.signature}")
    n = h.length

    def has(off: int, size: int) -> bool:
        return off + size <= n

    return FADT(
        header=h,
        firmware_ctrl=_u32(b, 36),
        dsdt=_u32(b, 40),
        x_dsdt=_u64(b, 140) if has(140, 8) else None,
        x_firmware_ctrl=_u64(b, 132) if has(132, 8) else None,
        pm_profile=_u8(b, 45),
        sci_int=_u16(b, 46),
        smi_cmd=_u32(b, 48),
        acpi_enable=_u8(b, 52),
        acpi_disable=_u8(b, 53),
        pm1a_evt_blk=_u32(b, 56),
        pm1a_cnt_blk=_u32(b, 64),
        pm1b_cnt_blk=_u32(b, 68),
        pm_tmr_blk=_u32(b, 76),
        gpe0_blk=_u32(b, 80),
        pm1_cnt_len=_u8(b, 89),
        pm_tmr_len=_u8(b, 91),
        century=_u8(b, 108),
        # IAPC_BOOT_ARCH was "reserved" in ACPI 1.0 (FADT revision 1).
        iapc_boot_arch=_u16(b, 109) if h.revision >= 2 and has(109, 2) else None,
        flags=_u32(b, 112) if has(112, 4) else 0,
        reset_reg=parse_gas(b, 116) if has(116, 12) else None,
        reset_value=_u8(b, 128) if has(128, 1) else None,
        x_pm_tmr_blk=parse_gas(b, 208) if has(208, 12) else None,
    )


# --- MADT (signature APIC) ----------------------------------------------------


@dataclass
class MADTEntry:
    type: int
    kind: str
    fields: dict[str, int] = field(default_factory=dict)


@dataclass
class MADT:
    header: Header
    lapic_address: int
    pcat_compat: bool
    entries: list[MADTEntry]

    def of(self, kind: str) -> list[MADTEntry]:
        return [e for e in self.entries if e.kind == kind]


MADT_KINDS = {
    0: "lapic", 1: "ioapic", 2: "iso", 3: "nmi_source", 4: "lapic_nmi",
    5: "lapic_override", 9: "x2apic", 0x0A: "x2apic_nmi",
}


def parse_madt(b: bytes) -> MADT:
    h = parse_header(b)
    if h.signature != "APIC":
        raise ACPIError(f"expected APIC (MADT), got {h.signature}")
    entries: list[MADTEntry] = []
    off = 44
    while off + 2 <= h.length:
        etype, elen = b[off], b[off + 1]
        if elen < 2 or off + elen > h.length:
            raise ACPIError(f"MADT entry at offset {off} has invalid length {elen}")
        e = b[off:off + elen]
        kind = MADT_KINDS.get(etype, f"type_{etype:#x}")
        f: dict[str, int] = {}
        if etype == 0:
            f = {"processor_uid": e[2], "apic_id": e[3], "flags": _u32(e, 4)}
        elif etype == 1:
            f = {"ioapic_id": e[2], "address": _u32(e, 4), "gsi_base": _u32(e, 8)}
        elif etype == 2:
            f = {"bus": e[2], "source_irq": e[3], "gsi": _u32(e, 4), "flags": _u16(e, 8)}
        elif etype == 3:
            f = {"flags": _u16(e, 2), "gsi": _u32(e, 4)}
        elif etype == 4:
            f = {"processor_uid": e[2], "flags": _u16(e, 3), "lint": e[5]}
        elif etype == 5:
            f = {"address": _u64(e, 4)}
        elif etype == 9:
            f = {"x2apic_id": _u32(e, 4), "flags": _u32(e, 8), "processor_uid": _u32(e, 12)}
        elif etype == 0x0A:
            f = {"flags": _u16(e, 2), "processor_uid": _u32(e, 4), "lint": e[8]}
        entries.append(MADTEntry(etype, kind, f))
        off += elen
    return MADT(h, _u32(b, 36), bool(_u32(b, 40) & 1), entries)


def polarity_trigger(flags: int) -> tuple[str, str]:
    """MPS INTI flags used by ISO/NMI entries."""
    pol = {0: "bus default", 1: "active high", 3: "active low"}.get(flags & 3, "reserved")
    trig = {0: "bus default", 1: "edge", 3: "level"}.get(flags >> 2 & 3, "reserved")
    return pol, trig


# --- MCFG ---------------------------------------------------------------------


@dataclass
class MCFGEntry:
    base: int
    segment: int
    start_bus: int
    end_bus: int


def parse_mcfg(b: bytes) -> list[MCFGEntry]:
    h = parse_header(b)
    if h.signature != "MCFG":
        raise ACPIError(f"expected MCFG, got {h.signature}")
    out = []
    for off in range(44, h.length - 15, 16):
        out.append(MCFGEntry(_u64(b, off), _u16(b, off + 8), b[off + 10], b[off + 11]))
    return out


# --- HPET ---------------------------------------------------------------------


@dataclass
class HPET:
    header: Header
    hardware_rev: int
    comparators: int
    counter_64bit: bool
    legacy_replacement: bool
    pci_vendor: int
    base: GAS
    number: int
    min_tick: int


def parse_hpet(b: bytes) -> HPET:
    h = parse_header(b)
    if h.signature != "HPET":
        raise ACPIError(f"expected HPET, got {h.signature}")
    block = _u32(b, 36)
    return HPET(
        header=h,
        hardware_rev=block & 0xFF,
        comparators=(block >> 8 & 0x1F) + 1,
        counter_64bit=bool(block >> 13 & 1),
        legacy_replacement=bool(block >> 15 & 1),
        pci_vendor=block >> 16,
        base=parse_gas(b, 40),
        number=b[52],
        min_tick=_u16(b, 53),
    )


# --- FACS (no standard header, no checksum) -------------------------------------


@dataclass
class FACS:
    length: int
    hardware_signature: int
    waking_vector: int
    global_lock: int
    flags: int
    version: int


def parse_facs(b: bytes) -> FACS:
    if len(b) < 32 or b[:4] != b"FACS":
        raise ACPIError("not a FACS: missing 'FACS' signature")
    return FACS(_u32(b, 4), _u32(b, 8), _u32(b, 12), _u32(b, 16), _u32(b, 20),
                b[32] if len(b) > 32 else 0)


# --- WAET ---------------------------------------------------------------------


def parse_waet(b: bytes) -> dict[str, bool]:
    h = parse_header(b)
    flags = _u32(b, 36) if h.length >= 40 else 0
    return {"rtc_good": bool(flags & 1), "pm_timer_good": bool(flags & 2)}
