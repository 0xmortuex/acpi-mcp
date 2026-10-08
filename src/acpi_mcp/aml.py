"""A small, honest AML reader: enough to answer the questions OS developers
ask of a DSDT without running an AML interpreter.

- `devices()` finds Device() objects with their namespace path and _HID/_CID,
  so "is there a PS/2 keyboard, a serial port, an HPET?" has an answer.
- `sleep_package("_S5_")` decodes the \\_S5_ package - the SLP_TYPa/SLP_TYPb
  values a kernel writes to PM1a_CNT to power the machine off.

This is a scanner, not a parser: AML can only be fully decoded by executing
it (methods can compute anything). The scanner validates every candidate
(opcode, package length, name characters, bounds) so false positives are
rare, but for an exact listing use `iasl -d` (acpi_disassemble).
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field

_NAME_LEAD = set((string.ascii_uppercase + "_").encode())
_NAME_CHARS = set((string.ascii_uppercase + string.digits + "_").encode())

# Well-known hardware IDs an OS developer meets on PCs and in QEMU.
KNOWN_IDS = {
    "PNP0000": "8259 PIC",
    "PNP0100": "8254 PIT (system timer)",
    "PNP0103": "HPET",
    "PNP0200": "8237 DMA controller",
    "PNP0303": "PS/2 keyboard (8042)",
    "PNP0400": "parallel port (LPT)",
    "PNP0501": "16550 serial port (COM)",
    "PNP0700": "floppy controller",
    "PNP0800": "PC speaker",
    "PNP0A03": "PCI host bridge",
    "PNP0A05": "generic container",
    "PNP0A06": "generic container (extended)",
    "PNP0A08": "PCI Express host bridge",
    "PNP0B00": "CMOS RTC",
    "PNP0C01": "system board resources",
    "PNP0C02": "motherboard resources (reserved ranges)",
    "PNP0C04": "x87 FPU",
    "PNP0C0C": "power button",
    "PNP0C0E": "sleep button",
    "PNP0C0F": "PCI interrupt link device",
    "PNP0C14": "WMI",
    "PNP0F13": "PS/2 mouse",
    "ACPI0003": "AC adapter",
    "ACPI0004": "module device",
    "ACPI0006": "GPE block",
    "ACPI0007": "processor device",
    "ACPI0010": "processor container",
    "ACPI0013": "generic event device (hardware-reduced)",
    "QEMU0001": "QEMU pvpanic",
    "QEMU0002": "QEMU fw_cfg",
    "PNP0C09": "embedded controller",
    "PNP0C0A": "control-method battery",
    "PNP0C0D": "lid switch",
}


@dataclass
class Device:
    path: str
    hid: str | None = None
    cids: list[str] = field(default_factory=list)
    uid: int | str | None = None
    offset: int = 0

    @property
    def description(self) -> str | None:
        for i in ([self.hid] if self.hid else []) + self.cids:
            if i in KNOWN_IDS:
                return KNOWN_IDS[i]
        return None


def pkg_length(b: bytes, off: int) -> tuple[int, int]:
    """Decode a PkgLength at off -> (length, bytes used by the encoding)."""
    lead = b[off]
    extra = lead >> 6
    if extra == 0:
        return lead & 0x3F, 1
    if off + extra >= len(b):
        raise IndexError("PkgLength runs past the end of the table")
    length = lead & 0x0F
    for i in range(extra):
        length |= b[off + 1 + i] << (4 + 8 * i)
    return length, 1 + extra


def name_string(b: bytes, off: int) -> tuple[str, int] | None:
    """Decode a NameString at off -> (name, bytes used), or None if invalid."""
    i = off
    prefix = ""
    while i < len(b) and b[i] in (0x5C, 0x5E):  # '\' root, '^' parent
        prefix += chr(b[i])
        i += 1
    if i >= len(b):
        return None
    if b[i] == 0x00:
        return prefix, i + 1 - off
    if b[i] == 0x2E:
        count, i = 2, i + 1
    elif b[i] == 0x2F:
        if i + 1 >= len(b):
            return None
        count, i = b[i + 1], i + 2
    else:
        count = 1
    segs = []
    for _ in range(count):
        seg = b[i:i + 4]
        if len(seg) != 4 or seg[0] not in _NAME_LEAD or not all(c in _NAME_CHARS for c in seg):
            return None
        segs.append(seg.decode())
        i += 4
    return prefix + ".".join(segs), i - off


def decode_eisa_id(value: int) -> str:
    """EisaId("PNP0303") is stored as a compressed 32-bit little-endian value."""
    b = value.to_bytes(4, "little")
    mfg = b[0] << 8 | b[1]
    chars = "".join(chr(0x40 + (mfg >> s & 0x1F)) for s in (10, 5, 0))
    return f"{chars}{b[2]:02X}{b[3]:02X}"


def _data_object(b: bytes, off: int) -> int | str | None:
    """Decode a simple constant: Zero/One/Ones, Byte/Word/DWord/QWord, String."""
    if off >= len(b):
        return None
    op = b[off]
    if op == 0x00:
        return 0
    if op == 0x01:
        return 1
    if op == 0xFF:
        return 0xFFFFFFFFFFFFFFFF
    sizes = {0x0A: 1, 0x0B: 2, 0x0C: 4, 0x0E: 8}
    if op in sizes:
        n = sizes[op]
        return int.from_bytes(b[off + 1:off + 1 + n], "little")
    if op == 0x0D:
        end = b.find(b"\x00", off + 1)
        if end < 0:
            return None
        return b[off + 1:end].decode("ascii", errors="replace")
    return None


def _id_value(b: bytes, off: int) -> str | None:
    if off >= len(b):
        return None
    v = _data_object(b, off)
    if isinstance(v, str):
        return v
    if b[off] == 0x0C and isinstance(v, int):
        return decode_eisa_id(v)
    return None


@dataclass
class _Block:
    kind: str
    name: str
    start: int  # offset of the name (inside the block)
    end: int    # exclusive
    path: str = ""


def _blocks(aml: bytes) -> list[_Block]:
    """Validated Scope/Device/Processor/ThermalZone candidates."""
    ops = {b"\x5b\x82": "Device", b"\x5b\x83": "Processor", b"\x5b\x85": "ThermalZone"}
    out: list[_Block] = []
    i = 0
    n = len(aml)
    while i < n - 2:
        kind = None
        oplen = 0
        two = aml[i:i + 2]
        if two in ops:
            kind, oplen = ops[two], 2
        elif aml[i] == 0x10:
            kind, oplen = "Scope", 1
        if kind is None:
            i += 1
            continue
        try:
            length, used = pkg_length(aml, i + oplen)
        except IndexError:
            i += 1
            continue
        end = i + oplen + length
        name = name_string(aml, i + oplen + used)
        # A real block's package must contain its name and stay in bounds.
        if name is None or end > n or length < used + name[1] or not name[0].strip("\\^"):
            i += 1
            continue
        out.append(_Block(kind, name[0], i + oplen + used + name[1], end))
        i += oplen + used + name[1]  # step INTO the body to find nested blocks
    return out


def _join(parent: str, name: str) -> str:
    if name.startswith("\\"):
        return name
    while name.startswith("^"):
        parent = parent.rsplit(".", 1)[0] if "." in parent else "\\"
        name = name[1:]
    if parent in ("", "\\"):
        return "\\" + name
    return f"{parent}.{name}"


_CONST_SIZES = {0x00: 1, 0x01: 1, 0xFF: 1, 0x0A: 2, 0x0B: 3, 0x0C: 5, 0x0E: 9}


def _skip_data(b: bytes, off: int) -> int | None:
    """Offset just past a DataRefObject at off, or None if it isn't one we know."""
    if off >= len(b):
        return None
    op = b[off]
    if op in _CONST_SIZES:
        return off + _CONST_SIZES[op]
    if op == 0x0D:  # String
        end = b.find(b"\x00", off + 1)
        return None if end < 0 else end + 1
    if op in (0x11, 0x12, 0x13):  # Buffer / Package / VarPackage
        length, _ = pkg_length(b, off + 1)
        return off + 1 + length
    if b[off:off + 2] == b"\x5b\x30":  # Revision
        return off + 2
    name = name_string(b, off)
    if name is not None:  # a reference to another named object
        return off + name[1]
    return None


def _ids_from(b: bytes, off: int) -> list[str]:
    """One ID, or every ID in a Package (as _CID often is)."""
    if b[off] == 0x12:
        length, used = pkg_length(b, off + 1)
        # Clamp: a corrupt length must not walk us off the end of the table.
        end = min(off + 1 + length, len(b))
        p = off + 1 + used + 1  # skip NumElements
        ids = []
        while p < end:
            v = _id_value(b, p)
            if v:
                ids.append(v)
            nxt = _skip_data(b, p)
            if nxt is None:
                break
            p = nxt
        return ids
    v = _id_value(b, off)
    return [v] if v else []


class _Walker:
    """Structured walk of AML term lists, with a validated byte scan as the
    fallback for anything it can't parse (e.g. an If predicate)."""

    def __init__(self, aml: bytes):
        self.b = aml
        self.devices: list[Device] = []
        self.heuristic_regions = 0

    def walk(self, off: int, end: int, scope: str, dev: Device | None) -> None:
        b = self.b
        while off < end:
            op = b[off]
            two = b[off:off + 2]
            try:
                if op == 0x10 or two in (b"\x5b\x82", b"\x5b\x83"):
                    oplen = 1 if op == 0x10 else 2
                    length, used = pkg_length(b, off + oplen)
                    body_end = off + oplen + length
                    name = name_string(b, off + oplen + used)
                    if name is None or body_end > end:
                        raise ValueError
                    path = _join(scope, name[0])
                    body = off + oplen + used + name[1]
                    if op == 0x10:
                        self.walk(body, body_end, path, None)
                    else:
                        child = Device(path, offset=off)
                        self.devices.append(child)
                        if two == b"\x5b\x83":
                            body += 6  # ProcID, PblkAddr, PblkLen
                        self.walk(body, body_end, path, child)
                    off = body_end
                elif op == 0x14 or two in (b"\x5b\x81", b"\x5b\x84", b"\x5b\x85",
                                           b"\x5b\x86", b"\x5b\x87"):
                    # Method / Field / PowerResource / ThermalZone / IndexField /
                    # BankField: never declare devices we need; skip whole.
                    oplen = 1 if op == 0x14 else 2
                    length, _ = pkg_length(b, off + oplen)
                    off += oplen + length
                elif op == 0x08:  # Name(NameString, DataRefObject)
                    name = name_string(b, off + 1)
                    if name is None:
                        raise ValueError
                    val = off + 1 + name[1]
                    if dev is not None:
                        if name[0] == "_HID":
                            ids = _ids_from(b, val)
                            dev.hid = ids[0] if ids else None
                        elif name[0] == "_CID":
                            dev.cids.extend(_ids_from(b, val))
                        elif name[0] == "_UID":
                            uid = _data_object(b, val)
                            dev.uid = uid if isinstance(uid, (int, str)) else None
                    nxt = _skip_data(b, val)
                    if nxt is None:
                        raise ValueError
                    off = nxt
                elif two == b"\x5b\x80":  # OperationRegion
                    name = name_string(b, off + 2)
                    if name is None:
                        raise ValueError
                    p = off + 2 + name[1] + 1  # + RegionSpace
                    for _ in range(2):  # RegionOffset, RegionLen
                        nxt = _skip_data(b, p)
                        if nxt is None:
                            raise ValueError
                        p = nxt
                    off = p
                elif two in (b"\x5b\x01", b"\x5b\x02"):  # Mutex(name, flags) / Event(name)
                    name = name_string(b, off + 2)
                    if name is None:
                        raise ValueError
                    off += 2 + name[1] + (1 if two == b"\x5b\x01" else 0)
                elif op == 0x06:  # Alias(source, alias)
                    first = name_string(b, off + 1)
                    second = name_string(b, off + 1 + first[1]) if first else None
                    if first is None or second is None:
                        raise ValueError
                    off += 1 + first[1] + second[1]
                elif op == 0x15:  # External(name, type, argcount)
                    name = name_string(b, off + 1)
                    if name is None:
                        raise ValueError
                    off += 1 + name[1] + 2
                else:
                    raise ValueError
            except (ValueError, IndexError):
                self._scan(off, end, scope)
                return

    def _scan(self, off: int, end: int, scope: str) -> None:
        """Fallback: validated byte scan of [off, end) for nested blocks."""
        self.heuristic_regions += 1
        sub = self.b[off:end]
        stack: list[_Block] = []
        for blk in _blocks(sub):
            while stack and blk.start >= stack[-1].end:
                stack.pop()
            blk.path = _join(stack[-1].path if stack else scope, blk.name)
            stack.append(blk)
            if blk.kind in ("Device", "Processor"):
                d = Device(blk.path, offset=off + blk.start)
                for key in ("_HID", "_CID", "_UID"):
                    pos = sub.find(b"\x08" + key.encode(), blk.start, blk.end)
                    if pos < 0:
                        continue
                    v = pos + 5
                    if key == "_HID":
                        ids = _ids_from(sub, v)
                        d.hid = ids[0] if ids else None
                    elif key == "_CID":
                        d.cids.extend(_ids_from(sub, v))
                    else:
                        u = _data_object(sub, v)
                        d.uid = u if isinstance(u, (int, str)) else None
                self.devices.append(d)


def scan_devices(aml: bytes) -> tuple[list[Device], int]:
    """(devices, heuristic_regions) for an AML body (DSDT/SSDT minus header).

    heuristic_regions counts stretches the structured walker couldn't parse
    and byte-scanned instead; 0 means every device came from a real parse.
    """
    w = _Walker(aml)
    w.walk(0, len(aml), "\\", None)
    return w.devices, w.heuristic_regions


def devices(aml: bytes) -> list[Device]:
    return scan_devices(aml)[0]


def sleep_package(aml: bytes, name: str = "_S5_") -> tuple[int, int] | None:
    """Decode Name(\\_Sx_, Package() {SLP_TYPa, SLP_TYPb, ...}) -> (a, b)."""
    key = name.encode()
    for pattern in (b"\x08" + key + b"\x12", b"\x08\\" + key + b"\x12"):
        pos = aml.find(pattern)
        if pos < 0:
            continue
        off = pos + len(pattern)
        _length, used = pkg_length(aml, off)
        off += used + 1  # skip NumElements
        values = []
        for _ in range(2):
            v = _data_object(aml, off)
            if not isinstance(v, int):
                return None
            values.append(v)
            off += {0x00: 1, 0x01: 1, 0xFF: 1, 0x0A: 2, 0x0B: 3, 0x0C: 5, 0x0E: 9}[aml[off]]
        return values[0], values[1]
    return None
