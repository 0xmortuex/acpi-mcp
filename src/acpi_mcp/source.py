"""Where tables come from: a live VM's memory (via its gdbstub) or a directory
of raw table files. Either way the result is the same TableSet, so every
tool works identically on a QEMU guest, a Linux box's
/sys/firmware/acpi/tables, or the output of `acpidump -b`.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from gdbstub_mcp.rsp import RSPClient, RSPError

from . import tables as t


class SourceError(RuntimeError):
    pass


@dataclass
class Table:
    signature: str
    raw: bytes
    address: int | None = None  # guest physical address, when read from a VM
    origin: str = ""            # file name, or "memory"

    @property
    def header(self) -> t.Header | None:
        if self.signature in ("FACS", "RSDP"):
            return None  # neither has a standard header
        return t.parse_header(self.raw)


@dataclass
class TableSet:
    origin: str
    tables: list[Table] = field(default_factory=list)
    rsdp: t.RSDP | None = None
    rsdp_address: int | None = None
    notes: list[str] = field(default_factory=list)

    def find(self, signature: str, index: int = 0) -> Table:
        sig = signature.upper()
        if sig == "FADT":
            sig = "FACP"
        if sig == "MADT":
            sig = "APIC"
        hits = [x for x in self.tables if x.signature == sig]
        if not hits:
            have = ", ".join(sorted({x.signature for x in self.tables}))
            raise KeyError(f"no {signature} table in {self.origin}. Tables present: {have}")
        if index >= len(hits):
            raise KeyError(f"{signature} index {index} out of range: there are {len(hits)}")
        return hits[index]

    def maybe(self, signature: str) -> Table | None:
        try:
            return self.find(signature)
        except KeyError:
            return None


# --- directory source -------------------------------------------------------


def _signature_of(raw: bytes) -> str | None:
    if raw.startswith(b"RSD PTR "):
        return "RSDP"
    sig = raw[:4]
    if len(sig) == 4 and all(48 <= c <= 57 or 65 <= c <= 90 or c == 95 for c in sig):
        return sig.decode()
    return None


def from_directory(path: str) -> TableSet:
    """Load every ACPI table file in a directory.

    Accepts Linux's /sys/firmware/acpi/tables (files named APIC, DSDT,
    SSDT1...) and `acpidump -b` output (apic.dat, dsdt.dat...). The table
    signature is read from each file's first bytes, never from its name.
    Subdirectories (dynamic/, data/) are walked too.
    """
    if not os.path.isdir(path):
        raise SourceError(f"not a directory: {path}")
    ts = TableSet(origin=os.path.abspath(path))
    for root, _dirs, files in os.walk(path):
        for name in sorted(files):
            full = os.path.join(root, name)
            try:
                with open(full, "rb") as fh:
                    raw = fh.read()
            except PermissionError:
                ts.notes.append(f"skipped {name}: permission denied (on Linux, run as root)")
                continue
            sig = _signature_of(raw)
            if sig is None:
                ts.notes.append(f"skipped {os.path.relpath(full, path)}: not an ACPI table")
                continue
            if sig == "RSDP":
                ts.rsdp = t.parse_rsdp(raw)
                continue
            ts.tables.append(Table(sig, raw, origin=os.path.relpath(full, path)))
    if not ts.tables:
        raise SourceError(f"no ACPI tables found in {path}")
    return ts


# --- live VM source ---------------------------------------------------------


class _Memory:
    """Guest *physical* memory through a gdbstub.

    QEMU's gdbstub reads virtual addresses by default, which breaks as soon
    as the guest enables paging and doesn't identity-map firmware memory.
    QEMU supports a vendor packet, Qqemu.PhyMemMode:1, that switches reads to
    physical addresses - exactly what ACPI pointers are. On stubs without it
    reads stay virtual, which is only correct while paging is off, and the
    TableSet says so in its notes.
    """

    def __init__(self, rsp: RSPClient):
        self.rsp = rsp
        self.physical = False
        try:
            supported = rsp.request("qqemu.Supported").decode()
        except RSPError:
            supported = ""
        if "PhyMemMode" in supported and rsp.request("Qqemu.PhyMemMode:1") == b"OK":
            self.physical = True

    def read(self, address: int, length: int) -> bytes:
        try:
            return bytes(self.rsp.read_memory(address, length))
        except RSPError as e:
            mode = "physical" if self.physical else "virtual"
            raise SourceError(f"could not read {length} bytes at {address:#x} ({mode}): {e}") from e

    def restore(self) -> None:
        if self.physical:
            self.rsp.request("Qqemu.PhyMemMode:0")


def _find_rsdp(mem: _Memory) -> tuple[int, bytes] | None:
    """Search where the spec says the RSDP lives: the first KiB of the EBDA,
    then the BIOS area 0xE0000-0xFFFFF, on 16-byte boundaries."""
    ebda = int.from_bytes(mem.read(0x40E, 2), "little") << 4
    regions = [(ebda, 1024)] if 0x80000 <= ebda < 0xA0000 else []
    regions.append((0xE0000, 0x20000))
    for base, size in regions:
        data = mem.read(base, size)
        for off in range(0, size - 20, 16):
            if data[off:off + 8] == b"RSD PTR " and t.checksum_ok(data[off:off + 20]):
                return base + off, data[off:off + 36]
    return None


def _read_table(mem: _Memory, address: int) -> bytes:
    head = mem.read(address, 8)
    length = int.from_bytes(head[4:8], "little")
    if not 8 <= length <= 16 * 1024 * 1024:
        raise SourceError(f"table at {address:#x} has implausible length {length} "
                          f"(signature {head[:4]!r}) - stale or corrupt pointer?")
    return mem.read(address, length)


def _bad_checksums(ts: TableSet) -> list[str]:
    return [x.signature for x in ts.tables if x.header is not None and not x.header.checksum_ok]


def _read_all(mem: _Memory, host: str, port: int) -> TableSet | None:
    """One pass over the tables, or None if there's no RSDP yet."""
    found = _find_rsdp(mem)
    if found is None:
        return None
    rsdp_addr, rsdp_raw = found
    ts = TableSet(origin=f"VM at {host}:{port}", rsdp_address=rsdp_addr)
    ts.rsdp = t.parse_rsdp(rsdp_raw)
    if not mem.physical:
        ts.notes.append("this stub has no physical-memory mode: tables were read through "
                        "virtual addresses, which is only correct while paging is off "
                        "(or firmware memory is identity-mapped)")
    root_addr = ts.rsdp.xsdt_address if ts.rsdp.xsdt_address else ts.rsdp.rsdt_address
    root = _read_table(mem, root_addr)
    ts.tables.append(Table(root[:4].decode(errors="replace"), root, root_addr, "memory"))
    for addr in t.parse_sdt_pointers(root):
        raw = _read_table(mem, addr)
        ts.tables.append(Table(raw[:4].decode(errors="replace"), raw, addr, "memory"))
    fadt = ts.maybe("FACP")
    if fadt is not None:
        f = t.parse_fadt(fadt.raw)
        if f.dsdt_address:
            raw = _read_table(mem, f.dsdt_address)
            ts.tables.append(Table("DSDT", raw, f.dsdt_address, "memory"))
        if f.facs_address:
            raw = _read_table(mem, f.facs_address)
            ts.tables.append(Table("FACS", raw, f.facs_address, "memory"))
    return ts


def from_gdbstub(host: str, port: int, boot_wait_s: float = 0.0, resume: bool = True,
                 timeout_s: float = 10.0) -> TableSet:
    """Read every table from a live VM.

    QEMU pauses the guest while a debugger is attached. resume=True detaches
    afterwards, which RESUMES the guest (standard gdb detach), even one that
    started under -S. resume=False just disconnects and leaves it paused -
    use that to read tables before attaching a debugger to a -S VM.

    If the firmware hasn't run yet (QEMU started with -S, CPU still at the
    reset vector) there are no tables. boot_wait_s > 0 lets the guest run in
    short bursts until a valid table set appears (returning as soon as it
    does), giving up after boot_wait_s seconds.
    """
    try:
        rsp = RSPClient(host, port, connect_timeout=timeout_s, read_timeout=timeout_s)
    except RSPError as e:
        raise SourceError(
            f"{e}. Start QEMU with -s (or -gdb tcp::{port}); note QEMU allows one "
            f"debugger at a time, so disconnect gdbstub-mcp/gdb from this VM first."
        ) from e
    try:
        mem = _Memory(rsp)
        deadline = time.monotonic() + boot_wait_s
        while True:
            ts = _read_all(mem, host, port)
            # A set read while firmware is still writing it shows up as no
            # RSDP or as bad checksums; let the guest run a little and retry.
            settled = ts is not None and not _bad_checksums(ts)
            if settled or time.monotonic() >= deadline:
                break
            rsp.resume()
            if rsp.wait_stop(0.25) is None:
                rsp.interrupt()
        if ts is None:
            raise SourceError(
                "no RSDP found in the EBDA or 0xE0000-0xFFFFF. If QEMU was started with -S, "
                "the firmware hasn't built the tables yet: call again with boot_wait_s=5 (it "
                "returns as soon as the tables exist). UEFI guests (OVMF) put the RSDP "
                "elsewhere and hand it to the OS via the EFI system table - load tables from "
                "a directory (acpidump -b) for those."
            )
        mem.restore()
        return ts
    finally:
        _disconnect(rsp, resume)


def _disconnect(rsp: RSPClient, resume: bool) -> None:
    if resume and not rsp.running:
        # With multiprocess negotiated, QEMU rejects a bare "D" (E22) and the
        # guest stays paused; it needs "D;<pid>". QEMU's pid is always 1.
        detach = "D;1" if rsp.features.get("multiprocess") == "+" else "D"
        rsp.request(detach)
    if rsp.sock is not None:
        rsp.sock.close()
        rsp.sock = None
