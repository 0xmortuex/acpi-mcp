"""acpi-mcp: an MCP server that reads ACPI tables and explains them."""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from typing import Any, TypeVar

from gdbstub_mcp.rsp import RSPError
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import explain as ex
from . import tables as t
from .source import SourceError, TableSet, from_directory, from_gdbstub

mcp = MCPServer(
    "acpi",
    instructions=(
        "Read and explain ACPI tables for OS development: CPUs and APIC IDs, I/O APICs and "
        "interrupt overrides, HPET, PCIe ECAM, power-off and reset recipes. First load a "
        "table set under a name: acpi_load with port= (a QEMU VM started with -s; tables "
        "are read from guest physical memory) or path= (/sys/firmware/acpi/tables, or "
        "`acpidump -b` output). Then: acpi_tables to list, acpi_table to decode and explain "
        "one, acpi_find for questions like 'how do I shut down', acpi_interrupt_routing for "
        "the ISA IRQ -> GSI map, acpi_dump for raw bytes, acpi_disassemble for AML (needs iasl)."
    ),
)

_sets: dict[str, TableSet] = {}

F = TypeVar("F", bound=Callable[..., Any])

# Failures an agent can act on. MCPServer only forwards a ToolError's message
# to the client - anything else arrives as a bare "Error executing tool X" -
# so these are re-raised as ToolError with their text intact. Anything not
# listed here is a genuine bug and stays hidden from the client.
_EXPECTED = (SourceError, t.ACPIError, RSPError, KeyError, ValueError, FileNotFoundError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            # KeyError's str() wraps the message in quotes; use the raw text.
            msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(str(msg)) from e

    mcp.tool()(wrapper)
    return fn


def _get(name: str) -> TableSet:
    ts = _sets.get(name)
    if ts is None:
        known = ", ".join(sorted(_sets)) or "none"
        raise KeyError(f"no table set named {name!r} (loaded: {known}) - call acpi_load first")
    return ts


@tool
def acpi_load(
    name: str,
    port: int | None = None,
    host: str = "127.0.0.1",
    path: str | None = None,
    boot_wait_s: float = 0.0,
    resume: bool = True,
) -> str:
    """Load a set of ACPI tables and register it under `name`.

    Pass exactly one source:
    - port: a live VM's gdbstub (QEMU -s is port 1234). Tables are read from
      guest PHYSICAL memory, so this works even after the guest enables
      paging. QEMU allows one debugger at a time - disconnect gdbstub-mcp first.
      QEMU pauses the guest while attached; resume=True detaches afterwards
      (the guest runs on, even one started with -S), resume=False leaves it paused.
      If QEMU was started with -S the firmware hasn't built the tables yet:
      set boot_wait_s=5: it runs the guest until the tables exist, then stops.
    - path: a directory of raw tables - /sys/firmware/acpi/tables on Linux
      (needs root), or the output of `acpidump -b` (any OS).
    Tables are a snapshot; load again to re-read.
    """
    if (port is None) == (path is None):
        raise ValueError("pass exactly one of port= (live VM) or path= (directory of tables)")
    if path is not None:
        ts = from_directory(path)
    else:
        assert port is not None
        ts = from_gdbstub(host, port, boot_wait_s=boot_wait_s, resume=resume)
    _sets[name] = ts
    return f"Loaded {name!r}: {len(ts.tables)} tables.\n\n" + ex.list_tables(ts)


@tool
def acpi_tables(name: str) -> str:
    """List every table: signature, address, length, checksum, OEM, and what it's for."""
    return ex.list_tables(_get(name))


@tool
def acpi_table(name: str, signature: str, index: int = 0) -> str:
    """Decode one table and explain what it means for an OS.

    signature: FACP/FADT, APIC/MADT, HPET, MCFG, DSDT, SSDT, FACS, RSDT, XSDT,
    WAET, RSDP. index picks among duplicates (e.g. several SSDTs).
    """
    ts = _get(name)
    if signature.upper() == "RSDP":
        if ts.rsdp is None:
            raise KeyError("this table set has no RSDP (directory sources usually don't)")
        return ex.explain_rsdp(ts.rsdp)
    return ex.explain_table(ts, ts.find(signature, index))


@tool
def acpi_interrupt_routing(name: str) -> str:
    """Map every legacy ISA IRQ (0-15) to its GSI and I/O APIC pin, with
    polarity and trigger mode, from the MADT's interrupt source overrides.
    This is the table to program I/O APIC redirection entries from."""
    ts = _get(name)
    madt = t.parse_madt(ts.find("APIC").raw)
    ioapics = ", ".join(f"id {e.fields['ioapic_id']} @ {e.fields['address']:#x} "
                        f"(GSI base {e.fields['gsi_base']})" for e in madt.of("ioapic"))
    return f"I/O APICs: {ioapics or 'none'}\n" + "\n".join(ex.irq_routing(madt))


@tool
def acpi_find(name: str, question: str) -> str:
    """Answer an OS-developer question from the tables, with the exact ports,
    addresses and values to use. Understands: shutdown / power off, reset /
    reboot, hpet, pci config / ecam, cpus / smp, irq routing / ioapic,
    pm timer, keyboard / ps2, serial, rtc century, sci."""
    return ex.find(_get(name), question)


@tool
def acpi_dump(name: str, signature: str, offset: int = 0, length: int = 256, index: int = 0) -> str:
    """Hexdump a table's raw bytes (offset/length within the table, max 4096 bytes)."""
    if not 0 < length <= 4096:
        raise ValueError("length must be between 1 and 4096")
    tb = _get(name).find(signature, index)
    if offset < 0 or offset >= len(tb.raw):
        raise ValueError(f"offset {offset} is outside the table ({len(tb.raw)} bytes)")
    data = tb.raw[offset:offset + length]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:06x}: {hexpart:<47}  {asc}")
    return f"{tb.signature} ({len(tb.raw)} bytes total)\n" + "\n".join(lines)


@tool
def acpi_disassemble(name: str, signature: str = "DSDT", index: int = 0,
                     max_chars: int = 40000) -> str:
    """Disassemble a DSDT/SSDT's AML to ASL source with ACPICA's `iasl -d`.

    Needs iasl on PATH (Debian/Ubuntu: apt install acpica-tools; macOS:
    brew install acpica; Windows: the ACPICA release from intel.com/acpi).
    acpi_table already lists devices and \\_S5_ without iasl.
    """
    iasl = shutil.which("iasl")
    if iasl is None:
        raise FileNotFoundError(
            "iasl not found on PATH. Install ACPICA tools (apt install acpica-tools / "
            "brew install acpica / Windows release from https://www.intel.com/content/www/"
            "us/en/developer/topic-technology/open/acpica/download.html). acpi_table "
            f"{signature} works without it for devices and \\_S5_."
        )
    tb = _get(name).find(signature, index)
    if tb.signature not in ("DSDT", "SSDT"):
        raise ValueError(f"{tb.signature} isn't AML; only DSDT/SSDT can be disassembled")
    with tempfile.TemporaryDirectory() as tmp:
        aml_path = os.path.join(tmp, "table.aml")
        with open(aml_path, "wb") as fh:
            fh.write(tb.raw)
        proc = subprocess.run([iasl, "-d", aml_path], capture_output=True, text=True,
                              timeout=60, cwd=tmp)
        dsl = os.path.join(tmp, "table.dsl")
        if proc.returncode != 0 or not os.path.isfile(dsl):
            raise ValueError(f"iasl failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
        with open(dsl, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n... [{len(text) - max_chars} more characters truncated]"
    return text


@tool
def acpi_sets() -> str:
    """List loaded table sets."""
    if not _sets:
        return "No table sets loaded - call acpi_load."
    return "\n".join(f"{n}: {ts.origin}, {len(ts.tables)} tables" for n, ts in _sets.items())


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
