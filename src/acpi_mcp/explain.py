"""Turn parsed tables into what an OS developer actually needs to know.

Every renderer answers "so what?" as well as "what": not just "ISO bus 0
source 0 gsi 2" but "IRQ0 (the PIT) arrives on I/O APIC pin 2, not pin 0".
"""

from __future__ import annotations

from . import aml
from . import tables as t
from .source import Table, TableSet

ISA_IRQ_NAMES = {
    0: "PIT timer", 1: "PS/2 keyboard", 2: "cascade", 3: "COM2", 4: "COM1", 5: "LPT2/sound",
    6: "floppy", 7: "LPT1", 8: "CMOS RTC", 9: "ACPI SCI (typical)", 12: "PS/2 mouse",
    13: "FPU", 14: "primary ATA", 15: "secondary ATA",
}

DESCRIPTIONS = {
    "RSDT": "Root System Description Table - 32-bit pointers to every other table",
    "XSDT": "Extended System Description Table - 64-bit pointers (preferred over RSDT)",
    "FACP": "Fixed ACPI Description Table (FADT) - power management hardware, DSDT pointer",
    "APIC": "Multiple APIC Description Table (MADT) - CPUs, I/O APICs, interrupt overrides",
    "DSDT": "Differentiated System Description Table - AML describing the devices",
    "SSDT": "Secondary System Description Table - more AML (CPU hotplug, extra devices)",
    "FACS": "Firmware ACPI Control Structure - waking vector and the global lock",
    "HPET": "High Precision Event Timer description",
    "MCFG": "PCI Express memory-mapped configuration space (ECAM) ranges",
    "WAET": "Windows ACPI Emulated devices Table - tells the OS which emulated devices are safe",
    "SRAT": "System Resource Affinity Table - NUMA nodes",
    "SLIT": "System Locality Information Table - NUMA distances",
    "BGRT": "Boot Graphics Resource Table - the boot logo",
    "DMAR": "DMA Remapping (Intel VT-d IOMMU)",
    "IVRS": "I/O Virtualization Reporting (AMD IOMMU)",
    "TPM2": "Trusted Platform Module 2.0",
    "SPCR": "Serial Port Console Redirection",
}


def _hdr_line(tb: Table) -> str:
    where = f" @ {tb.address:#x}" if tb.address is not None else f" ({tb.origin})"
    h = tb.header
    if h is None:
        return f"{tb.signature}{where}, {len(tb.raw)} bytes"
    ok = "ok" if h.checksum_ok else "BAD CHECKSUM"
    return (f"{h.signature} rev {h.revision}{where}, {h.length} bytes, checksum {ok}, "
            f"OEM {h.oem_id!r}/{h.oem_table_id!r}, creator {h.creator_id!r}")


def list_tables(ts: TableSet) -> str:
    lines = [f"ACPI tables from {ts.origin}:"]
    if ts.rsdp is not None:
        r = ts.rsdp
        where = f" @ {ts.rsdp_address:#x}" if ts.rsdp_address is not None else ""
        root = f"XSDT {r.xsdt_address:#x}" if r.xsdt_address else f"RSDT {r.rsdt_address:#x}"
        ok = "ok" if r.checksum_ok and r.ext_checksum_ok is not False else "BAD CHECKSUM"
        lines.append(f"  RSDP{where}: ACPI {r.acpi_version} (revision {r.revision}), "
                     f"OEM {r.oem_id!r}, points to {root}, checksum {ok}")
    for tb in ts.tables:
        desc = DESCRIPTIONS.get(tb.signature[:4], "")
        lines.append(f"  {_hdr_line(tb)}" + (f"\n      {desc}" if desc else ""))
    bad = [tb.signature for tb in ts.tables if tb.header is not None and not tb.header.checksum_ok]
    if bad:
        lines.append(f"\n{len(bad)} table(s) fail their checksum: {', '.join(bad)}. "
                     "Linux logs these and uses them anyway; a strict OS may reject them. "
                     "In a VM it usually means the read happened while firmware was still "
                     "writing, or the pointer was stale.")
    lines += [f"note: {n}" for n in ts.notes]
    return "\n".join(lines)


def explain_rsdp(r: t.RSDP) -> str:
    lines = [f"RSDP: ACPI {r.acpi_version} (revision {r.revision}), OEM {r.oem_id!r}",
             f"  RSDT at {r.rsdt_address:#x}"]
    if r.xsdt_address is not None:
        lines.append(f"  XSDT at {r.xsdt_address:#x} - use this one; it has 64-bit pointers")
    else:
        lines.append("  no XSDT (ACPI 1.0 RSDP): walk the RSDT's 32-bit pointers")
    lines.append(f"  checksum (first 20 bytes): {'ok' if r.checksum_ok else 'BAD'}")
    if r.ext_checksum_ok is not None:
        lines.append(f"  extended checksum: {'ok' if r.ext_checksum_ok else 'BAD'}")
    return "\n".join(lines)


def explain_fadt(f: t.FADT) -> str:
    profile = t.PM_PROFILES[f.pm_profile] if f.pm_profile < len(t.PM_PROFILES) else f.pm_profile
    lines = [f"FADT (FACP) revision {f.header.revision}, {f.header.length} bytes",
             f"  DSDT at {f.dsdt_address:#x}, FACS at {f.facs_address:#x}",
             f"  Preferred PM profile: {profile}"]
    if f.flags >> 20 & 1:
        lines.append("  HW_REDUCED_ACPI: no fixed hardware (no PM1/PM timer/SCI legacy) - "
                     "typical of ARM and some modern x86 tablets")
    lines.append(f"  SCI interrupt: IRQ {f.sci_int} - the interrupt ACPI events arrive on "
                 "(check MADT overrides for its GSI and polarity)")
    if f.smi_cmd:
        lines.append(f"  ACPI mode switch: write {f.acpi_enable:#x} to port {f.smi_cmd:#x} to enable "
                     f"ACPI ({f.acpi_disable:#x} to disable). If SCI_EN in PM1a_CNT is already set, "
                     "the firmware already did it.")
    else:
        lines.append("  SMI_CMD is 0: the system is always in ACPI mode, no switch needed")
    lines.append(f"  PM1a event block: I/O {f.pm1a_evt_blk:#x}; PM1a control block: I/O "
                 f"{f.pm1a_cnt_blk:#x}" + (f"; PM1b control: {f.pm1b_cnt_blk:#x}" if f.pm1b_cnt_blk else ""))
    if f.pm_tmr_blk:
        bits = 32 if f.flags >> 8 & 1 else 24
        lines.append(f"  PM timer: I/O port {f.pm_tmr_blk:#x}, {bits}-bit counter at 3.579545 MHz "
                     f"(wraps every {(1 << bits) / 3579545:.1f}s) - a reliable calibration source")
    if f.century:
        lines.append(f"  RTC century register: CMOS index {f.century:#x}")
    else:
        lines.append("  RTC century register: not provided (assume 20xx)")
    if f.iapc_boot_arch is not None:
        names = f.boot_arch_names()
        lines.append(f"  IA-PC boot flags: {', '.join(names) or 'none'}")
        if "8042" not in names:
            lines.append("    8042 bit clear: firmware does not promise a PS/2 controller - "
                         "on real hardware, probe before using port 0x64")
    else:
        lines.append("  IA-PC boot flags: not present (FADT revision 1 / ACPI 1.0) - "
                     "assume legacy devices and an 8042 exist, but probe")
    if f.reset_reg is not None and f.flags >> 10 & 1:
        lines.append(f"  Reset: write {f.reset_value:#x} to {f.reset_reg.describe()} "
                     "(RESET_REG_SUP is set)")
    elif f.reset_reg is not None:
        lines.append("  Reset register present but RESET_REG_SUP is clear - don't rely on it")
    else:
        lines.append("  No reset register (FADT too old) - reset via the 8042 (write 0xFE to "
                     "port 0x64) or a triple fault")
    lines.append(f"  Flags: {', '.join(f.flag_names()) or 'none'}")
    return "\n".join(lines)


def irq_routing(m: t.MADT) -> list[str]:
    """ISA IRQ -> GSI map with the reason for each non-identity entry."""
    overrides = {e.fields["source_irq"]: e for e in m.of("iso") if e.fields["bus"] == 0}
    lines = []
    for irq in range(16):
        name = ISA_IRQ_NAMES.get(irq, "")
        if irq in overrides:
            e = overrides[irq]
            pol, trig = t.polarity_trigger(e.fields["flags"])
            gsi = e.fields["gsi"]
            note = "  <-- override" + (f": IRQ{irq} is NOT on pin {irq}" if gsi != irq else "")
            lines.append(f"  IRQ{irq:<2} -> GSI {gsi:<3} {pol}, {trig}  {name}{note}")
        else:
            lines.append(f"  IRQ{irq:<2} -> GSI {irq:<3} (identity, ISA default: active high, edge)  {name}")
    return lines


def _gsi_owner(m: t.MADT, gsi: int) -> str:
    ioapics = sorted(m.of("ioapic"), key=lambda e: e.fields["gsi_base"])
    owner = None
    for e in ioapics:
        if gsi >= e.fields["gsi_base"]:
            owner = e
    if owner is None:
        return "no I/O APIC covers it"
    pin = gsi - owner.fields["gsi_base"]
    return f"I/O APIC {owner.fields['ioapic_id']} pin {pin}"


def explain_madt(m: t.MADT) -> str:
    cpus = [e for e in m.of("lapic") + m.of("x2apic")]
    enabled = [e for e in cpus if e.fields["flags"] & 1]
    capable = [e for e in cpus if not e.fields["flags"] & 1 and e.fields["flags"] & 2]
    ids = [e.fields.get("apic_id", e.fields.get("x2apic_id")) for e in enabled]
    lines = [f"MADT revision {m.header.revision}: local APIC base {m.lapic_address:#x}"
             + (" (dual 8259 PICs present: mask them before using the APIC)" if m.pcat_compat else ""),
             f"  {len(enabled)} usable CPU(s), APIC IDs {ids}"
             + (f"; {len(capable)} more hot-pluggable" if capable else "")]
    disabled = [e for e in cpus if not e.fields["flags"] & 3]
    if disabled:
        lines.append(f"  {len(disabled)} disabled CPU entr(y/ies) - firmware placeholders, do not start them")
    if enabled:
        lines.append(f"  The BSP is usually APIC ID {ids[0]}; start the others with INIT-SIPI-SIPI")
    for e in m.of("lapic_override"):
        lines.append(f"  Local APIC address override: {e.fields['address']:#x} - use this, not the base above")
    for e in m.of("ioapic"):
        lines.append(f"  I/O APIC id {e.fields['ioapic_id']} at {e.fields['address']:#x}, "
                     f"GSI base {e.fields['gsi_base']}")
    isos = m.of("iso")
    if isos:
        lines.append("  Interrupt source overrides (legacy ISA IRQ -> GSI):")
        for e in isos:
            pol, trig = t.polarity_trigger(e.fields["flags"])
            irq, gsi = e.fields["source_irq"], e.fields["gsi"]
            why = ""
            if irq == 0 and gsi == 2:
                why = " - this is why the PIT timer shows up on I/O APIC pin 2, not 0"
            elif pol == "active high" and trig == "level" or pol == "active low":
                why = " - non-ISA polarity/trigger: program the redirection entry to match"
            lines.append(f"    IRQ{irq} -> GSI {gsi} ({_gsi_owner(m, gsi)}), {pol}, {trig}{why}")
    for e in m.of("nmi_source"):
        lines.append(f"  NMI source: GSI {e.fields['gsi']}")
    for e in m.of("lapic_nmi") + m.of("x2apic_nmi"):
        who = "all CPUs" if e.fields["processor_uid"] in (0xFF, 0xFFFFFFFF) else f"CPU uid {e.fields['processor_uid']}"
        pol, trig = t.polarity_trigger(e.fields["flags"])
        lines.append(f"  Local APIC NMI on LINT{e.fields['lint']} for {who} ({pol}, {trig}) - "
                     f"program LVT LINT{e.fields['lint']} as NMI")
    other = [e for e in m.entries if e.kind.startswith("type_")]
    if other:
        lines.append(f"  {len(other)} other entr(y/ies): {', '.join(e.kind for e in other)}")
    return "\n".join(lines)


def explain_mcfg(entries: list[t.MCFGEntry]) -> str:
    lines = ["MCFG: PCI Express ECAM (memory-mapped config space)"]
    for e in entries:
        size = (e.end_bus - e.start_bus + 1) << 20
        lines.append(f"  segment {e.segment}, buses {e.start_bus}-{e.end_bus}: base {e.base:#x} "
                     f"({size >> 20} MiB)")
        lines.append(f"    config address of bus B, device D, function F, offset O = "
                     f"{e.base:#x} + ((B - {e.start_bus}) << 20 | D << 15 | F << 12 | O)")
    lines.append("  Map this range uncached. Without MCFG, use legacy I/O ports 0xCF8/0xCFC "
                 "(first 256 bytes of config space only).")
    return "\n".join(lines)


def explain_hpet(h: t.HPET) -> str:
    return "\n".join([
        f"HPET #{h.number}: registers at {h.base.describe()}",
        f"  {h.comparators} comparators, {'64' if h.counter_64bit else '32'}-bit main counter, "
        f"vendor {h.pci_vendor:#06x}, hardware rev {h.hardware_rev}",
        f"  legacy replacement routing {'supported' if h.legacy_replacement else 'NOT supported'}"
        + (" (can replace the PIT on IRQ0 and the RTC on IRQ8)" if h.legacy_replacement else ""),
        f"  minimum periodic tick: {h.min_tick} counter ticks",
        "  Read the period (femtoseconds per tick) from bits 63:32 of the capabilities "
        "register at offset 0 of the register block.",
    ])


def explain_facs(f: t.FACS) -> str:
    return "\n".join([
        f"FACS: {f.length} bytes, version {f.version}, hardware signature {f.hardware_signature:#x}",
        f"  firmware waking vector {f.waking_vector:#x} - where the CPU resumes after S3",
        f"  global lock: {f.global_lock:#x} (shared with firmware; take it before touching "
        "hardware the AML also uses)",
    ])


def explain_aml(tb: Table) -> str:
    body = tb.raw[36:]
    devs, heuristic = aml.scan_devices(body)
    lines = [_hdr_line(tb), f"  {len(body)} bytes of AML bytecode, {len(devs)} Device objects"]
    if heuristic:
        lines.append(f"  ({heuristic} region(s) couldn't be parsed structurally and were "
                     "byte-scanned; use acpi_disassemble for an exact listing)")
    known = [d for d in devs if d.description]
    if known:
        lines.append("  Recognised devices:")
        for d in known:
            ids = d.hid + (f" (compatible {', '.join(d.cids)})" if d.cids else "") if d.hid else ", ".join(d.cids)
            lines.append(f"    {d.path:<28} {ids:<26} {d.description}")
    unknown = [d for d in devs if d.hid and not d.description]
    if unknown:
        lines.append("  Other devices with IDs: " + ", ".join(f"{d.path} ({d.hid})" for d in unknown))
    s5 = aml.sleep_package(body)
    if s5 is not None:
        lines.append(f"  \\_S5_ (soft off): SLP_TYPa={s5[0]}, SLP_TYPb={s5[1]}")
    return "\n".join(lines)


def explain_table(ts: TableSet, tb: Table) -> str:
    sig = tb.signature
    if sig == "FACP":
        return explain_fadt(t.parse_fadt(tb.raw))
    if sig == "APIC":
        return explain_madt(t.parse_madt(tb.raw))
    if sig == "MCFG":
        return explain_mcfg(t.parse_mcfg(tb.raw))
    if sig == "HPET":
        return explain_hpet(t.parse_hpet(tb.raw))
    if sig == "FACS":
        return explain_facs(t.parse_facs(tb.raw))
    if sig in ("DSDT", "SSDT"):
        return explain_aml(tb)
    if sig in ("RSDT", "XSDT"):
        ptrs = t.parse_sdt_pointers(tb.raw)
        names = {x.address: x.signature for x in ts.tables if x.address is not None}
        lines = [_hdr_line(tb), f"  {len(ptrs)} pointers:"]
        lines += [f"    {p:#x}" + (f" -> {names[p]}" if p in names else "") for p in ptrs]
        return "\n".join(lines)
    if sig == "WAET":
        w = t.parse_waet(tb.raw)
        return "\n".join([_hdr_line(tb),
                          f"  RTC good: {w['rtc_good']} (no need to wait for update-in-progress)",
                          f"  PM timer good: {w['pm_timer_good']} (one read is enough, no re-read)",
                          "  Present on QEMU/Hyper-V: you are almost certainly in a VM."])
    desc = DESCRIPTIONS.get(sig, "no decoder for this table yet")
    return f"{_hdr_line(tb)}\n  {desc}. Use acpi_dump for the raw bytes."


# --- acpi_find: questions an OS developer actually asks ------------------------


def _shutdown(ts: TableSet) -> str:
    fadt_t = ts.maybe("FACP")
    dsdt_t = ts.maybe("DSDT")
    if fadt_t is None or dsdt_t is None:
        return "Shutdown needs both the FADT and the DSDT, and one of them is missing."
    f = t.parse_fadt(fadt_t.raw)
    s5 = aml.sleep_package(dsdt_t.raw[36:])
    if s5 is None:
        return ("No \\_S5_ package found in the DSDT, so soft-off isn't described statically. "
                "On QEMU you can write 0x2000 to port 0x604 (PIIX) as a QEMU-only fallback.")
    a = (s5[0] << 10) | (1 << 13)
    out = [f"Soft power-off (S5): \\_S5_ = SLP_TYPa {s5[0]}, SLP_TYPb {s5[1]}",
           f"  1. If SMI_CMD ({f.smi_cmd:#x}) is non-zero and SCI_EN (bit 0 of PM1a_CNT) is clear, "
           f"enable ACPI: outb({f.smi_cmd:#x}, {f.acpi_enable:#x}) and wait for SCI_EN",
           f"  2. outw({f.pm1a_cnt_blk:#x}, {a:#06x})   # SLP_TYPa << 10 | SLP_EN (bit 13)"]
    if f.pm1b_cnt_blk:
        out.append(f"  3. outw({f.pm1b_cnt_blk:#x}, {(s5[1] << 10) | (1 << 13):#06x})   # PM1b, same")
    out.append("  Strictly, the spec says to run \\_PTS(5) first; most hobby kernels skip it "
               "and it works on QEMU and most PCs.")
    return "\n".join(out)


def _reset(ts: TableSet) -> str:
    fadt_t = ts.maybe("FACP")
    if fadt_t is not None:
        f = t.parse_fadt(fadt_t.raw)
        if f.reset_reg is not None and f.flags >> 10 & 1:
            return (f"Reset: write {f.reset_value:#x} to {f.reset_reg.describe()} "
                    f"(FADT RESET_REG, RESET_REG_SUP set). Fall back to the 8042 if it returns.")
    return ("No usable FADT reset register (FADT too old or RESET_REG_SUP clear). Reset via "
            "the 8042 keyboard controller (write 0xFE to port 0x64), or as a last resort "
            "load a zero-length IDT and trigger an interrupt (triple fault).")


def find(ts: TableSet, query: str) -> str:
    q = query.lower()
    answers: list[str] = []

    def want(*words: str) -> bool:
        return any(w in q for w in words)

    if want("shutdown", "shut down", "power off", "poweroff", "power down", "s5", "turn off", "halt the machine"):
        answers.append(_shutdown(ts))
    if want("reset", "reboot", "restart"):
        answers.append(_reset(ts))
    if want("hpet", "high precision"):
        h = ts.maybe("HPET")
        answers.append(explain_hpet(t.parse_hpet(h.raw)) if h else
                       "No HPET table: there is no HPET (or the firmware hides it). Use the "
                       "PM timer or the LAPIC timer calibrated against the PIT.")
    if want("pci", "ecam", "mcfg", "config space"):
        m = ts.maybe("MCFG")
        answers.append(explain_mcfg(t.parse_mcfg(m.raw)) if m else
                       "No MCFG table: no memory-mapped PCIe config space is advertised "
                       "(e.g. QEMU -M pc). Use legacy port I/O: address to 0xCF8, data at 0xCFC.")
    if want("cpu", "core", "smp", "processor", "apic id", "lapic"):
        m = ts.maybe("APIC")
        answers.append(explain_madt(t.parse_madt(m.raw)) if m else
                       "No MADT: assume a single CPU and the legacy 8259 PICs.")
    if want("ioapic", "io apic", "i/o apic", "irq", "interrupt", "gsi"):
        m = ts.maybe("APIC")
        if m:
            madt = t.parse_madt(m.raw)
            answers.append("Legacy IRQ routing (from MADT):\n" + "\n".join(irq_routing(madt)))
    if want("timer", "pm timer", "calibrat"):
        fadt_t = ts.maybe("FACP")
        if fadt_t:
            f = t.parse_fadt(fadt_t.raw)
            if f.pm_tmr_blk:
                bits = 32 if f.flags >> 8 & 1 else 24
                answers.append(f"ACPI PM timer: read port {f.pm_tmr_blk:#x} (32-bit inl), "
                               f"{bits}-bit counter at 3.579545 MHz - ideal for calibrating "
                               "the LAPIC timer or TSC.")
    if want("keyboard", "ps/2", "ps2", "8042", "mouse"):
        fadt_t = ts.maybe("FACP")
        dsdt_t = ts.maybe("DSDT")
        lines = []
        if fadt_t:
            f = t.parse_fadt(fadt_t.raw)
            if f.iapc_boot_arch is None:
                lines.append("FADT revision 1 has no IA-PC boot flags: an 8042 is assumed.")
            else:
                has = "8042" in f.boot_arch_names()
                lines.append(f"FADT IA-PC boot flags: 8042 {'present' if has else 'NOT advertised'}.")
        if dsdt_t:
            devs = [d for d in aml.devices(dsdt_t.raw[36:]) if d.hid in ("PNP0303", "PNP0F13")]
            lines += [f"DSDT: {d.path} ({d.hid}, {d.description})" for d in devs]
        answers.append("\n".join(lines) or "No FADT/DSDT to answer from.")
    if want("serial", "com1", "uart", "16550"):
        dsdt_t = ts.maybe("DSDT")
        if dsdt_t:
            devs = [d for d in aml.devices(dsdt_t.raw[36:]) if d.hid == "PNP0501"]
            answers.append("\n".join(f"Serial port: {d.path} (_UID {d.uid})" for d in devs)
                           or "No 16550 (PNP0501) device in the DSDT.")
    if want("century", "rtc", "cmos"):
        fadt_t = ts.maybe("FACP")
        if fadt_t:
            c = t.parse_fadt(fadt_t.raw).century
            answers.append(f"RTC century: CMOS register {c:#x}" if c else
                           "FADT has no century register: assume 20xx.")
    if want("sci", "acpi event", "acpi interrupt"):
        fadt_t, m = ts.maybe("FACP"), ts.maybe("APIC")
        if fadt_t:
            irq = t.parse_fadt(fadt_t.raw).sci_int
            line = f"SCI is IRQ {irq}"
            if m:
                madt = t.parse_madt(m.raw)
                iso = [e for e in madt.of("iso") if e.fields["source_irq"] == irq]
                if iso:
                    pol, trig = t.polarity_trigger(iso[0].fields["flags"])
                    line += f" -> GSI {iso[0].fields['gsi']}, {pol}, {trig} (per MADT override)"
                else:
                    line += " (no override: GSI equals IRQ; the spec makes SCI level/active-low "
                    line += "unless an override says otherwise)"
            answers.append(line)
    if not answers:
        return ("I don't have a recipe for that. Try: shutdown, reset, hpet, pci config, cpus, "
                "irq routing, pm timer, keyboard, serial, rtc century, sci. Or read a table "
                "directly with acpi_table.")
    return "\n\n".join(answers)
