# Changelog

## 0.1.0 - 2026-10-08

First release.

- Table sources: a live VM through its gdbstub (guest physical memory via QEMU's
  `Qqemu.PhyMemMode`, firmware allowed to run until a checksum-valid set exists,
  `D;1` detach so the guest resumes, or `resume=False` to leave it paused), or a
  directory of table files (`/sys/firmware/acpi/tables`, `acpidump -b`).
- Parsers: RSDP v1/v2, RSDT/XSDT, FADT (rev 1-6 fields, flags, IA-PC boot flags, GAS
  reset register), MADT (LAPIC, I/O APIC, ISO, NMI, LAPIC NMI, LAPIC override, x2APIC,
  x2APIC NMI), MCFG, HPET, FACS, WAET, generic header + checksum for any table.
- AML: structured walk of Scope/Device/Name objects for device paths and
  _HID/_CID/_UID (EISA IDs decoded, well-known IDs named), and the `\_S5_` package.
- Explanations and recipes: `acpi_find` for shutdown, reset, HPET, PCIe ECAM, CPUs,
  IRQ routing, PM timer, PS/2, serial, RTC century, SCI. `acpi_interrupt_routing` for
  the ISA IRQ to GSI map.
- `acpi_disassemble` via `iasl -d` when it is installed.
