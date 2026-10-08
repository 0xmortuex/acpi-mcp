# Backlog

Real, finishable improvements - pick ONE, ship it end-to-end with tests.

## Features
- [ ] UEFI guests: find the RSDP via the EFI system table (scan for the EFI_SYSTEM_TABLE signature, walk ConfigurationTable for the ACPI 2.0 GUID). Test with OVMF.
- [ ] ARM64 ACPI: MADT GICC/GICD/GICR/ITS entries, GTDT (generic timer), SPCR (serial console). Test with `qemu-system-aarch64 -M virt` + edk2.
- [ ] SRAT/SLIT decoding (NUMA) - test with `-numa node` options.
- [ ] `_PRT` (PCI interrupt routing) from the DSDT: device/pin -> link or GSI. Needs Package parsing inside Method-free `_PRT` names; QEMU's are methods, so evaluate the simple case or fall back to iasl.
- [ ] `_CRS` resource templates for well-known devices (I/O ports/IRQ of COM1, the HPET MMIO range) - static ResourceTemplate buffers are parseable without an interpreter.
- [ ] DMAR (VT-d) / IVRS (AMD-Vi) summaries - `-device intel-iommu` gives a DMAR.
- [ ] Diff two table sets (`acpi_diff`): "what changed between pc and q35" / between firmware versions.

## Quality
- [ ] Fuzz the parsers with truncated/corrupted tables (every parser must raise ACPIError, never IndexError).
- [ ] Capture a real-hardware table set (with permission) as a fixture to cover non-QEMU OEM quirks.
