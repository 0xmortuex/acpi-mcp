Real ACPI tables captured from QEMU 11.0 (SeaBIOS) with
`qemu-system-i386 -M pc|q35 -smp 2 -m 128`, read out of guest physical memory
through the gdbstub by acpi-mcp itself. Files are named by signature, like
Linux's /sys/firmware/acpi/tables. RSDP is the 20-byte ACPI 1.0 structure.
