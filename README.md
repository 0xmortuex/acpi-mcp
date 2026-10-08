# acpi-mcp

**Let your AI agent read the firmware's ACPI tables and tell you what they mean.**

<!-- mcp-name: io.github.0xmortuex/acpi-mcp -->

acpi-mcp is an [MCP](https://modelcontextprotocol.io) server that reads ACPI tables and
explains them for OS developers. It covers how many CPUs there are and their APIC IDs,
where the I/O APIC lives, which ISA IRQs are remapped, where the HPET and PCIe config
space are, and the exact port writes that power the machine off or reset it.

It reads tables from three places:

- a **live QEMU guest**, out of guest physical memory through QEMU's gdbstub (works
  even after the guest turns on paging);
- a **directory of table files**: Linux's `/sys/firmware/acpi/tables`, or `acpidump -b`
  output from any machine;
- optionally, AML disassembly with `iasl` if you have it installed. Nothing else needs it.

Companion to [qemu-mcp](https://github.com/0xmortuex/qemu-mcp) (boot and drive the VM)
and [gdbstub-mcp](https://github.com/0xmortuex/gdbstub-mcp) (debug the kernel).

## What it looks like

This is real output from QEMU 11 (`-M q35 -smp 2`), read live from the guest:

```
> acpi_table MADT
MADT revision 3: local APIC base 0xfee00000 (dual 8259 PICs present: mask them before using the APIC)
  2 usable CPU(s), APIC IDs [0, 1]
  The BSP is usually APIC ID 0; start the others with INIT-SIPI-SIPI
  I/O APIC id 0 at 0xfec00000, GSI base 0
  Interrupt source overrides (legacy ISA IRQ -> GSI):
    IRQ0 -> GSI 2 (I/O APIC 0 pin 2), bus default, bus default - this is why the PIT timer shows up on I/O APIC pin 2, not 0
    IRQ9 -> GSI 9 (I/O APIC 0 pin 9), active high, level - non-ISA polarity/trigger: program the redirection entry to match
    ...
  Local APIC NMI on LINT1 for all CPUs (bus default, bus default) - program LVT LINT1 as NMI

> acpi_find "how do I shut down the machine?"
Soft power-off (S5): \_S5_ = SLP_TYPa 0, SLP_TYPb 0
  1. If SMI_CMD (0xb2) is non-zero and SCI_EN (bit 0 of PM1a_CNT) is clear, enable ACPI: outb(0xb2, 0x2) and wait for SCI_EN
  2. outw(0x604, 0x2000)   # SLP_TYPa << 10 | SLP_EN (bit 13)

> acpi_find "reboot"
Reset: write 0xf to I/O port 0xcf9 (8-bit) (FADT RESET_REG, RESET_REG_SUP set). Fall back to the 8042 if it returns.

> acpi_find "pci config space"
MCFG: PCI Express ECAM (memory-mapped config space)
  segment 0, buses 0-255: base 0xb0000000 (256 MiB)
    config address of bus B, device D, function F, offset O = 0xb0000000 + ((B - 0) << 20 | D << 15 | F << 12 | O)

> acpi_table DSDT
  8491 bytes of AML bytecode, 37 Device objects
  Recognised devices:
    \_SB_.PCI0                   PNP0A08 (compatible PNP0A03) PCI Express host bridge
    \_SB_.HPET                   PNP0103                    HPET
    \_SB_.PCI0.SF8_.KBD_         PNP0303                    PS/2 keyboard (8042)
    \_SB_.PCI0.SF8_.COM1         PNP0501                    16550 serial port (COM)
    ...
```

**The recipes are tested, not just printed.** The integration tests write the exact
instructions `acpi_find` prescribes into a live guest, run them, and check the
result: the shutdown recipe powers off both `-M pc` and `-M q35`, and the reset
recipe resets q35. A control case that only runs `hlt` keeps running.

## Why

ACPI is the first wall every hobby OS hits after "hello world". You need it for SMP,
the I/O APIC, the HPET, PCIe and power-off. The tables are binary structures spread
across firmware memory, the spec runs to over a thousand pages, and the bugs are silent:
miss the IRQ0 → GSI2 override and your timer simply never fires. This server reads the
tables your firmware actually built and answers in terms of what to program.

As far as I could find, no other MCP server reads or explains ACPI tables.

## Install

```bash
pip install acpi-mcp
claude mcp add acpi -- acpi-mcp
```

## Usage

Start QEMU with its gdbstub (`-s`). `-S` is fine, because acpi-mcp lets the firmware
run until the tables exist:

```bash
qemu-system-x86_64 -M q35 -smp 2 -kernel kernel.elf -s -S
```

Then ask your agent something like *"load the ACPI tables from the VM on port 1234 and
tell me how to route the keyboard interrupt through the I/O APIC"*.

On a Linux machine you can read its own tables (as root):

```
acpi_load(name="host", path="/sys/firmware/acpi/tables")
```

## Tools

| Tool | What it does |
|------|--------------|
| `acpi_load` | Load tables under a name from `port=` (live VM; `boot_wait_s` lets firmware run first; `resume` chooses whether the guest runs on afterwards) or from `path=` (a directory). |
| `acpi_tables` | List every table: address, length, checksum, OEM, and what the table is for. |
| `acpi_table` | Decode one table and explain it: FADT, MADT, HPET, MCFG, DSDT/SSDT, FACS, RSDT/XSDT, WAET, RSDP. |
| `acpi_interrupt_routing` | Map ISA IRQs 0-15 to GSI and I/O APIC pin, with polarity and trigger mode. |
| `acpi_find` | Answer OS-dev questions: shutdown, reset, HPET, PCI config, CPUs, IRQ routing, PM timer, keyboard, serial, RTC century, SCI. |
| `acpi_dump` | Hexdump a table's raw bytes. |
| `acpi_disassemble` | AML to ASL with `iasl -d`, if installed. |
| `acpi_sets` | List loaded table sets. |

## How it reads a live VM

1. It connects to the gdbstub. QEMU pauses the guest while a debugger is attached.
2. It switches the stub to **physical** memory with QEMU's `Qqemu.PhyMemMode:1`, so
   ACPI's physical pointers work even when the guest has paging on. On stubs without
   this packet it reads virtual addresses and says so in the output.
3. It searches the EBDA and `0xE0000-0xFFFFF` for a checksummed `RSD PTR `, then walks
   the XSDT (or RSDT), the FADT, the DSDT and the FACS.
4. If the CPU hasn't run the firmware yet (`-S`), it runs the guest in short bursts until
   a complete, checksum-valid table set exists. It returns as soon as one does.
5. It detaches with `D;1`, and the guest continues. Pass `resume=False` to leave it
   paused, for example before attaching gdbstub-mcp to a `-S` VM. QEMU allows only one
   debugger at a time.

## Limits

- **The AML reader is a structured walker, not an interpreter.** It parses the Scope,
  Device and Name objects that describe devices and skips Method bodies. Anything a
  method computes at runtime, such as a `_STA` that hides a device, isn't evaluated.
  If it ever has to fall back to byte-scanning a region (an `If` at scope level), the
  output says so. Use `acpi_disassemble` (iasl) for an exact listing.
- **UEFI guests (OVMF)** pass the RSDP to the OS through the EFI system table, not the
  BIOS area, so the live search won't find it. Load those tables from a directory
  (`acpidump -b`) for now.
- x86 only for now. ARM's ACPI (GICC/GICD in the MADT, GTDT) is on the backlog.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests && mypy --strict src
pytest tests
```

The unit tests run on **real tables captured from QEMU** (`tests/fixtures/tables/`), so
they need no QEMU. `tests/test_qemu_integration.py` reads live tables from i386 and
x86_64 guests on both `pc` and `q35`, checks that the CPU count follows `-smp`, checks
`resume` semantics, and runs the shutdown and reset recipes inside the guest. It skips
any QEMU binary that isn't installed.

## License

MIT
