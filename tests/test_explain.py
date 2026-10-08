import os

import pytest

from acpi_mcp import explain as ex
from acpi_mcp.source import SourceError, from_directory

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "tables")


@pytest.fixture(scope="module")
def pc():
    return from_directory(os.path.join(FIX, "pc"))


@pytest.fixture(scope="module")
def q35():
    return from_directory(os.path.join(FIX, "q35"))


def test_directory_reads_signatures_from_content(pc, q35):
    assert {t.signature for t in pc.tables} == {"APIC", "DSDT", "FACP", "FACS", "HPET", "RSDT", "WAET"}
    assert "MCFG" in {t.signature for t in q35.tables}
    assert pc.rsdp is not None and pc.rsdp.revision == 0


def test_directory_notes_non_tables():
    ts = from_directory(FIX)  # walks pc/ and q35/, and sees README.md
    assert any("README.md" in n and "not an ACPI table" in n for n in ts.notes)


def test_directory_errors(tmp_path):
    with pytest.raises(SourceError, match="not a directory"):
        from_directory(str(tmp_path / "nope"))
    (tmp_path / "junk.txt").write_text("hello")
    with pytest.raises(SourceError, match="no ACPI tables"):
        from_directory(str(tmp_path))


def test_find_aliases_and_missing(pc):
    assert pc.find("MADT").signature == "APIC"
    assert pc.find("fadt").signature == "FACP"
    with pytest.raises(KeyError, match="Tables present: APIC"):
        pc.find("MCFG")


def test_list_tables(q35):
    text = ex.list_tables(q35)
    assert "RSDP: ACPI 1.0 (revision 0)" in text
    assert "MCFG rev 1" in text and "BAD CHECKSUM" not in text


def test_madt_explanation_names_the_pit_override(pc):
    text = ex.explain_table(pc, pc.find("APIC"))
    assert "2 usable CPU(s), APIC IDs [0, 1]" in text
    assert "IRQ0 -> GSI 2 (I/O APIC 0 pin 2)" in text
    assert "PIT timer shows up on I/O APIC pin 2" in text
    assert "program LVT LINT1 as NMI" in text


def test_fadt_explanations_differ_by_revision(pc, q35):
    old = ex.explain_table(pc, pc.find("FACP"))
    new = ex.explain_table(q35, q35.find("FACP"))
    assert "No reset register (FADT too old)" in old
    assert "IA-PC boot flags: not present" in old
    assert "Reset: write 0xf to I/O port 0xcf9 (8-bit)" in new
    assert "IA-PC boot flags: 8042" in new
    assert "PM timer: I/O port 0x608, 24-bit" in new


def test_shutdown_recipe(pc):
    text = ex.find(pc, "how do I shut down the machine?")
    assert "outw(0x604, 0x2000)" in text and "SLP_TYPa 0" in text


def test_reset_recipes(pc, q35):
    assert "0xcf9" in ex.find(q35, "reboot")
    assert "0xFE to port 0x64" in ex.find(pc, "reboot")


def test_pci_config(pc, q35):
    assert "0xCF8" in ex.find(pc, "pci config space")
    assert "base 0xb0000000 (256 MiB)" in ex.find(q35, "where is PCIe ECAM")


def test_irq_routing(pc):
    from acpi_mcp import tables as t
    lines = ex.irq_routing(t.parse_madt(pc.find("APIC").raw))
    assert lines[0].startswith("  IRQ0  -> GSI 2") and "NOT on pin 0" in lines[0]
    assert "identity" in lines[1]
    assert "active high, level" in lines[9]  # SCI


def test_sci_and_devices(pc):
    assert "SCI is IRQ 9 -> GSI 9, active high, level" in ex.find(pc, "sci")
    kb = ex.find(pc, "is there a ps/2 keyboard")
    assert "PNP0303" in kb and "FADT revision 1" in kb
    assert "_UID 1" in ex.find(pc, "serial port")


def test_unknown_question(pc):
    assert "I don't have a recipe" in ex.find(pc, "make coffee")


def test_hpet_and_dsdt_explanations(q35):
    assert "3 comparators, 64-bit" in ex.explain_table(q35, q35.find("HPET"))
    dsdt = ex.explain_table(q35, q35.find("DSDT"))
    assert "PS/2 keyboard (8042)" in dsdt and "\\_S5_ (soft off)" in dsdt
    assert "byte-scanned" not in dsdt
