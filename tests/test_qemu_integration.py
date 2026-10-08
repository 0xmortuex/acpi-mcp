"""Against real QEMU: read live tables through the gdbstub on four machine
configurations, then execute the shutdown and reset recipes acpi_find gives
inside the guest and check the machine actually powers off / resets.

Skipped for any qemu-system binary that isn't installed.
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from acpi_mcp import server as S
from acpi_mcp.source import SourceError
from gdbstub_mcp import server as G
from gdbstub_mcp.rsp import RSPClient

ELF = os.path.join(os.path.dirname(__file__), "fixtures", "kernel", "kernel.elf")
COUNTER = 0x1021A0  # `counter` in the fixture kernel, incremented in kmain's loop


def find_qemu(arch):
    found = shutil.which(f"qemu-system-{arch}")
    if found:
        return found
    win = rf"C:\Program Files\qemu\qemu-system-{arch}.exe"
    return win if os.path.isfile(win) else None


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class VM:
    def __init__(self, arch, machine, smp=2, extra=()):
        qemu = find_qemu(arch)
        if qemu is None:
            pytest.skip(f"qemu-system-{arch} not installed")
        self.arch = arch
        self.port = free_port()
        self.proc = subprocess.Popen(
            [qemu, "-display", "none", "-M", machine, "-smp", str(smp), "-m", "128",
             "-kernel", ELF, "-gdb", f"tcp:127.0.0.1:{self.port}", "-S", "-no-reboot", *extra],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def close(self):
        for name in list(G._sessions):
            G._sessions.pop(name).close()
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()


@pytest.fixture
def vm_factory():
    vms = []

    def make(*a, **k):
        v = VM(*a, **k)
        vms.append(v)
        return v

    yield make
    for v in vms:
        v.close()
    S._sets.clear()


CONFIGS = [("i386", "pc"), ("i386", "q35"), ("x86_64", "pc"), ("x86_64", "q35")]


@pytest.mark.parametrize("arch,machine", CONFIGS)
def test_live_tables(vm_factory, arch, machine):
    vm = vm_factory(arch, machine, smp=2)
    out = S.acpi_load("vm", port=vm.port, boot_wait_s=10)
    assert "BAD CHECKSUM" not in out
    assert "no physical-memory mode" not in out  # QEMU supports Qqemu.PhyMemMode
    ts = S._sets["vm"]
    assert ("MCFG" in {t.signature for t in ts.tables}) == (machine == "q35")
    madt = S.acpi_table("vm", "MADT")
    assert "2 usable CPU(s), APIC IDs [0, 1]" in madt
    assert "IRQ0 -> GSI 2" in madt
    assert "PS/2 keyboard" in S.acpi_table("vm", "DSDT")


def test_cpu_count_follows_smp(vm_factory):
    vm = vm_factory("x86_64", "q35", smp=4)
    S.acpi_load("vm", port=vm.port, boot_wait_s=10)
    assert "4 usable CPU(s), APIC IDs [0, 1, 2, 3]" in S.acpi_table("vm", "MADT")


def test_before_firmware_runs_error_is_instructive(vm_factory):
    vm = vm_factory("i386", "pc")
    with pytest.raises(SourceError, match="boot_wait_s=5"):
        S.acpi_load("vm", port=vm.port)


def _counter(port):
    c = RSPClient("127.0.0.1", port)
    try:
        return int.from_bytes(c.read_memory(COUNTER, 4), "little")
    finally:
        c.request("D;1")
        c.sock.close()
        c.sock = None


def test_resume_semantics(vm_factory):
    vm = vm_factory("i386", "pc")
    S.acpi_load("vm", port=vm.port, boot_wait_s=10, resume=False)
    # resume=False: the guest stays paused after acpi_load disconnects.
    c = RSPClient("127.0.0.1", vm.port)
    a = int.from_bytes(c.read_memory(COUNTER, 4), "little")
    c.sock.close()
    c.sock = None
    time.sleep(0.5)
    c = RSPClient("127.0.0.1", vm.port)
    b = int.from_bytes(c.read_memory(COUNTER, 4), "little")
    c.sock.close()
    c.sock = None
    assert a == b, "guest ran although acpi_load was told resume=False"
    # resume=True: acpi_load detaches with D;1 and the guest keeps running.
    S.acpi_load("vm", port=vm.port, resume=True)
    time.sleep(0.5)
    first = _counter(vm.port)
    time.sleep(0.5)
    assert _counter(vm.port) != first, "guest stayed paused after resume=True"


# Machine code for the recipes, so the test executes exactly what acpi_find says.
SHUTDOWN = "66ba0406" "66b80020" "66ef" "f4"  # mov dx,0x604; mov ax,0x2000; out dx,ax; hlt
RESET = "66baf90c" "b00f" "ee" "f4"           # mov dx,0xcf9; mov al,0x0f; out dx,al; hlt
HALT = "f4"                                   # control: just hlt


@pytest.mark.parametrize("arch,machine,question,code,expect_exit", [
    ("i386", "pc", "shut down", SHUTDOWN, True),
    ("x86_64", "q35", "shut down", SHUTDOWN, True),
    ("x86_64", "q35", "reboot", RESET, True),  # -no-reboot turns the reset into an exit
    ("x86_64", "pc", None, HALT, False),
])
def test_recipes_work_in_the_guest(vm_factory, arch, machine, question, code, expect_exit):
    vm = vm_factory(arch, machine, smp=1)
    S.acpi_load("vm", port=vm.port, boot_wait_s=10, resume=False)
    if question == "shut down":
        assert "outw(0x604, 0x2000)" in S.acpi_find("vm", question)
    elif question == "reboot":
        assert "write 0xf to I/O port 0xcf9" in S.acpi_find("vm", question)
    G.debug_connect("g", port=vm.port)
    G.debug_write_memory("g", "0x7000", code)
    G.debug_set_register("g", "rip" if arch == "x86_64" else "eip", "0x7000")
    G.debug_continue("g", 3)
    try:
        vm.proc.wait(timeout=5)
        exited = True
    except subprocess.TimeoutExpired:
        exited = False
    assert exited == expect_exit
