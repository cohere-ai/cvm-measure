# Copyright 2026 Cohere, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The QEMU half of the Kata TDX model against the shipped QEMU binary.

For VM shapes no live pod has had, the shipped QEMU is the ground truth for
the fw_cfg blobs OVMF measures. It runs under qtest with Kata's device tree
(host-only devices swapped for stand-ins with the same PCI footprint), the
guest writes OVMF's platform init and the modelled 64-bit window, and the
ACPI blobs, SMBIOS tables and e820 RAM map are compared byte for byte.

Needs KATA_TDX_ROOT (see test_kata_tdx) and KATA_TDX_ORACLE_QEMU, the command
that runs that release's qemu-system-x86_64-tdx-experimental on linux/amd64,
for example ``docker exec -i <container> /opt/kata/bin/qemu-system-x86_64-tdx-experimental``.
KATA_TDX_ORACLE_SHARE is the release's ``opt/kata/share`` as that QEMU sees it
(default: under KATA_TDX_ROOT).
"""

from __future__ import annotations

import base64
import os
import shlex
import struct
import subprocess
from pathlib import Path

import pytest

from cvm_measure.kata_tdx import acpi, pcialloc, smbios, tdhob
from cvm_measure.kata_tdx.platform import Platform

from .test_kata_tdx import kata_config, kata_root, needs_tomllib, platform

__all__ = ["kata_config", "kata_root", "platform"]

ACPI_BLOBS = ("etc/table-loader", "etc/acpi/rsdp", "etc/acpi/tables")
_DMA_BUF = 0x100000
_FW_CFG_FILE_DIR = 0x19
_LPC = 0x1F << 3
_PM_BASE = 0x600
_FIRST_ROOT_PORT = 0x09 << 3
_VIRTIO_SERIAL = 0x11 << 3

# (gpus, vcpus, memory_mib): vCPU counts up to the SMBIOS 2.x limit, memory on
# both sides of q35's 2.75 GiB lowmem rule and past one 2 TiB SMBIOS DIMM,
# and the 8-GPU layout no live pod has had.
SHAPES = [
    (1, 1, 4608),
    (1, 64, 4608),
    (1, 254, 4608),
    (1, 4, 2048),
    (1, 4, 2815),
    (1, 4, 2816),
    (1, 4, 4097),
    (1, 4, (2 << 20) + 512),
    (1, 4, 3 << 20),
    (0, 4, 8192),
    (8, 195, 3149824),
]


class _QTest:
    def __init__(self, qemu: list[str], args: list[str]) -> None:
        self.proc = subprocess.Popen(
            [*qemu, "-accel", "qtest", "-qtest", "stdio", "-qtest-log", "/dev/null"]
            + ["-display", "none", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def cmd(self, line: str) -> str:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(line + "\n")
        while True:
            resp: str = self.proc.stdout.readline()
            if not resp:
                assert self.proc.stderr is not None
                raise RuntimeError(f"qemu exited: {self.proc.stderr.read()}")
            if resp.startswith(("OK", "FAIL")):
                break
        if not resp.startswith("OK"):
            raise RuntimeError(f"{line}: {resp}")
        return resp[3:].strip()

    def pci(self, devfn: int, off: int, size: int, value: int | None = None) -> int:
        self.cmd(f"outl 0xcf8 {0x8000_0000 | devfn << 8 | off & 0xFC:#x}")
        op = {1: "b", 2: "w", 4: "l"}[size]
        port = 0xCFC + (off & 3)
        if value is None:
            return int(self.cmd(f"in{op} {port:#x}"), 16)
        self.cmd(f"out{op} {port:#x} {value:#x}")
        return value

    def fw_cfg(self, key: int, size: int) -> bytes:
        access = struct.pack(">IIQ", key << 16 | 0x0A, size, _DMA_BUF + 0x1000)
        self.cmd(
            f"b64write {_DMA_BUF:#x} {len(access):#x} {base64.b64encode(access).decode()}"
        )
        self.cmd("outl 0x514 0")
        self.cmd(
            f"outl 0x518 {int.from_bytes(_DMA_BUF.to_bytes(4, 'big'), 'little'):#x}"
        )
        return base64.b64decode(self.cmd(f"b64read {_DMA_BUF + 0x1000:#x} {size:#x}"))

    def blob(self, name: str) -> bytes:
        count = struct.unpack(">I", self.fw_cfg(_FW_CFG_FILE_DIR, 4))[0]
        raw = self.fw_cfg(_FW_CFG_FILE_DIR, 4 + 64 * count)[4:]
        for i in range(count):
            size, sel, _, fname = struct.unpack_from(">IHH56s", raw, 64 * i)
            if fname.rstrip(b"\0").decode() == name:
                return self.fw_cfg(sel, size)
        raise KeyError(name)

    def ovmf_init(self, hole64: tuple[int, int]) -> None:
        """PlatformInitLib's Q35 setup, then a 64-bit window spanning hole64.

        QEMU's tables only see pci_bus_get_w64_range, so the first root
        port's prefetch window opens the range and the last virtio BAR closes it.
        """
        self.pci(_LPC, 0x40, 4, self.pci(_LPC, 0x40, 4) & ~0xFF80 | _PM_BASE)
        self.pci(_LPC, 0x04, 1, self.pci(_LPC, 0x04, 1) | 0x01)
        self.pci(_LPC, 0x44, 1, self.pci(_LPC, 0x44, 1) | 0x80)
        self.pci(_LPC, 0xF0, 4, 0xFED1_C000 | 1)
        self.pci(0, 0x60, 4, 0)
        self.pci(0, 0x64, 4, 0)
        self.pci(0, 0x60, 4, 0xE000_0000 | 1)
        start, end = hole64
        last = start + (1 << 20) - 1
        rp = _FIRST_ROOT_PORT
        self.pci(rp, 0x24, 2, (start >> 16) & 0xFFF0 | 1)
        self.pci(rp, 0x26, 2, (last >> 16) & 0xFFF0 | 1)
        self.pci(rp, 0x28, 4, start >> 32)
        self.pci(rp, 0x2C, 4, last >> 32)
        self.pci(rp, 0x04, 2, self.pci(rp, 0x04, 2) | 0x2)
        bar = end - 0x4000
        self.pci(_VIRTIO_SERIAL, 0x20, 4, bar & 0xFFFF_FFFF)
        self.pci(_VIRTIO_SERIAL, 0x24, 4, bar >> 32)
        self.pci(_VIRTIO_SERIAL, 0x04, 2, self.pci(_VIRTIO_SERIAL, 0x04, 2) | 0x2)

    def close(self) -> None:
        # qtest has no quit command and killing a wrapper such as docker exec
        # leaves QEMU running, so power off through PM1a_CNT (SLP_EN, S5).
        assert self.proc.stdin is not None
        try:
            self.cmd(f"outw {_PM_BASE + 4:#x} 0x2000")
        except RuntimeError:
            pass
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def _kata_argv(
    share: str, kernel: str, gpus: int, vcpus: int, memory_mib: int
) -> list[str]:
    """runtime-rs's QEMU devices; vfio-pci and vhost-vsock become virtio-rng-pci."""
    a = [
        "-L", f"{share}/kata-qemu/qemu",
        "-kernel", f"{share}/kata-containers/{kernel}",
        "-append", "x",
        "-smp", str(vcpus),
        "-machine", "q35,smm=off,pic=off,memory-backend=entire-guest-memory",
        "-cpu", "max,phys-bits=46,vendor=GenuineIntel",
        "-m", f"{memory_mib}M",
        "-object", f"memory-backend-ram,id=entire-guest-memory,size={memory_mib}M,reserve=off",
    ]  # fmt: skip
    for k in range(gpus):
        a += [
            "-device",
            f"pcie-root-port,id=rp{k},addr={0x09 + k:#x},chassis={k + 10},slot={k + 9},bus=pcie.0",
        ]
    a += [
        "-object", "rng-random,id=rng0,filename=/dev/urandom",
        "-device", "virtio-rng-pci,rng=rng0",
        "-device", (
            "pci-bridge,bus=pcie.0,id=pci-bridge-0,chassis_nr=1,shpc=off,addr=2,"
            "io-reserve=4k,mem-reserve=1m,pref64-reserve=1m"
        ),
        "-device", "virtio-scsi-pci,id=scsi0",
        "-device", "virtio-net-pci,mac=02:00:00:00:00:01",
        "-device", "virtio-rng-pci",
    ]  # fmt: skip
    for i in range(3):
        a += [
            "-blockdev",
            f"driver=null-co,node-name=d{i}",
            "-device",
            f"virtio-blk-pci,drive=d{i}",
        ]
    a += [
        "-blockdev",
        "driver=null-co,node-name=d3",
        "-device",
        "scsi-hd,drive=d3,bus=scsi0.0",
    ]
    for k in range(gpus):
        a += ["-device", f"virtio-rng-pci,bus=rp{k},addr=0x0"]
    for k in range(gpus, 8):
        a += ["-device", f"pcie-root-port,id=rp{k},chassis=0,slot={k},bus=pcie.0"]
    a += [
        "-device", "virtio-serial-pci,id=serial0",
        "-vga", "none", "-no-user-config", "-nodefaults",
        "-bios", f"{share}/ovmf/OVMF.inteltdx.fd",
    ]  # fmt: skip
    return a


def _with_processor_id(tables: bytes, platform: Platform) -> bytes:
    """QEMU copies its own CPUID leaf 1 into type 4; use the platform's."""
    out = bytearray(tables)
    off = 0
    while out[off] != 127:
        if out[off] == 4:
            struct.pack_into(
                "<II", out, off + 8, platform.cpuid_1_eax, platform.cpuid_1_edx
            )
        off = out.index(b"\0\0", off + out[off + 1]) + 2
    return bytes(out)


@needs_tomllib
@pytest.mark.parametrize(
    ("gpus", "vcpus", "memory_mib"),
    SHAPES,
    ids=[f"{g}gpu-{v}cpu-{m}M" for g, v, m in SHAPES],
)
def test_matches_shipped_qemu(
    gpus: int,
    vcpus: int,
    memory_mib: int,
    kata_config: Path,
    kata_root: Path,
    platform: Platform,
) -> None:
    from cvm_measure.kata_tdx.config import load_config
    from cvm_measure.kata_tdx.registers import Guest

    qemu = shlex.split(os.environ.get("KATA_TDX_ORACLE_QEMU", ""))
    if not qemu:
        pytest.skip("KATA_TDX_ORACLE_QEMU is not set")
    share = os.environ.get("KATA_TDX_ORACLE_SHARE", str(kata_root / "opt/kata/share"))
    cfg = load_config(kata_config, root=kata_root)

    ram = memory_mib << 20
    e820 = tdhob.q35_e820_ram(ram)
    bits = pcialloc.ovmf_phys_bits(platform.phys_bits, platform.guest_phys_bits)
    base, size = pcialloc.mmio64_window(bits, max(a + n for a, n in e820))
    hole64 = pcialloc.root_bus_mem64(
        window_base=base,
        window_size=size,
        root_ports=[
            list(platform.gpu_bars) if k < gpus else []
            for k in range(cfg.pcie_root_port)
        ],
        root_bus_bars=acpi._root_bus_virtio_bars(acpi.kata_topology(cfg, gpus)),
    )
    blobs = acpi.fw_cfg_blobs(
        cfg,
        Guest(vcpus, memory_mib, gpus),
        window_base=base,
        window_size=size,
        gpu_bars=platform.gpu_bars,
    )
    tables = smbios.qemu_tables(
        machine="pc-q35-11.0",
        vcpus=vcpus,
        ram_bytes=ram,
        e820_ram=e820,
        cpuid_1_eax=platform.cpuid_1_eax,
        cpuid_1_edx=platform.cpuid_1_edx,
    )

    q = _QTest(qemu, _kata_argv(share, Path(cfg.kernel).name, gpus, vcpus, memory_mib))
    try:
        q.ovmf_init(hole64)
        ref = {n: q.blob(n) for n in ACPI_BLOBS}
        raw = q.blob("etc/e820")
        ref_tables = _with_processor_id(q.blob("etc/smbios/smbios-tables"), platform)
    finally:
        q.close()
    ref_e820 = [
        (addr, length)
        for addr, length, kind in (
            struct.unpack_from("<QQI", raw, o) for o in range(0, len(raw), 20)
        )
        if kind == 1
    ]

    assert e820 == ref_e820
    assert tables == ref_tables
    assert blobs.table_loader == ref["etc/table-loader"]
    assert blobs.rsdp == ref["etc/acpi/rsdp"]
    assert blobs.tables == ref["etc/acpi/tables"]
