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

"""The fw_cfg files OVMF measures, read from Kata's own QEMU binary.

QEMU builds its ACPI tables when OVMF first reads them, after OVMF has set up
the chipset and placed the 64-bit BARs. The binary runs under qtest, which
executes no guest code and needs no KVM, so those firmware writes are replayed
over the qtest socket before the files are read. Host-only devices (vfio-pci
GPUs, vhost-vsock) become virtio-rng-pci, which takes the same PCI slot. No TD
is created, so code QEMU runs only for a TDX guest does not run here.
"""

from __future__ import annotations

import base64
import struct
import subprocess
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import KataConfig
    from .registers import Guest

TABLE_LOADER = "etc/table-loader"
ACPI_RSDP = "etc/acpi/rsdp"
ACPI_TABLES = "etc/acpi/tables"
SMBIOS_ANCHOR = "etc/smbios/smbios-anchor"
SMBIOS_TABLES = "etc/smbios/smbios-tables"
E820 = "etc/e820"

# virtio-pci modern devices expose one 16 KiB 64-bit prefetchable BAR.
VIRTIO_BAR = 16 << 10
# Kata places cold-plugged GPU root ports at fixed addresses from slot 9.
_FIRST_GPU_PORT_SLOT = 0x09
_ROOT_PORT_ID = (0x1B36, 0x000C)
# Transitional: devices on pcie.0 are integrated endpoints, so legacy stays on.
_VIRTIO_SERIAL_ID = (0x1AF4, 0x1003)
_DMA_BUF = 0x100000
_FW_CFG_FILE_DIR = 0x19
_LPC = 0x1F << 3
_PM_BASE = 0x600


def _check_supported(cfg: KataConfig, gpus: int) -> None:
    unsupported = {
        f"machine_type {cfg.machine_type!r}": cfg.machine_type != "q35",
        f"cold_plug_vfio {cfg.cold_plug_vfio!r}": gpus
        and cfg.cold_plug_vfio != "root-port",
        f"pcie_switch_port {cfg.pcie_switch_port}": cfg.pcie_switch_port,
        f"default_bridges {cfg.default_bridges}": cfg.default_bridges != 1,
        f"block_device_driver {cfg.block_device_driver!r}": cfg.block_device_driver
        != "virtio-scsi",
        f"shared_fs {cfg.shared_fs!r}": cfg.shared_fs not in ("", "none"),
        "no entropy_source": not cfg.entropy_source,
        f"vm_rootfs_driver {cfg.vm_rootfs_driver!r}": cfg.vm_rootfs_driver
        != "virtio-blk-pci",
    }
    bad = [k for k, v in unsupported.items() if v]
    if bad:
        raise NotImplementedError(
            "Kata device layout not modelled for: " + ", ".join(bad)
        )
    if gpus > cfg.pcie_root_port:
        raise ValueError(
            f"{gpus} GPUs need {gpus} root ports; the configuration has {cfg.pcie_root_port}"
        )


def root_bus_virtio_bars(cfg: KataConfig) -> list[int]:
    """64-bit BARs on pcie.0: rng, scsi, net, vsock, serial and one blk per image."""
    return [VIRTIO_BAR] * (5 + 1 + len(cfg.extensions))


def kata_argv(cfg: KataConfig, guest: Guest, phys_bits: int) -> list[str]:
    """runtime-rs's QEMU command line, in device realize order, minus the TD."""
    _check_supported(cfg, guest.gpus)
    share = cfg.qemu.parent.parent / "share" / "kata-qemu" / "qemu"
    mem = f"{guest.memory_mib}M"
    a = [
        "-L", str(share),
        "-kernel", str(cfg.kernel),
        "-append", "x",
        "-smp", str(guest.vcpus),
        "-machine", "q35,smm=off,pic=off,memory-backend=entire-guest-memory",
        "-cpu", f"max,phys-bits={phys_bits},vendor=GenuineIntel",
        "-m", mem,
        "-object", f"memory-backend-ram,id=entire-guest-memory,size={mem},reserve=off",
    ]  # fmt: skip
    for k in range(guest.gpus):
        slot = _FIRST_GPU_PORT_SLOT + k
        a += [
            "-device",
            f"pcie-root-port,id=rp{k},addr={slot:#x},chassis={k + 10},slot={slot},bus=pcie.0",
        ]
    a += [
        "-object", f"rng-random,id=rng0,filename={cfg.entropy_source}",
        "-device", "virtio-rng-pci,rng=rng0",
        "-device", (
            "pci-bridge,bus=pcie.0,id=pci-bridge-0,chassis_nr=1,shpc=off,addr=2,"
            "io-reserve=4k,mem-reserve=1m,pref64-reserve=1m"
        ),
        "-device", "virtio-scsi-pci,id=scsi0",
        "-device", "virtio-net-pci,mac=02:00:00:00:00:01",
        "-device", "virtio-rng-pci",
    ]  # fmt: skip
    for i in range(1 + len(cfg.extensions)):
        a += [
            "-blockdev",
            f"driver=null-co,node-name=d{i}",
            "-device",
            f"virtio-blk-pci,drive=d{i}",
        ]
    a += ["-blockdev", "driver=null-co,node-name=initdata"]
    a += ["-device", "scsi-hd,drive=initdata,bus=scsi0.0"]
    for k in range(guest.gpus):
        a += ["-device", f"virtio-rng-pci,bus=rp{k},addr=0x0"]
    for k in range(guest.gpus, cfg.pcie_root_port):
        a += ["-device", f"pcie-root-port,id=rp{k},chassis=0,slot={k},bus=pcie.0"]
    a += [
        "-device", "virtio-serial-pci,id=serial0",
        "-vga", "none", "-no-user-config", "-nodefaults",
        "-bios", str(cfg.firmware),
    ]  # fmt: skip
    return a


class _QTest:
    def __init__(self, qemu: Sequence[str], args: Sequence[str]) -> None:
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
                raise RuntimeError(f"QEMU exited: {self.proc.stderr.read().strip()}")
            if resp.startswith(("OK", "FAIL")):
                break
        if not resp.startswith("OK"):
            raise RuntimeError(f"qtest {line!r}: {resp.strip()}")
        return resp[3:].strip()

    def pci(self, devfn: int, off: int, size: int, value: int | None = None) -> int:
        self.cmd(f"outl 0xcf8 {0x8000_0000 | devfn << 8 | off & 0xFC:#x}")
        op = {1: "b", 2: "w", 4: "l"}[size]
        port = 0xCFC + (off & 3)
        if value is None:
            return int(self.cmd(f"in{op} {port:#x}"), 16)
        self.cmd(f"out{op} {port:#x} {value:#x}")
        return value

    def find(self, vendor_device: tuple[int, int]) -> int:
        vendor, device = vendor_device
        for slot in range(32):
            if self.pci(slot << 3, 0, 4) == device << 16 | vendor:
                return slot << 3
        raise LookupError(f"no PCI device {vendor:04x}:{device:04x} on bus 0")

    def fw_cfg(self, key: int, size: int) -> bytes:
        # FWCfgDmaAccess is big-endian: control (select | read), length, address.
        access = struct.pack(">IIQ", key << 16 | 0x0A, size, _DMA_BUF + 0x1000)
        self.cmd(
            f"b64write {_DMA_BUF:#x} {len(access):#x} {base64.b64encode(access).decode()}"
        )
        self.cmd("outl 0x514 0")
        self.cmd(
            f"outl 0x518 {int.from_bytes(_DMA_BUF.to_bytes(4, 'big'), 'little'):#x}"
        )
        return base64.b64decode(self.cmd(f"b64read {_DMA_BUF + 0x1000:#x} {size:#x}"))

    def files(self) -> dict[str, tuple[int, int]]:
        count = struct.unpack(">I", self.fw_cfg(_FW_CFG_FILE_DIR, 4))[0]
        raw = self.fw_cfg(_FW_CFG_FILE_DIR, 4 + 64 * count)[4:]
        out = {}
        for i in range(count):
            size, sel, _, name = struct.unpack_from(">IHH56s", raw, 64 * i)
            out[name.rstrip(b"\0").decode()] = (sel, size)
        return out

    def ovmf_init(self, hole64: tuple[int, int]) -> None:
        """PlatformInitLib's Q35 setup, then a 64-bit window spanning hole64.

        QEMU's tables only see pci_bus_get_w64_range, so one root port's
        prefetch window opens the range and a virtio BAR closes it.
        """
        self._enable_pm()
        self.pci(_LPC, 0xF0, 4, 0xFED1_C000 | 1)
        self.pci(0, 0x60, 4, 0)
        self.pci(0, 0x64, 4, 0)
        self.pci(0, 0x60, 4, 0xE000_0000 | 1)
        start, end = hole64
        last = start + (1 << 20) - 1
        rp = self.find(_ROOT_PORT_ID)
        self.pci(rp, 0x24, 2, (start >> 16) & 0xFFF0 | 1)
        self.pci(rp, 0x26, 2, (last >> 16) & 0xFFF0 | 1)
        self.pci(rp, 0x28, 4, start >> 32)
        self.pci(rp, 0x2C, 4, last >> 32)
        self.pci(rp, 0x04, 2, self.pci(rp, 0x04, 2) | 0x2)
        serial = self.find(_VIRTIO_SERIAL_ID)
        bar = end - VIRTIO_BAR
        self.pci(serial, 0x20, 4, bar & 0xFFFF_FFFF)
        self.pci(serial, 0x24, 4, bar >> 32)
        self.pci(serial, 0x04, 2, self.pci(serial, 0x04, 2) | 0x2)

    def _enable_pm(self) -> None:
        self.pci(_LPC, 0x40, 4, self.pci(_LPC, 0x40, 4) & ~0xFF80 | _PM_BASE)
        self.pci(_LPC, 0x04, 1, self.pci(_LPC, 0x04, 1) | 0x01)
        self.pci(_LPC, 0x44, 1, self.pci(_LPC, 0x44, 1) | 0x80)

    def close(self) -> None:
        # qtest has no quit command and killing a wrapper such as docker run
        # leaves QEMU running, so power off through PM1a_CNT (SLP_EN, S5).
        assert self.proc.stdin is not None
        try:
            self._enable_pm()
            self.cmd(f"outw {_PM_BASE + 4:#x} 0x2000")
        except RuntimeError:
            pass
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def read_fw_cfg(
    cfg: KataConfig,
    guest: Guest,
    *,
    hole64: tuple[int, int],
    phys_bits: int,
    names: Sequence[str],
    wrapper: Sequence[str] = (),
) -> dict[str, bytes]:
    """Run ``cfg.qemu`` for ``guest`` and read the named fw_cfg files.

    ``wrapper`` prefixes the command, for hosts that cannot run the linux/amd64
    binary directly; the artifact paths in ``cfg`` must resolve inside it.
    """
    q = _QTest([*wrapper, str(cfg.qemu)], kata_argv(cfg, guest, phys_bits))
    try:
        q.ovmf_init(hole64)
        files = q.files()
        return {n: q.fw_cfg(*files[n]) for n in names}
    finally:
        q.close()
