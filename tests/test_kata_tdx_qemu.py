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

"""The QEMU command line, qtest client and SMBIOS filter, without Kata release artifacts."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from cvm_measure.kata_tdx import qemu, smbios
from cvm_measure.kata_tdx.platform import load_platform

from .conftest import FIXTURES_DIR
from .fake_qtest import FILES
from .test_kata_tdx import PLATFORM, SHAPES, needs_tomllib

SMBIOS_1GPU_3CPU = FIXTURES_DIR / "kata-tdx" / "smbios-tables-1gpu-3cpu.bin"
_CONFIG = """\
[hypervisor.qemu]
path = "/opt/kata/bin/qemu"
firmware = "/ovmf.fd"
kernel = "/vmlinuz"
image = "/rootfs.img"
vm_rootfs_driver = "virtio-blk-pci"
block_device_driver = "{block}"
shared_fs = "none"
entropy_source = "/dev/urandom"
default_bridges = 1
cold_plug_vfio = "root-port"
pcie_root_port = 8
[[hypervisor.qemu.guest_extension_images]]
name = "gpu"
path = "/gpu.img"
[[hypervisor.qemu.guest_extension_images]]
name = "coco"
path = "/coco.img"
"""


def _config(tmp_path: Path, block: str = "virtio-scsi") -> Any:
    from cvm_measure.kata_tdx.config import load_config

    path = tmp_path / "configuration.toml"
    path.write_text(_CONFIG.format(block=block))
    return load_config(path, root=tmp_path)


def _devices(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-device"]


@needs_tomllib
class TestKataArgv:
    def test_device_tree(self, tmp_path: Path) -> None:
        from cvm_measure.kata_tdx.registers import Guest

        cfg = _config(tmp_path)
        argv = qemu.kata_argv(cfg, Guest(vcpus=27, memory_mib=396032, gpus=2), 46)
        devices = _devices(argv)
        assert sum(d.startswith("pcie-root-port") for d in devices) == 8
        assert devices[:2] == [
            "pcie-root-port,id=rp0,addr=0x9,chassis=10,slot=9,bus=pcie.0",
            "pcie-root-port,id=rp1,addr=0xa,chassis=11,slot=10,bus=pcie.0",
        ]
        assert sum(d.startswith("virtio-blk-pci") for d in devices) == 3
        assert [d for d in devices if ",bus=rp" in d] == [
            "virtio-rng-pci,bus=rp0,addr=0x0",
            "virtio-rng-pci,bus=rp1,addr=0x0",
        ]
        assert devices[-1] == "virtio-serial-pci,id=serial0"
        assert argv[argv.index("-cpu") + 1] == "max,phys-bits=46,vendor=GenuineIntel"
        assert argv[argv.index("-bios") + 1] == str(tmp_path / "ovmf.fd")
        assert argv[argv.index("-L") + 1] == str(
            tmp_path / "opt/kata/share/kata-qemu/qemu"
        )
        assert qemu.root_bus_virtio_bars(cfg) == [16 << 10] * 8

    def test_unmodelled_layout(self, tmp_path: Path) -> None:
        from cvm_measure.kata_tdx.registers import Guest

        with pytest.raises(NotImplementedError, match="block_device_driver"):
            qemu.kata_argv(_config(tmp_path, "virtio-blk"), Guest(4, 8192, 1), 46)

    def test_more_gpus_than_root_ports(self, tmp_path: Path) -> None:
        from cvm_measure.kata_tdx.registers import Guest

        with pytest.raises(ValueError, match="9 GPUs need 9 root ports"):
            qemu.kata_argv(_config(tmp_path), Guest(4, 8192, 9), 46)


@needs_tomllib
def test_read_fw_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cvm_measure.kata_tdx.registers import Guest

    state = tmp_path / "state.json"
    monkeypatch.setenv("FAKE_QTEST_STATE", str(state))
    start, end = 0x3800_0000_0000, 0x3880_0002_0000
    blobs = qemu.read_fw_cfg(
        _config(tmp_path),
        Guest(vcpus=3, memory_mib=4608, gpus=1),
        hole64=(start, end),
        phys_bits=46,
        names=tuple(FILES),
        wrapper=[sys.executable, str(Path(__file__).parent / "fake_qtest.py")],
    )
    assert blobs == FILES

    config = {
        int(d): bytes.fromhex(c) for d, c in json.loads(state.read_text()).items()
    }
    root_port, serial, lpc = config[0x09 << 3], config[0x11 << 3], config[0x1F << 3]
    assert struct.unpack_from("<HHII", root_port, 0x24) == (
        (start >> 16) & 0xFFF0 | 1,
        ((start + (1 << 20) - 1) >> 16) & 0xFFF0 | 1,
        start >> 32,
        (start + (1 << 20) - 1) >> 32,
    )
    bar = end - (16 << 10)
    assert struct.unpack_from("<II", serial, 0x20) == (bar & 0xFFFF_FFFF, bar >> 32)
    assert root_port[0x04] & 0x2 and serial[0x04] & 0x2
    assert struct.unpack_from("<I", lpc, 0x40)[0] & 0xFF80 == 0x600
    assert struct.unpack_from("<I", config[0], 0x60)[0] == 0xE000_0001


class TestSmbios:
    def test_handoff_digest(self) -> None:
        platform = load_platform(PLATFORM)
        shape = next(s for s in SHAPES if s["gpus"] == 1 and s["vcpus"] == 3)
        tables = smbios.with_processor_id(
            SMBIOS_1GPU_3CPU.read_bytes(), platform.cpuid_1_eax, platform.cpuid_1_edx
        )
        assert smbios.handoff_digest(tables).hex() == shape["events"]["smbios"]

    def test_processor_id_only_touches_type_4(self) -> None:
        raw = SMBIOS_1GPU_3CPU.read_bytes()
        out = smbios.with_processor_id(raw, 0x1122_3344, 0x5566_7788)
        before, after = smbios._split(raw), smbios._split(out)
        assert [r for r in before if r[0] != 4] == [r for r in after if r[0] != 4]
        type4 = [r for r in after if r[0] == 4]
        assert len(type4) == 1
        assert type4[0][8:16] == struct.pack("<II", 0x1122_3344, 0x5566_7788)

    def test_entry_point(self) -> None:
        smbios.check_entry_point(b"_SM_\x1f")
        with pytest.raises(NotImplementedError, match="SMBIOS 3.0"):
            smbios.check_entry_point(b"_SM3_\x18")
