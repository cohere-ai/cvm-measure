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

"""Kata TDX registers against a live oke-us-phx-1-cc-prod pod VM.

Tests that read Kata release artifacts need KATA_TDX_ROOT set to a directory
holding the extracted kata-static tarballs (the ``opt/kata`` tree) whose
digests are recorded in the golden file.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from cvm_measure.kata_tdx import pcialloc, smbios, tdhob
from cvm_measure.kata_tdx.platform import Platform, load_platform
from cvm_measure.kata_tdx.qemu import q35_machine

from .conftest import FIXTURES_DIR

REPO = Path(__file__).parent.parent
PLATFORM = REPO / "platforms" / "oci-bm-gpu-b200-emr.json"
GOLDEN = json.loads((FIXTURES_DIR / "golden" / "kata-tdx-oci-b200.json").read_text())
SHAPES = GOLDEN["shapes"]
RELEASE_CONFIG = "opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-nvidia-gpu-tdx-runtime-rs.toml"
B200_HOLE64_END = {1: 0x3880_0002_0000, 2: 0x38F8_0002_0000, 4: 0x39E8_0002_0000}

needs_tomllib = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="tomllib needs Python 3.11"
)


def _shape_id(shape: dict[str, Any]) -> str:
    return f"{shape['gpus']}gpu"


@pytest.fixture(scope="module")
def platform() -> Platform:
    return load_platform(PLATFORM)


@pytest.fixture(scope="module")
def kata_root() -> Path:
    root = os.environ.get("KATA_TDX_ROOT", "")
    if not root:
        pytest.skip("KATA_TDX_ROOT is not set")
    path = Path(root)
    for rel, digest in GOLDEN["artifacts_sha384"].items():
        if hashlib.sha384((path / rel).read_bytes()).hexdigest() != digest:
            pytest.fail(
                f"{path / rel} is not the artifact the golden values were measured with"
            )
    return path


@pytest.fixture(scope="module")
def kata_config(kata_root: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    if sys.version_info < (3, 11):
        pytest.skip("tomllib needs Python 3.11")
    cfg_dir = tmp_path_factory.mktemp("kata-config")
    config = cfg_dir / "configuration.toml"
    shutil.copy(kata_root / RELEASE_CONFIG, config)
    shutil.copytree(FIXTURES_DIR / "kata-tdx" / "config.d", cfg_dir / "config.d")
    return config


# -- No artifacts needed ---------------------------------------------------------


class TestPlatform:
    def test_b200(self, platform: Platform) -> None:
        assert platform.cpuid_1_eax == 0xC06F2
        assert platform.gpu_bars == (256 << 30, 64 << 20, 32 << 20)

    def test_rejects_non_power_of_two_bar(self, tmp_path: Path) -> None:
        data = json.loads(PLATFORM.read_text())
        data["gpu_bars"] = ["3GiB"]
        (tmp_path / "p.json").write_text(json.dumps(data))
        with pytest.raises(ValueError, match="power of two"):
            load_platform(tmp_path / "p.json")


class TestQemuMachine:
    def test_newest_q35_type_wins(self) -> None:
        blob = b"\0pc-q35-10.2-machine\0\0pc-q35-11.0-machine\0\0pc-q35-9.1-machine\0"
        assert q35_machine(blob) == "pc-q35-11.0"

    def test_adjacent_type_names(self) -> None:
        blob = b"\0pc-q35-9.1-machine\0pc-q35-11.0-machine\0pc-q35-10.2-machine\0"
        assert q35_machine(blob) == "pc-q35-11.0"

    def test_unmodelled_machine(self) -> None:
        with pytest.raises(NotImplementedError):
            q35_machine(b"\0pc-q35-11.1-machine\0")


class TestE820:
    def test_split_above_lowmem(self) -> None:
        assert tdhob.q35_e820_ram(396032 << 20) == [
            (0, 2 << 30),
            (4 << 30, (396032 << 20) - (2 << 30)),
        ]

    def test_small_guest(self) -> None:
        assert tdhob.q35_e820_ram(2 << 30) == [(0, 2 << 30)]


@pytest.mark.parametrize("shape", SHAPES, ids=_shape_id)
def test_smbios_handoff_digest(shape: dict[str, Any], platform: Platform) -> None:
    ram = shape["memory_mib"] << 20
    tables = smbios.qemu_tables(
        machine="pc-q35-11.0",
        vcpus=shape["vcpus"],
        ram_bytes=ram,
        e820_ram=tdhob.q35_e820_ram(ram),
        cpuid_1_eax=platform.cpuid_1_eax,
        cpuid_1_edx=platform.cpuid_1_edx,
    )
    assert smbios.handoff_digest(tables).hex() == shape["events"]["smbios"]


@pytest.mark.parametrize("vcpus", [255, 256])
def test_smbios_30_entry_point_unmodelled(vcpus: int, platform: Platform) -> None:
    with pytest.raises(NotImplementedError, match="SMBIOS 3.0"):
        smbios.qemu_tables(
            machine="pc-q35-11.0",
            vcpus=vcpus,
            ram_bytes=8 << 30,
            e820_ram=tdhob.q35_e820_ram(8 << 30),
            cpuid_1_eax=platform.cpuid_1_eax,
            cpuid_1_edx=platform.cpuid_1_edx,
        )


@pytest.mark.parametrize("shape", SHAPES, ids=_shape_id)
def test_hole64(shape: dict[str, Any], platform: Platform) -> None:
    bits = pcialloc.ovmf_phys_bits(platform.phys_bits, platform.guest_phys_bits)
    assert bits == 46
    ram = shape["memory_mib"] << 20
    base, size = pcialloc.mmio64_window(
        bits, max(a + n for a, n in tdhob.q35_e820_ram(ram))
    )
    ports = [list(platform.gpu_bars) if i < shape["gpus"] else [] for i in range(8)]
    assert pcialloc.root_bus_mem64(
        window_base=base,
        window_size=size,
        root_ports=ports,
        root_bus_bars=[16 << 10] * 8,
    ) == (
        0x3800_0000_0000,
        B200_HOLE64_END[shape["gpus"]],
    )


def test_phys_bits_capped_by_guest_phys_bits() -> None:
    assert pcialloc.ovmf_phys_bits(52, 40) == 40
    assert pcialloc.ovmf_phys_bits(52, 0, page_1g=False) == 40


@needs_tomllib
class TestCmdline:
    def _config(self, tmp_path: Path, extra: str = "") -> Path:
        mbr = bytearray(512)
        struct.pack_into("<I", mbr, 440, 0x409EA605)
        for i in range(2):
            mbr[446 + 16 * i + 4] = 0x83
            struct.pack_into("<II", mbr, 446 + 16 * i + 8, 2048 * (i + 1), 2048)
        mbr[510:512] = b"\x55\xaa"
        (tmp_path / "rootfs.img").write_bytes(bytes(mbr))
        config = tmp_path / "configuration.toml"
        config.write_text(
            '[hypervisor.qemu]\npath = "/qemu"\nfirmware = "/ovmf.fd"\nkernel = "/vmlinuz"\n'
            'image = "/rootfs.img"\nrootfs_type = "erofs"\nvm_rootfs_driver = "virtio-blk-pci"\n'
            'kernel_params = "pci=realloc"\ndisable_guest_selinux = true\n'
            'kernel_verity_params = "root_hash=ab,salt=cd,data_blocks=8,data_block_size=4096,hash_block_size=4096"\n'
            "[agent.kata]\nlaunch_process_timeout = 15\n" + extra
        )
        return config

    def test_runtime_rs_order(self, tmp_path: Path) -> None:
        from cvm_measure.kata_tdx.cmdline import kernel_cmdline
        from cvm_measure.kata_tdx.config import load_config

        cfg = load_config(self._config(tmp_path), root=tmp_path)
        assert kernel_cmdline(cfg) == (
            "reboot=k panic=1 systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service "
            "systemd.mask=systemd-networkd.socket "
            'dm-mod.create="dm-verity,,,ro,0 64 verity 1 PARTUUID=409ea605-01 PARTUUID=409ea605-02 4096 4096 8 '
            '0 sha256 ab cd" root=/dev/dm-0 rootflags=ro rootfstype=erofs '
            "dm-mod.waitfor=PARTUUID=409ea605-01,PARTUUID=409ea605-02 "
            "agent.cdh_api_timeout=50 agent.launch_process_timeout=15 pci=realloc selinux=0 console=hvc0"
        )

    def test_drop_in_overrides(self, tmp_path: Path) -> None:
        from cvm_measure.kata_tdx.cmdline import kernel_cmdline
        from cvm_measure.kata_tdx.config import load_config

        config = self._config(tmp_path)
        (tmp_path / "config.d").mkdir()
        (tmp_path / "config.d" / "50-x.toml").write_text(
            '[hypervisor.qemu]\nkernel_params = "nvrc.smi.srs=1"\n'
        )
        cmdline = kernel_cmdline(load_config(config, root=tmp_path))
        assert " nvrc.smi.srs=1 selinux=0 " in cmdline
        assert "pci=realloc" not in cmdline

    def test_initrd_unsupported(self, tmp_path: Path) -> None:
        from cvm_measure.kata_tdx.cmdline import kernel_cmdline
        from cvm_measure.kata_tdx.config import load_config

        config = self._config(tmp_path)
        config.write_text(
            config.read_text().replace(
                'image = "/rootfs.img"', 'image = "/rootfs.img"\ninitrd = "/initrd"'
            )
        )
        with pytest.raises(NotImplementedError):
            kernel_cmdline(load_config(config, root=tmp_path))


# -- Kata release artifacts ------------------------------------------------------


@pytest.mark.parametrize("shape", SHAPES, ids=_shape_id)
def test_tdx_table(shape: dict[str, Any], kata_root: Path) -> None:
    firmware = (kata_root / "opt/kata/share/ovmf/OVMF.inteltdx.fd").read_bytes()
    assert (
        tdhob.tdx_table_digest(firmware, shape["memory_mib"] << 20).hex()
        == shape["events"]["tdx_table"]
    )


@needs_tomllib
@pytest.mark.parametrize("shape", SHAPES, ids=_shape_id)
def test_acpi_blobs(shape: dict[str, Any], tmp_path: Path, platform: Platform) -> None:
    from cvm_measure.kata_tdx import acpi
    from cvm_measure.kata_tdx.config import load_config
    from cvm_measure.kata_tdx.registers import Guest

    config = tmp_path / "configuration.toml"
    config.write_text(
        '[hypervisor.qemu]\npath = "/qemu"\nfirmware = "/ovmf.fd"\nkernel = "/vmlinuz"\nimage = "/rootfs.img"\n'
        'vm_rootfs_driver = "virtio-blk-pci"\nblock_device_driver = "virtio-scsi"\nshared_fs = "none"\n'
        'entropy_source = "/dev/urandom"\ndefault_bridges = 1\ncold_plug_vfio = "root-port"\npcie_root_port = 8\n'
        '[[hypervisor.qemu.guest_extension_images]]\nname = "gpu"\npath = "/gpu.img"\n'
        '[[hypervisor.qemu.guest_extension_images]]\nname = "coco"\npath = "/coco.img"\n'
    )
    ram = shape["memory_mib"] << 20
    bits = pcialloc.ovmf_phys_bits(platform.phys_bits, platform.guest_phys_bits)
    base, size = pcialloc.mmio64_window(
        bits, max(a + n for a, n in tdhob.q35_e820_ram(ram))
    )
    blobs = acpi.fw_cfg_blobs(
        load_config(config),
        Guest(shape["vcpus"], shape["memory_mib"], shape["gpus"]),
        window_base=base,
        window_size=size,
        gpu_bars=platform.gpu_bars,
    )
    events = shape["events"]
    assert hashlib.sha384(blobs.table_loader).hexdigest() == events["table_loader"]
    assert hashlib.sha384(blobs.rsdp).hexdigest() == events["rsdp"]
    assert hashlib.sha384(blobs.tables).hexdigest() == events["acpi_tables"]


@pytest.mark.parametrize("shape", SHAPES, ids=_shape_id)
def test_registers(
    shape: dict[str, Any], kata_config: Path, kata_root: Path, platform: Platform
) -> None:
    from cvm_measure.kata_tdx.config import load_config
    from cvm_measure.kata_tdx.registers import Guest, compute

    regs = compute(
        load_config(kata_config, root=kata_root),
        platform,
        Guest(shape["vcpus"], shape["memory_mib"], shape["gpus"]),
        initdata=FIXTURES_DIR / "initdata" / GOLDEN["initdata"],
    )
    assert regs.as_dict() == {
        "mrtd": GOLDEN["mrtd"],
        "mrconfigid": GOLDEN["mrconfigid"],
        "rtmr0": shape["rtmr0"],
        "rtmr1": GOLDEN["rtmr1"],
        "rtmr2": GOLDEN["rtmr2"],
        "rtmr3": "00" * 48,
    }


def test_cli(
    kata_config: Path, kata_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from cvm_measure.cli import main

    shape = SHAPES[0]
    main(
        [
            "kata-tdx",
            "--config",
            str(kata_config),
            "--root",
            str(kata_root),
            "--platform",
            str(PLATFORM),
            "--vcpus",
            str(shape["vcpus"]),
            "--memory-mib",
            str(shape["memory_mib"]),
            "--gpus",
            str(shape["gpus"]),
            "--initdata",
            str(FIXTURES_DIR / "initdata" / GOLDEN["initdata"]),
            "--output-format",
            "json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert out["rtmr0"] == shape["rtmr0"]
    assert out["mrconfigid"] == GOLDEN["mrconfigid"]
