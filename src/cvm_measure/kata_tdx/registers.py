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

"""TDX registers of a Kata pod VM on QEMU q35 with OVMF IntelTdx and a direct kernel boot."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..tdx.initdata import compute_digest
from ..tdx.mrtd import cfv_image, compute_mrtd
from ..tdx.pe import pe_authenticode_digest
from ..tdx.registers import EFI_ACTION_DIGESTS, SEPARATOR_DIGEST
from ..tdx.rtmr import SHA384_SIZE, replay_digests
from ..tdx.uefi import (
    EFI_GLOBAL_VARIABLE_GUID,
    EFI_IMAGE_SECURITY_DATABASE_GUID,
    compute_variable_digest,
)
from . import pcialloc, qemu, smbios, tdhob
from .cmdline import kernel_cmdline
from .config import KataConfig
from .ovmf import boot_manager_menu_option
from .platform import Platform

# QEMU fw_cfg "bootorder" for a -kernel boot: the linuxboot_dma option ROM only.
_FW_CFG_BOOTORDER = b"/rom@genroms/linuxboot_dma.bin\0"
# fw_cfg "BootMenu": the u16 boot menu flag, off.
_FW_CFG_BOOT_MENU = b"\0\0"
# OVMF with no persistent variable store: BootOrder holds Boot0000 only.
_BOOT_ORDER = b"\0\0"
_SECURE_BOOT_VARIABLES = (
    (EFI_GLOBAL_VARIABLE_GUID, "SecureBoot"),
    (EFI_GLOBAL_VARIABLE_GUID, "PK"),
    (EFI_GLOBAL_VARIABLE_GUID, "KEK"),
    (EFI_IMAGE_SECURITY_DATABASE_GUID, "db"),
    (EFI_IMAGE_SECURITY_DATABASE_GUID, "dbx"),
)


@dataclass(frozen=True)
class Guest:
    """The VM size Kata gives QEMU (-smp, -m) and the GPUs it cold-plugs."""

    vcpus: int
    memory_mib: int
    gpus: int


@dataclass(frozen=True)
class KataTdxRegisters:
    mrtd: str
    mrconfigid: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str

    def as_dict(self) -> dict[str, str]:
        return {
            "mrtd": self.mrtd,
            "mrconfigid": self.mrconfigid,
            "rtmr0": self.rtmr0,
            "rtmr1": self.rtmr1,
            "rtmr2": self.rtmr2,
            "rtmr3": self.rtmr3,
        }


def rtmr0_digests(
    cfg: KataConfig,
    platform: Platform,
    guest: Guest,
    firmware: bytes,
    qemu_wrapper: Sequence[str] = (),
) -> list[bytes]:
    """The RTMR[0] events in the order OVMF measures them."""
    ram = guest.memory_mib << 20
    first_non_address = max(a + n for a, n in tdhob.q35_e820_ram(ram))
    bits = pcialloc.ovmf_phys_bits(platform.phys_bits, platform.guest_phys_bits)
    window_base, window_size = pcialloc.mmio64_window(bits, first_non_address)
    hole64 = pcialloc.root_bus_mem64(
        window_base=window_base,
        window_size=window_size,
        root_ports=[
            list(platform.gpu_bars) if k < guest.gpus else []
            for k in range(cfg.pcie_root_port)
        ],
        root_bus_bars=qemu.root_bus_virtio_bars(cfg),
    )
    blobs = qemu.read_fw_cfg(
        cfg,
        guest,
        hole64=hole64,
        phys_bits=bits,
        names=(
            qemu.TABLE_LOADER,
            qemu.ACPI_RSDP,
            qemu.ACPI_TABLES,
            qemu.SMBIOS_ANCHOR,
            qemu.SMBIOS_TABLES,
        ),
        wrapper=qemu_wrapper,
    )
    smbios.check_entry_point(blobs[qemu.SMBIOS_ANCHOR])
    tables = smbios.with_processor_id(
        blobs[qemu.SMBIOS_TABLES], platform.cpuid_1_eax, platform.cpuid_1_edx
    )

    def sha384(data: bytes) -> bytes:
        return hashlib.sha384(data).digest()

    return [
        tdhob.tdx_table_digest(firmware, ram),
        sha384(cfv_image(firmware)),
        sha384(_FW_CFG_BOOT_MENU),
        sha384(_FW_CFG_BOOTORDER),
        *(
            compute_variable_digest(guid, name, b"")
            for guid, name in _SECURE_BOOT_VARIABLES
        ),
        SEPARATOR_DIGEST,
        sha384(blobs[qemu.TABLE_LOADER]),
        sha384(blobs[qemu.ACPI_RSDP]),
        sha384(blobs[qemu.ACPI_TABLES]),
        smbios.handoff_digest(tables),
        sha384(_BOOT_ORDER),
        sha384(boot_manager_menu_option(firmware)),
    ]


def rtmr1_digests(kernel: bytes) -> list[bytes]:
    return [
        pe_authenticode_digest(kernel, "sha384"),
        EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
        SEPARATOR_DIGEST,
        EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
        EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
    ]


def rtmr2_digests(cmdline: str) -> list[bytes]:
    """OVMF's QemuKernelLoaderFsDxe measures the command line as UTF-16, NUL included."""
    return [hashlib.sha384((cmdline + "\0").encode("utf-16-le")).digest()]


def compute(
    cfg: KataConfig,
    platform: Platform,
    guest: Guest,
    initdata: Path | bytes | None = None,
    qemu_wrapper: Sequence[str] = (),
) -> KataTdxRegisters:
    if cfg.initrd:
        raise NotImplementedError(
            "initrd boots measure an extra RTMR[2] event that is not modelled"
        )
    firmware = Path(cfg.firmware).read_bytes()
    kernel = Path(cfg.kernel).read_bytes()
    return KataTdxRegisters(
        mrtd=compute_mrtd(firmware).hex(),
        mrconfigid=(
            compute_digest(initdata) if initdata is not None else bytes(SHA384_SIZE)
        ).hex(),
        rtmr0=replay_digests(
            rtmr0_digests(cfg, platform, guest, firmware, qemu_wrapper)
        ).hex(),
        rtmr1=replay_digests(rtmr1_digests(kernel)).hex(),
        rtmr2=replay_digests(rtmr2_digests(kernel_cmdline(cfg))).hex(),
        rtmr3=bytes(SHA384_SIZE).hex(),
    )
