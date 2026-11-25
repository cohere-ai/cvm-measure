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

"""The kernel command line Kata runtime-rs passes to QEMU with ``-append``.

Ported from runtime-rs ``hypervisor/src/kernel_param.rs`` (KernelParams),
``qemu/cmdline_generator.rs`` (Kernel::new and the console device) and
kata-types ``get_agent_kernel_params``. OVMF measures this string into RTMR[2].
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from .config import KataConfig

GUEST_IMAGE_REGISTRY_AUTH_PATH = (
    "/run/kata-containers/shared/containers/"
    "0000000000000000000000000000000000000000000000000000000000000000-0000000000000000-"
    "registry-auth.json"
)
_IMAGE_ROOTFS_DRIVERS = ("virtio-blk-pci", "virtio-blk-ccw", "virtio-blk-mmio")
_VERITY_BLOCK_SIZE_BYTES = 512
_DEFAULT_CDH_API_TIMEOUT_MS = 50_000


def partition_uuids(image: Path) -> dict[int, str]:
    """kata-types fs::partition_uuids for an MBR image: "<disk signature>-<partition>"."""
    with image.open("rb") as f:
        mbr = f.read(512)
    if len(mbr) != 512 or mbr[510:512] != b"\x55\xaa":
        raise ValueError(f"{image}: invalid rootfs MBR signature")
    entries = [mbr[446 + 16 * i : 462 + 16 * i] for i in range(4)]
    if any(e[4] == 0xEE for e in entries):
        raise NotImplementedError(f"{image}: GPT rootfs images are not supported")
    (signature,) = struct.unpack_from("<I", mbr, 440)
    return {
        i + 1: f"{signature:08x}-{i + 1:02x}"
        for i, e in enumerate(entries)
        if e[4] != 0 and e[12:16] != bytes(4)
    }


def split_kernel_params(params: str) -> list[tuple[str, str]]:
    """KernelParams::from_string: split on spaces outside double quotes, then on the first '='."""
    out, current, in_quote = [], "", False
    for c in params + " ":
        if c == '"':
            in_quote = not in_quote
        elif c == " " and not in_quote:
            if current.strip():
                key, _, value = current.strip().partition("=")
                out.append((key, value))
            current = ""
            continue
        current += c
    return out


def _verity(params: str) -> dict[str, str] | None:
    if not params.strip():
        return None
    fields = dict(f.strip().split("=", 1) for f in params.split(",") if f.strip())
    if "root_hash" not in fields:
        raise ValueError("kernel_verity_params is missing root_hash")
    return fields


def _rootfs_params(
    cfg: KataConfig, root: str, hash_device: str
) -> list[tuple[str, str]]:
    if cfg.rootfs_type not in ("ext4", "xfs", "erofs"):
        raise ValueError(f"Unsupported rootfs type {cfg.rootfs_type!r}")
    flags = "data=ordered,errors=remount-ro ro" if cfg.rootfs_type == "ext4" else "ro"
    verity = _verity(cfg.kernel_verity_params)
    if verity is None:
        return [("root", root), ("rootflags", flags), ("rootfstype", cfg.rootfs_type)]
    data_blocks = int(verity["data_blocks"])
    data_block_size = int(verity["data_block_size"])
    dm = (
        f"dm-verity,,,ro,0 {data_block_size // _VERITY_BLOCK_SIZE_BYTES * data_blocks} verity 1 "
        f"{root} {hash_device} {data_block_size} {int(verity['hash_block_size'])} {data_blocks} "
        f"0 sha256 {verity['root_hash']} {verity.get('salt', '')}"
    )
    return [
        ("dm-mod.create", f'"{dm}"'),
        ("root", "/dev/dm-0"),
        ("rootflags", flags),
        ("rootfstype", cfg.rootfs_type),
    ]


def agent_kernel_params(agent: dict[str, Any]) -> list[str]:
    """get_agent_kernel_params, rendered in BTreeMap (key) order."""
    if agent.get("mem_agent", {}).get("enable", False):
        raise NotImplementedError("agent mem_agent parameters are not supported")
    kv: dict[str, str] = {}
    if agent.get("enable_debug", False):
        kv["agent.log"] = "debug"
    if agent.get("enable_tracing", False):
        kv["agent.trace"] = "true"
    if agent.get("container_pipe_size", 0) > 0:
        kv["agent.container_pipe_size"] = str(agent["container_pipe_size"])
    if agent.get("launch_process_timeout", 0) > 0:
        kv["agent.launch_process_timeout"] = str(agent["launch_process_timeout"])
    cdh_ms = agent.get("cdh_api_timeout_ms", _DEFAULT_CDH_API_TIMEOUT_MS)
    if cdh_ms > 0:
        kv["agent.cdh_api_timeout"] = str(cdh_ms // 1000)
    if agent.get("debug_console_enabled", False):
        raise NotImplementedError("agent debug console is not supported")
    if agent.get("visible_cdi_devices", False):
        kv["agent.visible_cdi_devices"] = "true"
    if agent.get("image_registry_auth_file", ""):
        kv["agent.image_registry_auth"] = f"file://{GUEST_IMAGE_REGISTRY_AUTH_PATH}"
    return [f"{k}={v}" if v else k for k, v in sorted(kv.items())]


def kernel_cmdline(cfg: KataConfig) -> str:
    if cfg.initrd:
        raise NotImplementedError("initrd boot is not supported")
    if cfg.vm_rootfs_driver not in _IMAGE_ROOTFS_DRIVERS:
        raise NotImplementedError(
            f"rootfs driver {cfg.vm_rootfs_driver!r} is not supported"
        )
    if cfg.enable_iommu:
        raise NotImplementedError("enable_iommu is not supported")
    if cfg.use_legacy_serial:
        raise NotImplementedError("use_legacy_serial is not supported")

    params: list[tuple[str, str]] = [
        ("reboot", "k"),
        ("panic", "1"),
        ("systemd.unit", "kata-containers.target"),
        ("systemd.mask", "systemd-networkd.service"),
        ("systemd.mask", "systemd-networkd.socket"),
    ]
    if cfg.hypervisor_debug:
        params.append(("agent.log_vport", "1025"))

    uuids = partition_uuids(cfg.image)
    root = f"PARTUUID={uuids[1]}"
    if cfg.kernel_verity_params:
        hash_device = f"PARTUUID={uuids[2]}"
        params += _rootfs_params(cfg, root, hash_device)
        params.append(("dm-mod.waitfor", f"{root},{hash_device}"))
    else:
        params += _rootfs_params(cfg, root, "")
        params.append(("rootwait", ""))

    boot_params = " ".join(
        [*agent_kernel_params(cfg.agent), cfg.kernel_params]
        if cfg.kernel_params
        else agent_kernel_params(cfg.agent)
    )
    params += split_kernel_params(boot_params)
    params.append(("selinux", "0" if cfg.disable_guest_selinux else "1"))
    for ext in cfg.extensions:
        params += split_kernel_params(
            f"kata.extension.{ext.name}.verity_params={ext.verity_params}"
        )
    params.append(("console", "hvc0"))
    return " ".join(f"{k}={v}" if v else k for k, v in params)
