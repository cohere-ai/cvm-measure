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

"""The subset of a Kata runtime-rs configuration that reaches the TD's measurements.

Kata reads ``config.d/*.toml`` next to the configuration file in name order and
merges each over the base, so a host's drop-ins change what is measured just
as the release configuration does.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib


@dataclass(frozen=True)
class Extension:
    name: str
    path: Path
    verity_params: str


@dataclass(frozen=True)
class KataConfig:
    qemu: Path
    firmware: Path
    kernel: Path
    image: Path
    initrd: str
    kernel_params: str
    kernel_verity_params: str
    rootfs_type: str
    vm_rootfs_driver: str
    hypervisor_debug: bool
    disable_guest_selinux: bool
    use_legacy_serial: bool
    enable_iommu: bool
    machine_type: str
    pcie_root_port: int
    pcie_switch_port: int
    default_bridges: int
    cold_plug_vfio: str
    block_device_driver: str
    shared_fs: str
    entropy_source: str
    extensions: tuple[Extension, ...]
    agent: dict[str, Any]


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _load_toml(path: Path) -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        with path.open("rb") as f:
            return tomllib.load(f)
    raise RuntimeError(
        "Reading Kata configuration needs Python 3.11 or newer (tomllib)"
    )


def load_config(path: str | Path, root: str | Path = "/") -> KataConfig:
    """Load a Kata configuration and its drop-ins.

    Absolute paths in the configuration are resolved under ``root``, so an
    extracted release tarball can stand in for the host's ``/``.
    """
    path = Path(path)
    data = _load_toml(path)
    drop_ins = path.parent / "config.d"
    if drop_ins.is_dir():
        for drop_in in sorted(drop_ins.glob("*.toml")):
            data = _merge(data, _load_toml(drop_in))

    runtime = data.get("runtime", {})
    hv_name = runtime.get("hypervisor_name", "qemu")
    agent_name = runtime.get("agent_name", "kata")
    hv = data["hypervisor"][hv_name]
    agent = data.get("agent", {}).get(agent_name, {})

    def host(p: str) -> Path:
        return Path(root) / p.lstrip("/")

    return KataConfig(
        qemu=host(hv["path"]),
        firmware=host(hv["firmware"]),
        kernel=host(hv["kernel"]),
        image=host(hv["image"]),
        initrd=hv.get("initrd", ""),
        kernel_params=hv.get("kernel_params", ""),
        kernel_verity_params=hv.get("kernel_verity_params", ""),
        rootfs_type=hv.get("rootfs_type", ""),
        vm_rootfs_driver=hv.get("vm_rootfs_driver", ""),
        hypervisor_debug=bool(hv.get("enable_debug", False)),
        disable_guest_selinux=bool(hv.get("disable_guest_selinux", False)),
        use_legacy_serial=bool(hv.get("use_legacy_serial", False)),
        enable_iommu=bool(hv.get("enable_iommu", False)),
        machine_type=hv.get("machine_type", "q35"),
        pcie_root_port=int(hv.get("pcie_root_port", 0)),
        pcie_switch_port=int(hv.get("pcie_switch_port", 0)),
        default_bridges=int(hv.get("default_bridges", 0)),
        cold_plug_vfio=hv.get("cold_plug_vfio", "no-port"),
        block_device_driver=hv.get("block_device_driver", "virtio-scsi"),
        shared_fs=hv.get("shared_fs", ""),
        entropy_source=hv.get("entropy_source", ""),
        extensions=tuple(
            Extension(e["name"], host(e["path"]), e.get("verity_params", ""))
            for e in hv.get("guest_extension_images", [])
        ),
        agent=agent,
    )
