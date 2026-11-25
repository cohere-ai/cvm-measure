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

"""The ACPI fw_cfg blobs QEMU q35 builds for a Kata pod VM.

QEMU rebuilds its tables after OVMF has enumerated PCI, so they depend on the
device tree Kata's QEMU command line creates and on where OVMF put the 64-bit
BARs. The tree is the runtime-rs device order for the configuration; the BAR
placement comes from :mod:`pcialloc`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from . import pcialloc
from .qemu_acpi import (
    ACPI_BUILD_LOADER_FILE,
    ACPI_BUILD_RSDP_FILE,
    ACPI_BUILD_TABLE_FILE,
    PciBus,
    PciDevice,
    Topology,
    build,
)

if TYPE_CHECKING:
    from .config import KataConfig
    from .registers import Guest

# virtio-pci modern devices on QEMU 11.0 expose one 16 KiB 64-bit prefetchable BAR.
_VIRTIO_MODERN_BAR = 16 << 10
# Kata places cold-plugged GPU root ports at fixed addresses from slot 9.
_FIRST_GPU_PORT_SLOT = 0x09
_PCI_BRIDGE_SLOT = 0x02


@dataclass(frozen=True)
class FwCfgBlobs:
    table_loader: bytes
    rsdp: bytes
    tables: bytes


class _RootBus:
    """do_pci_register_device's slot choice on pcie.0: the first free function-0 slot."""

    def __init__(self) -> None:
        self.bus = PciBus(express=True)
        self.used: set[int] = set()

    def add(
        self,
        kind: str,
        name: str,
        slot: int | None = None,
        function: int = 0,
        **kw: Any,
    ) -> PciDevice:
        if slot is None:
            slot = next(s for s in range(32) if (s << 3) not in self.used)
        devfn = (slot << 3) | function
        if devfn in self.used:
            raise ValueError(f"{name}: devfn {devfn:#x} already in use")
        self.used.add(devfn)
        dev = PciDevice(slot=slot, function=function, kind=kind, name=name, **kw)
        self.bus.devices.append(dev)
        return dev


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


def kata_topology(cfg: KataConfig, gpus: int) -> Topology:
    """The PCI tree from runtime-rs's QEMU command line, in device realize order.

    The pod has one network interface, and the initdata disk sits on the
    virtio-scsi controller, so it adds no PCI function.
    """
    _check_supported(cfg, gpus)
    rb = _RootBus()
    rb.add("host-bridge", "mch", 0, hotpluggable=False)
    rb.add("lpc", "ich9-lpc", 0x1F, function=0, hotpluggable=False)
    rb.add("endpoint", "ich9-ahci", 0x1F, function=2)
    rb.add("smbus", "ich9-smbus", 0x1F, function=3, hotpluggable=False)
    ports = [
        rb.add(
            "pcie-root-port",
            f"rp{k}",
            _FIRST_GPU_PORT_SLOT + k,
            bus=PciBus(express=True),
        )
        for k in range(gpus)
    ]
    rb.add("endpoint", "virtio-rng-pci")
    rb.add("pci-bridge", "pci-bridge-0", _PCI_BRIDGE_SLOT, bus=PciBus(express=False))
    rb.add("endpoint", "virtio-scsi-pci")
    rb.add("endpoint", "virtio-net-pci")
    rb.add("endpoint", "vhost-vsock-pci")
    for i in range(1 + len(cfg.extensions)):
        rb.add("endpoint", f"virtio-blk-pci{i}")
    for k, port in enumerate(ports):
        port.secondary.devices.append(
            PciDevice(slot=0, kind="endpoint", name=f"gpu{k}")
        )
    for k in range(gpus, cfg.pcie_root_port):
        rb.add("pcie-root-port", f"rp{k}", bus=PciBus(express=True))
    rb.add("endpoint", "virtio-serial-pci")
    return Topology(root=rb.bus)


def _root_bus_virtio_bars(topology: Topology) -> list[int]:
    return [
        _VIRTIO_MODERN_BAR
        for d in topology.root.devices
        if d.kind == "endpoint" and d.name.startswith(("virtio-", "vhost-"))
    ]


def fw_cfg_blobs(
    cfg: KataConfig,
    guest: Guest,
    *,
    window_base: int,
    window_size: int,
    gpu_bars: tuple[int, ...],
) -> FwCfgBlobs:
    topology = kata_topology(cfg, guest.gpus)
    hole64 = pcialloc.root_bus_mem64(
        window_base=window_base,
        window_size=window_size,
        root_ports=[
            list(gpu_bars) if k < guest.gpus else [] for k in range(cfg.pcie_root_port)
        ],
        root_bus_bars=_root_bus_virtio_bars(topology),
    )
    blobs = build(
        topology, vcpus=guest.vcpus, ram_bytes=guest.memory_mib << 20, hole64=hole64
    )
    return FwCfgBlobs(
        table_loader=blobs[ACPI_BUILD_LOADER_FILE],
        rsdp=blobs[ACPI_BUILD_RSDP_FILE],
        tables=blobs[ACPI_BUILD_TABLE_FILE],
    )
