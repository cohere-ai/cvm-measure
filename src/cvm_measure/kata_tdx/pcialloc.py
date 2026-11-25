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

"""Where OVMF places 64-bit PCI resources, which QEMU reports in DSDT PCI0._CRS.

QEMU builds its ACPI tables after OVMF has programmed every BAR and bridge
window, and derives the 64-bit hole from the lowest and highest 64-bit
resources on the root bus. This ports the parts of OVMF that decide those:
PlatformAddressWidthFromCpuid and PlatformDynamicMmioWindow (PlatformInitLib
MemDetect.c), PciHotPlugInit's resource padding for hotplug-capable bridges,
and PciBusDxe's InsertResourceNode and CalculateResourceAperture, with
PciHostBridgeDxe allocating the root aperture bottom-up from the window base.
In a TD, IncompatiblePciDeviceSupport keeps 64-bit BARs 64-bit and option
ROMs are not mapped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

GIB = 1 << 30
# PciHostBridge.c: memory apertures are 1 MiB aligned.
_ROOT_ALIGNMENT = (1 << 20) - 1


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class Node:
    length: int
    alignment: int
    padding: bool = False
    children: list[Node] = field(default_factory=list)
    offset: int = 0


def insert(bridge: Node, node: Node) -> None:
    """InsertResourceNode: descending alignment, ties ordered by (Length & Alignment)."""
    kids = bridge.children
    kids.insert(0, node)
    i = 1
    while i < len(kids):
        other = kids[i]
        if node.alignment > other.alignment:
            break
        if node.alignment == other.alignment:
            rest, other_rest = (
                node.length & node.alignment,
                other.length & other.alignment,
            )
            if rest == 0 or rest >= other_rest:
                break
        kids[i - 1], kids[i] = kids[i], kids[i - 1]
        i += 1


def aperture(bridge: Node) -> None:
    """CalculateResourceAperture for a memory resource node."""
    used = {False: 0, True: 0}
    for node in bridge.children:
        node.offset = align_up(used[node.padding], node.alignment + 1)
        used[node.padding] = node.offset + node.length
    bridge.length = max(align_up(v, bridge.alignment + 1) for v in used.values())
    if bridge.children and bridge.children[0].alignment > bridge.alignment:
        bridge.alignment = bridge.children[0].alignment


def ovmf_phys_bits(
    phys_bits: int, guest_phys_bits: int, *, page_1g: bool = True
) -> int:
    """PlatformAddressWidthFromCpuid for OVMF built with 4-level paging."""
    bits = phys_bits
    if guest_phys_bits and bits > guest_phys_bits:
        bits = guest_phys_bits
    bits = min(bits, 46)
    if not page_1g and bits > 40:
        bits = 40
    return bits


def mmio64_window(
    phys_bits: int, first_non_address: int, pci64_size: int = 32 * GIB
) -> tuple[int, int]:
    """PlatformDynamicMmioWindow: the top eighth of the address space.

    ``pci64_size`` is PcdPciMmio64Size; the classic window would start at
    ``first_non_address`` aligned to its largest power of two.
    """
    space, size = 1 << phys_bits, 1 << (phys_bits - 3)
    classic_base = align_up(first_non_address, 1 << (pci64_size.bit_length() - 1))
    if not (pci64_size < size and classic_base + size < space):
        raise NotImplementedError("OVMF would use its classic MMIO window")
    return space - size, size


def hotplug_pref64_padding(window_size: int) -> int:
    """PciHotPlugInit GetResourcePadding default for a PCIe root port's 64-bit prefetchable window."""
    if window_size <= 32 * GIB:
        return 0
    pad = window_size >> 8
    return 1 << (pad - 1).bit_length()


def root_bus_mem64(
    *,
    window_base: int,
    window_size: int,
    root_ports: list[list[int]],
    root_bus_bars: list[int],
) -> tuple[int, int]:
    """Return [lowest, highest+1) of the 64-bit resources OVMF places on the root bus.

    ``root_ports`` lists, per PCIe root port, the 64-bit BAR sizes behind it.
    ``root_bus_bars`` lists the 64-bit BAR sizes of devices on the root bus.
    """
    pad = hotplug_pref64_padding(window_size)
    root = Node(0, _ROOT_ALIGNMENT)
    for bars in root_ports:
        port = Node(0, _ROOT_ALIGNMENT)
        for size in bars:
            insert(port, Node(size, size - 1))
        if pad:
            insert(port, Node(pad, pad - 1, padding=True))
        aperture(port)
        insert(root, port)
    for size in root_bus_bars:
        insert(root, Node(size, size - 1))
    aperture(root)
    start = align_up(window_base, root.alignment + 1)
    used = [n for n in root.children if n.length]
    return start + min(n.offset for n in used), start + max(
        n.offset + n.length for n in used
    )
