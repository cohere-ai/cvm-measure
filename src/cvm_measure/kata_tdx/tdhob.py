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

"""The TD HOB QEMU hands to TDVF, and the TdxTable event OVMF measures from it.

QEMU builds the HOB in ``hw/i386/tdvf-hob.c`` from the RAM entries of
``target/i386/kvm/tdx.c``: the q35 e820 RAM ranges, with each TD_HOB and
TEMP_MEM section of the firmware's TDX metadata split out as accepted memory,
sorted by address. OVMF's ``TdxHelperMeasureTdHob`` hashes the list up to, but
not including, its end-of-list HOB.
"""

from __future__ import annotations

import hashlib
import struct

from ..tdx.mrtd import (
    EFI_HOB_HANDOFF_TABLE_VERSION,
    EFI_HOB_TYPE_END_OF_HOB_LIST,
    EFI_HOB_TYPE_HANDOFF,
    EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
    EFI_RESOURCE_MEMORY_UNACCEPTED,
    EFI_RESOURCE_SYSTEM_MEMORY,
    GIB,
    SIZEOF_HOB_GENERIC_HEADER,
    SIZEOF_HOB_HANDOFF_INFO,
    SIZEOF_HOB_RESOURCE_DESCRIPTOR,
    TDHOB_BASE_ATTRIBUTES,
    TDX_SECTION_TDHOB,
    TDX_SECTION_TEMPMEM,
    TDXMetadataSection,
    _parse_tdx_metadata,
)


def q35_e820_ram(ram_bytes: int) -> list[tuple[int, int]]:
    """pc_q35_init's low/high split and pc_memory_init's E820_RAM entries."""
    lowmem = 0x8000_0000 if ram_bytes >= 0xB000_0000 else 0xB000_0000
    if ram_bytes >= lowmem:
        return [(0, lowmem), (4 * GIB, ram_bytes - lowmem)]
    return [(0, ram_bytes)]


def ram_entries(
    ram_bytes: int, sections: list[TDXMetadataSection]
) -> list[tuple[int, int, bool]]:
    """tdx_init_ram_entries and tdx_accept_ram_range: (address, length, accepted)."""
    entries = [(addr, length, False) for addr, length in q35_e820_ram(ram_bytes)]
    for sec in sections:
        if sec.section_type not in (TDX_SECTION_TDHOB, TDX_SECTION_TEMPMEM):
            continue
        addr, size = sec.memory_base, sec.memory_size
        i = next(
            (
                i
                for i, (a, n, _) in enumerate(entries)
                if a <= addr and addr + size <= a + n
            ),
            None,
        )
        if i is None:
            raise ValueError(
                f"TDVF section 0x{addr:x}+0x{size:x} is not inside one RAM entry"
            )
        start, length, accepted = entries[i]
        if accepted:
            continue
        entries[i] = (addr, size, True)
        if addr > start:
            entries.append((start, addr - start, False))
        if addr + size < start + length:
            entries.append((addr + size, start + length - addr - size, False))
    return sorted(entries, key=lambda e: e[0])


def td_hob(firmware: bytes, ram_bytes: int) -> tuple[int, bytes]:
    """Return the HOB list's guest address and its bytes, end-of-list HOB included."""
    sections = _parse_tdx_metadata(firmware).sections
    hobs = [s for s in sections if s.section_type == TDX_SECTION_TDHOB]
    if len(hobs) != 1:
        raise ValueError(
            f"Firmware TDX metadata describes {len(hobs)} TD_HOB sections; expected 1"
        )
    base = hobs[0].memory_base

    body = b"".join(
        struct.pack(
            "<HHI16sIIQQ",
            EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
            SIZEOF_HOB_RESOURCE_DESCRIPTOR,
            0,
            bytes(16),
            EFI_RESOURCE_SYSTEM_MEMORY if accepted else EFI_RESOURCE_MEMORY_UNACCEPTED,
            TDHOB_BASE_ATTRIBUTES,
            addr,
            length,
        )
        for addr, length, accepted in ram_entries(ram_bytes, sections)
    )
    end = struct.pack(
        "<HHI", EFI_HOB_TYPE_END_OF_HOB_LIST, SIZEOF_HOB_GENERIC_HEADER, 0
    )
    end_of_list = base + SIZEOF_HOB_HANDOFF_INFO + len(body) + len(end)
    phit = struct.pack(
        "<HHIIIQQQQQ",
        EFI_HOB_TYPE_HANDOFF,
        SIZEOF_HOB_HANDOFF_INFO,
        0,
        EFI_HOB_HANDOFF_TABLE_VERSION,
        0,
        0,
        0,
        0,
        0,
        end_of_list,
    )
    if len(phit) + len(body) + len(end) > hobs[0].memory_size:
        raise ValueError("TD HOB does not fit its TDVF section")
    return base, phit + body + end


def tdx_table_digest(firmware: bytes, ram_bytes: int) -> bytes:
    _, hob = td_hob(firmware, ram_bytes)
    return hashlib.sha384(hob[:-SIZEOF_HOB_GENERIC_HEADER]).digest()
