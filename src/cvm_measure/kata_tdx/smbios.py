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

"""The SMBIOS table OVMF measures as EV_EFI_HANDOFF_TABLES.

QEMU's structures are its fw_cfg file etc/smbios/smbios-tables (see
:mod:`qemu`). OVMF's SmbiosPlatformDxe installs them in order, adds its own
type 0 when QEMU sent none, and SmbiosDxe appends an end-of-table record.
SmbiosMeasurementDxe hashes the result after blanking the fields in its
filter table.
"""

from __future__ import annotations

import hashlib
import struct


def check_entry_point(anchor: bytes) -> None:
    # 255 or more cores per socket make QEMU's auto entry point switch to 3.0.
    if not anchor.startswith(b"_SM_"):
        raise NotImplementedError(
            "OVMF's handling of an SMBIOS 3.0 entry point is not modelled"
        )


def with_processor_id(tables: bytes, cpuid_1_eax: int, cpuid_1_edx: int) -> bytes:
    """QEMU copies its own CPUID leaf 1 into type 4; use the host's."""
    out = bytearray(tables)
    off = 0
    while out[off] != 127:
        if out[off] == 4:
            struct.pack_into("<II", out, off + 8, cpuid_1_eax, cpuid_1_edx)
        off = out.index(b"\0\0", off + out[off + 1]) + 2
    return bytes(out)


# OvmfPkg/SmbiosPlatformDxe mOvmfDefaultType0 with the default PCDs:
# PcdFirmwareVendor "EDK II", empty version and date strings replaced by the
# driver's fallbacks.
_OVMF_TYPE0 = (
    struct.pack(
        "<BBHBBHBBQBBBBBBH",
        0,
        0x1A,
        0,
        1,
        2,
        0xE800,
        3,
        0,
        1 << 3,
        0,
        0x1C,
        0,
        0,
        0xFF,
        0xFF,
        0,
    )
    + b"EDK II\0unknown\x0002/02/2022\0\0"
)
# SmbiosDxe end-of-table record; 0xFEFF is GetMaxSmbiosHandle for SMBIOS > 2.0.
_END_OF_TABLE = struct.pack("<BBH", 127, 4, 0xFEFF) + b"\0\0"

# SmbiosMeasurementDxe mSmbiosFilterStandardTableBlackList:
# type -> [(offset, size, is_string)]; None zeroes everything after the header.
_FILTERS: dict[int, list[tuple[int, int, bool]] | None] = {
    1: [(0x07, 1, True), (0x08, 16, False), (0x18, 1, False)],
    2: [(0x07, 1, True), (0x0A, 1, True)],
    3: [(0x07, 1, True), (0x08, 1, True)],
    4: [
        (0x20, 1, True),
        (0x21, 1, True),
        (0x22, 1, True),
        (0x23, 1, False),
        (0x24, 1, False),
        (0x25, 1, False),
        (0x2A, 2, False),
        (0x2C, 2, False),
        (0x2E, 2, False),
        (0x11, 1, False),
        (0x16, 2, False),
    ],
    11: None,
    15: None,
    17: [(0x18, 1, True), (0x19, 1, True), (0x1A, 1, True)],
    18: None,
    22: [(0x0E, 1, True), (0x10, 2, False), (0x12, 2, False)],
    23: [(0x05, 2, False)],
    27: [(0x0C, 2, False)],
    31: None,
    33: None,
    39: [(0x07, 1, True), (0x08, 1, True), (0x09, 1, True)],
}


def _split(table: bytes) -> list[bytes]:
    out, off = [], 0
    while off < len(table):
        end = table.index(b"\0\0", off + table[off + 1]) + 2
        out.append(table[off:end])
        off = end
    return out


def ovmf_table(qemu: bytes) -> bytes:
    """The table SmbiosDxe publishes from QEMU's etc/smbios/smbios-tables."""
    records = []
    for rec in _split(qemu):
        if rec[0] == 127:
            break
        records.append(rec)
    if not any(r[0] == 0 for r in records):
        records.append(_OVMF_TYPE0)
    return b"".join(records) + _END_OF_TABLE


def _filter(record: bytes) -> bytes:
    rec = bytearray(record)
    rtype, length = rec[0], rec[1]
    filters = _FILTERS.get(rtype, [])
    if rtype >= 128 or filters is None:
        rec[4:] = bytes(len(rec) - 4)
        return bytes(rec)
    for off, size, is_string in filters:
        if length < off + size:
            continue
        if is_string and rec[off]:
            strings = bytes(rec[length:]).split(b"\0")
            start = length + sum(len(s) + 1 for s in strings[: rec[off] - 1])
            n = len(strings[rec[off] - 1])
            rec[start : start + n] = b" " * n
        rec[off : off + size] = bytes(size)
    return bytes(rec)


def handoff_digest(qemu: bytes) -> bytes:
    return hashlib.sha384(
        b"".join(_filter(r) for r in _split(ovmf_table(qemu)))
    ).digest()
