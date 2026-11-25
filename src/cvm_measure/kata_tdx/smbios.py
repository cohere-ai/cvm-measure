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

QEMU generates the structures (``hw/smbios/smbios.c``, default options, SMBIOS
2.8 entry point). OVMF's SmbiosPlatformDxe installs them in order, adds its
own type 0 when QEMU sent none, and SmbiosDxe appends an end-of-table record.
SmbiosMeasurementDxe hashes the result after blanking the fields in its
filter table.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence

KIB, MIB, TIB = 1 << 10, 1 << 20, 1 << 40

QEMU_MANUFACTURER = "QEMU"
Q35_DESCRIPTION = "Standard PC (Q35 + ICH9, 2009)"


def _record(rtype: int, handle: int, fmt: bytes, strings: Sequence[str] = ()) -> bytes:
    head = struct.pack("<BBH", rtype, 4 + len(fmt), handle) + fmt
    if not strings:
        return head + b"\0\0"
    return head + b"".join(s.encode() + b"\0" for s in strings) + b"\0"


def qemu_tables(
    *,
    machine: str,
    vcpus: int,
    ram_bytes: int,
    e820_ram: Sequence[tuple[int, int]],
    cpuid_1_eax: int,
    cpuid_1_edx: int,
    memory_device_size: int = 2 * TIB,
) -> bytes:
    """smbios_get_tables_ep for a q35 machine with ``-smp N`` (one socket, N cores)."""
    if vcpus > 0xFF:
        raise NotImplementedError(
            "more than 255 cores per socket needs the SMBIOS 3.0 entry point"
        )
    out = [
        _record(
            1,
            0x100,
            struct.pack("<BBBB16sBBB", 1, 2, 3, 0, bytes(16), 0x06, 0, 0),
            (QEMU_MANUFACTURER, Q35_DESCRIPTION, machine),
        ),
        _record(
            3,
            0x300,
            struct.pack(
                "<BBBBBBBBBIBBBBB", 1, 0x01, 2, 0, 0, 3, 3, 3, 2, 0, 0, 0, 0, 0, 0
            ),
            (QEMU_MANUFACTURER, machine),
        ),
        _record(
            4,
            0x400,
            struct.pack(
                "<BBBBIIBBHHHBBHHHBBBBBBHH",
                1,
                0x03,
                0xFE,
                2,
                cpuid_1_eax,
                cpuid_1_edx,
                3,
                0,
                0,
                2000,
                2000,
                0x41,
                0x01,
                0xFFFF,
                0xFFFF,
                0xFFFF,
                0,
                0,
                0,
                vcpus,
                vcpus,
                vcpus,
                0x02,
                0x01,
            ),
            ("CPU 0", QEMU_MANUFACTURER, machine),
        ),
    ]

    dimms = -(-ram_bytes // memory_device_size)
    size_kb = -(-ram_bytes // KIB)
    max_capacity, ext_capacity = (
        (size_kb, 0) if size_kb < 0x8000_0000 else (0x8000_0000, ram_bytes)
    )
    out.append(
        _record(
            16,
            0x1000,
            struct.pack(
                "<BBBIHHQ", 0x01, 0x03, 0x06, max_capacity, 0xFFFE, dimms, ext_capacity
            ),
        )
    )
    for i in range(dimms):
        size = (
            memory_device_size
            if i < dimms - 1
            else (ram_bytes - 1) % memory_device_size + 1
        )
        size_mb = -(-size // MIB)
        std, ext = (size_mb, 0) if size_mb < 0x7FFF else (0x7FFF, size_mb)
        out.append(
            _record(
                17,
                0x1100 + i,
                struct.pack(
                    "<HHHHHBBBBBHHBBBBBIHHHH",
                    0x1000,
                    0xFFFE,
                    0xFFFF,
                    0xFFFF,
                    std,
                    0x09,
                    0,
                    1,
                    0,
                    0x07,
                    0x02,
                    0,
                    2,
                    0,
                    0,
                    0,
                    0,
                    ext,
                    0,
                    0,
                    0,
                    0,
                ),
                (f"DIMM {i}", QEMU_MANUFACTURER),
            )
        )
    offset = max(dimms - (0x1300 - 0x1100), 0)
    for i, (start, length) in enumerate(e820_ram):
        end = start + length - 1
        if start // KIB < 0xFFFF_FFFF and end // KIB < 0xFFFF_FFFF:
            fmt = struct.pack("<IIHBQQ", start // KIB, end // KIB, 0x1000, 1, 0, 0)
        else:
            fmt = struct.pack(
                "<IIHBQQ", 0xFFFF_FFFF, 0xFFFF_FFFF, 0x1000, 1, start, end
            )
        out.append(_record(19, 0x1300 + offset + i, fmt))
    out.append(_record(32, 0x2000, bytes(7)))
    out.append(_record(127, 0x7F00, b""))
    return b"".join(out)


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
