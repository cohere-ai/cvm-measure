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

"""PE/COFF Authenticode hash and section extraction.

Two concerns for TDX measurement:
  - pe_authenticode_digest: PE Authenticode SHA-384 hash for RTMR[1] boot app event
  - pe_extract_section: extract named sections from PE for RTMR[2] UKI measurements
"""

from __future__ import annotations

import hashlib
import struct


def _parse_pe_header(pe_data: bytes) -> tuple[int, int, int] | None:
    """Validate PE and return (coff_offset, num_sections, sec_table_offset).

    Returns None for invalid PE files.
    """
    if len(pe_data) < 64 or pe_data[:2] != b"MZ":
        return None

    pe_offset = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if pe_offset + 4 > len(pe_data) or pe_data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    coff_offset = pe_offset + 4
    num_sections = struct.unpack_from("<H", pe_data, coff_offset + 2)[0]
    opt_hdr_size = struct.unpack_from("<H", pe_data, coff_offset + 16)[0]
    sec_table_off = coff_offset + 20 + opt_hdr_size
    return coff_offset, num_sections, sec_table_off


def pe_authenticode_digest(pe_data: bytes, algo: str = "sha384") -> bytes:
    """Compute the Authenticode digest of a PE/COFF image.

    Follows the Microsoft PE Authenticode specification: the hash covers
    the entire file except the CheckSum field, the Certificate Table
    directory entry, and any trailing certificate data.
    """
    header = _parse_pe_header(pe_data)
    if header is None:
        raise ValueError("Not a valid PE file (missing MZ or PE signature)")

    coff_offset, num_sections, sec_table_off = header
    opt_offset = coff_offset + 20
    opt_hdr_size = struct.unpack_from("<H", pe_data, coff_offset + 16)[0]
    magic = struct.unpack_from("<H", pe_data, opt_offset)[0]

    if magic == 0x20B:  # PE32+
        checksum_off = opt_offset + 64
        num_rva_off = opt_offset + 108
        dd_offset = opt_offset + 112
    elif magic == 0x10B:  # PE32
        checksum_off = opt_offset + 64
        num_rva_off = opt_offset + 92
        dd_offset = opt_offset + 96
    else:
        raise ValueError(f"Unknown PE optional header magic: 0x{magic:04X}")

    size_of_headers = struct.unpack_from("<I", pe_data, opt_offset + 60)[0]
    num_rva_and_sizes = struct.unpack_from("<I", pe_data, num_rva_off)[0]

    cert_entry_off = dd_offset + 4 * 8 if num_rva_and_sizes > 4 else None
    cert_table_size = 0
    if cert_entry_off is not None and cert_entry_off + 8 <= opt_offset + opt_hdr_size:
        cert_table_size = struct.unpack_from("<I", pe_data, cert_entry_off + 4)[0]
    else:
        cert_entry_off = None

    sections: list[tuple[int, int]] = []
    for i in range(num_sections):
        so = sec_table_off + i * 40
        raw_size = struct.unpack_from("<I", pe_data, so + 16)[0]
        raw_ptr = struct.unpack_from("<I", pe_data, so + 20)[0]
        if raw_size > 0 and raw_ptr > 0:
            sections.append((raw_ptr, raw_size))
    sections.sort()

    h = hashlib.new(algo)

    h.update(pe_data[:checksum_off])
    after_checksum = checksum_off + 4

    if cert_entry_off is not None:
        h.update(pe_data[after_checksum:cert_entry_off])
        after_cert_entry = cert_entry_off + 8
    else:
        after_cert_entry = after_checksum

    h.update(pe_data[after_cert_entry:size_of_headers])

    sum_of_bytes = size_of_headers
    for ptr, size in sections:
        end = min(ptr + size, len(pe_data))
        h.update(pe_data[ptr:end])
        sum_of_bytes += end - ptr

    extra_end = len(pe_data) - cert_table_size
    if extra_end > sum_of_bytes:
        h.update(pe_data[sum_of_bytes:extra_end])

    return h.digest()


def pe_extract_section(
    pe_data: bytes,
    section_name: str,
    *,
    use_virtual_size: bool = False,
) -> bytes | None:
    """Extract a named section's data from a PE/COFF image.

    With use_virtual_size=True, returns only VirtualSize bytes, matching
    what systemd-stub measures for UKI section content.
    """
    header = _parse_pe_header(pe_data)
    if header is None:
        return None

    _, num_sections, sec_table_off = header

    for i in range(num_sections):
        so = sec_table_off + i * 40
        name = pe_data[so : so + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virt_size = struct.unpack_from("<I", pe_data, so + 8)[0]
        raw_size = struct.unpack_from("<I", pe_data, so + 16)[0]
        raw_ptr = struct.unpack_from("<I", pe_data, so + 20)[0]
        if name == section_name and raw_size > 0 and raw_ptr > 0:
            size = virt_size if use_virtual_size else raw_size
            return pe_data[raw_ptr : raw_ptr + size]

    return None
