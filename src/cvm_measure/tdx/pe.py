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

# SizeOfImage sits at this optional-header offset for both PE32 and PE32+.
_OPT_OFF_SIZE_OF_IMAGE = 56

# A section's zero tail covers uninitialized data, which in a real UKI is
# under one SectionAlignment. VirtualSize is a UINT32, so without a cap a
# hostile image could make us allocate close to 4 GiB.
MAX_VIRTUAL_PADDING_BYTES = 64 * 1024 * 1024


def _read_u16(pe_data: bytes, offset: int, what: str) -> int:
    """Read a UINT16 that has to be inside the file."""
    if offset < 0 or offset + 2 > len(pe_data):
        raise ValueError(
            f"PE image truncated: {what} at offset {offset} is past the end of "
            f"a {len(pe_data)}-byte image"
        )
    return int(struct.unpack_from("<H", pe_data, offset)[0])


def _read_u32(pe_data: bytes, offset: int, what: str) -> int:
    """Read a UINT32 that has to be inside the file."""
    if offset < 0 or offset + 4 > len(pe_data):
        raise ValueError(
            f"PE image truncated: {what} at offset {offset} is past the end of "
            f"a {len(pe_data)}-byte image"
        )
    return int(struct.unpack_from("<I", pe_data, offset)[0])


def _section_entry(pe_data: bytes, sec_table_off: int, i: int) -> int:
    """Offset of one 40-byte section-table entry, which has to be in the file."""
    so = sec_table_off + i * 40
    if so + 40 > len(pe_data):
        raise ValueError(
            f"PE section table entry {i} at offset {so} runs past the end of a "
            f"{len(pe_data)}-byte image"
        )
    return so


def _parse_pe_header(pe_data: bytes) -> tuple[int, int, int] | None:
    """Validate PE and return (coff_offset, num_sections, sec_table_offset).

    Returns None when the signatures say this is not a PE at all. A file that
    claims to be one but cannot hold the headers it declares raises instead,
    because every offset below is read out of those headers.
    """
    if len(pe_data) < 64 or pe_data[:2] != b"MZ":
        return None

    pe_offset = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if pe_offset + 4 > len(pe_data) or pe_data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    coff_offset = pe_offset + 4
    num_sections = _read_u16(pe_data, coff_offset + 2, "NumberOfSections")
    opt_hdr_size = _read_u16(pe_data, coff_offset + 16, "SizeOfOptionalHeader")
    sec_table_off = coff_offset + 20 + opt_hdr_size
    if sec_table_off > len(pe_data):
        raise ValueError(
            f"PE optional header declares {opt_hdr_size} bytes, putting the "
            f"section table at offset {sec_table_off}, past the end of a "
            f"{len(pe_data)}-byte image"
        )
    return coff_offset, num_sections, sec_table_off


def _size_of_image(pe_data: bytes, coff_offset: int) -> int | None:
    """Read SizeOfImage: how many bytes the loader maps for this image.

    Returns None when the optional header is too small or truncated to hold
    the field, in which case the caller cannot bound sections against it.
    """
    opt_hdr_size = _read_u16(pe_data, coff_offset + 16, "SizeOfOptionalHeader")
    field_end = _OPT_OFF_SIZE_OF_IMAGE + 4
    if opt_hdr_size < field_end or coff_offset + 20 + field_end > len(pe_data):
        return None
    return _read_u32(
        pe_data, coff_offset + 20 + _OPT_OFF_SIZE_OF_IMAGE, "SizeOfImage"
    )


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
    opt_hdr_size = _read_u16(pe_data, coff_offset + 16, "SizeOfOptionalHeader")
    magic = _read_u16(pe_data, opt_offset, "optional header magic")

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

    size_of_headers = _read_u32(pe_data, opt_offset + 60, "SizeOfHeaders")
    num_rva_and_sizes = _read_u32(pe_data, num_rva_off, "NumberOfRvaAndSizes")

    cert_entry_off = dd_offset + 4 * 8 if num_rva_and_sizes > 4 else None
    cert_table_size = 0
    if cert_entry_off is not None and cert_entry_off + 8 <= opt_offset + opt_hdr_size:
        cert_table_size = _read_u32(pe_data, cert_entry_off + 4, "certificate table size")
    else:
        cert_entry_off = None

    sections: list[tuple[int, int]] = []
    for i in range(num_sections):
        so = _section_entry(pe_data, sec_table_off, i)
        raw_size = _read_u32(pe_data, so + 16, "SizeOfRawData")
        raw_ptr = _read_u32(pe_data, so + 20, "PointerToRawData")
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


def pe_section_names(pe_data: bytes) -> list[str]:
    """List section names in section-table order, including any duplicates."""
    header = _parse_pe_header(pe_data)
    if header is None:
        raise ValueError("Not a valid PE file (missing MZ or PE signature)")

    _, num_sections, sec_table_off = header
    names = []
    for i in range(num_sections):
        so = _section_entry(pe_data, sec_table_off, i)
        names.append(
            pe_data[so : so + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        )
    return names


def pe_extract_section(
    pe_data: bytes,
    section_name: str,
    *,
    use_virtual_size: bool = False,
) -> bytes | None:
    """Extract a named section's data from a PE/COFF image.

    With use_virtual_size=True, returns the loaded image of the section as
    systemd-stub measures it: at most SizeOfRawData bytes from the file,
    zero-filled out to VirtualSize. A section may declare more virtual space
    than it stores on disk, and the loader zero-fills that tail rather than
    reading whatever follows in the file.

    A section with no content is reported as absent, so callers cannot
    disagree about whether an empty section is measured.

    The virtual extent must stay inside SizeOfImage, matching the bound
    systemd applies before it measures a section.
    """
    header = _parse_pe_header(pe_data)
    if header is None:
        return None

    coff_offset, num_sections, sec_table_off = header

    for i in range(num_sections):
        so = _section_entry(pe_data, sec_table_off, i)
        name = pe_data[so : so + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virt_size = _read_u32(pe_data, so + 8, "VirtualSize")
        raw_size = _read_u32(pe_data, so + 16, "SizeOfRawData")
        raw_ptr = _read_u32(pe_data, so + 20, "PointerToRawData")
        if name != section_name:
            continue
        if raw_size == 0 or raw_ptr == 0:
            return None
        if raw_ptr + raw_size > len(pe_data):
            raise ValueError(
                f"Section {section_name!r} runs past the end of the PE image: "
                f"{raw_ptr} + {raw_size} > {len(pe_data)}"
            )

        raw = pe_data[raw_ptr : raw_ptr + raw_size]
        if not use_virtual_size:
            return raw
        if virt_size == 0:
            return None

        virt_addr = _read_u32(pe_data, so + 12, "VirtualAddress")
        image_size = _size_of_image(pe_data, coff_offset)
        if image_size is not None and virt_addr + virt_size > image_size:
            raise ValueError(
                f"Section {section_name!r} does not fit in the loaded image: "
                f"VirtualAddress {virt_addr} + VirtualSize {virt_size} exceeds "
                f"SizeOfImage {image_size}"
            )
        if virt_size <= raw_size:
            return raw[:virt_size]

        padding = virt_size - raw_size
        if padding > MAX_VIRTUAL_PADDING_BYTES:
            raise ValueError(
                f"Section {section_name!r} declares a {padding} byte zero tail, "
                f"over the {MAX_VIRTUAL_PADDING_BYTES} byte limit"
            )
        return raw + bytes(padding)

    return None
