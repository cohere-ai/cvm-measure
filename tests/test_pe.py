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

"""Unit tests: PE/COFF parsing."""

from __future__ import annotations

import struct

import pytest

from cvm_measure.tdx.pe import (
    pe_authenticode_digest,
    pe_extract_section,
)

_PE_OFFSET = 0x80
_OPT_HDR_SIZE = 240


def build_pe(sections: list[tuple[str, int, int, bytes]]) -> bytes:
    """Build a minimal PE32+ image.

    Each section is (name, VirtualSize, SizeOfRawData, data), where data is
    zero-padded out to SizeOfRawData on disk.
    """
    sec_table_off = _PE_OFFSET + 4 + 20 + _OPT_HDR_SIZE
    headers_len = sec_table_off + 40 * len(sections)
    body_off = -(-headers_len // 512) * 512

    image = bytearray(body_off)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, _PE_OFFSET)
    image[_PE_OFFSET : _PE_OFFSET + 4] = b"PE\x00\x00"

    coff = _PE_OFFSET + 4
    struct.pack_into("<H", image, coff, 0x8664)
    struct.pack_into("<H", image, coff + 2, len(sections))
    struct.pack_into("<H", image, coff + 16, _OPT_HDR_SIZE)

    opt = coff + 20
    struct.pack_into("<H", image, opt, 0x20B)
    struct.pack_into("<I", image, opt + 60, body_off)
    struct.pack_into("<I", image, opt + 108, 16)

    raw_ptr = body_off
    for i, (name, virt_size, raw_size, data) in enumerate(sections):
        so = sec_table_off + i * 40
        image[so : so + len(name)] = name.encode("ascii")
        struct.pack_into("<I", image, so + 8, virt_size)
        struct.pack_into("<I", image, so + 12, 0x1000 * (i + 1))
        struct.pack_into("<I", image, so + 16, raw_size)
        struct.pack_into("<I", image, so + 20, raw_ptr)
        image.extend(data + bytes(raw_size - len(data)))
        raw_ptr += raw_size

    return bytes(image)


class TestPEValidation:

    def test_not_pe_raises(self) -> None:
        with pytest.raises(ValueError, match="MZ"):
            pe_authenticode_digest(b"not a pe file")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="MZ"):
            pe_authenticode_digest(b"")

    def test_extract_section_not_pe_returns_none(self) -> None:
        assert pe_extract_section(b"not a pe", ".text") is None

    def test_truncated_pe_missing_signature(self) -> None:
        data = b"MZ" + b"\x00" * 62
        with pytest.raises(ValueError, match="PE signature"):
            pe_authenticode_digest(data)


class TestPEAuthenticode:
    """Integration tests using real UKI (BOOTX64.EFI) fixture."""

    def test_digest_length(self, uki_a3: bytes) -> None:
        result = pe_authenticode_digest(uki_a3)
        assert len(result) == 48

    def test_digest_deterministic(self, uki_a3: bytes) -> None:
        r1 = pe_authenticode_digest(uki_a3)
        r2 = pe_authenticode_digest(uki_a3)
        assert r1 == r2

    def test_sha256_digest(self, uki_a3: bytes) -> None:
        result = pe_authenticode_digest(uki_a3, algo="sha256")
        assert len(result) == 32


class TestPESectionVirtualSize:
    """The loaded section is raw bytes plus a zero tail, never the next section."""

    def test_virtual_size_smaller_than_raw_is_truncated(self) -> None:
        pe = build_pe([(".osrel", 5, 512, b"ID=cos\n")])
        assert pe_extract_section(pe, ".osrel", use_virtual_size=True) == b"ID=co"

    def test_virtual_size_larger_than_raw_is_zero_padded(self) -> None:
        pe = build_pe([
            (".cmdline", 600, 512, b"console=ttyS0"),
            (".sbat", 16, 512, b"SECRET-NEIGHBOUR"),
        ])
        content = pe_extract_section(pe, ".cmdline", use_virtual_size=True)

        assert content is not None
        assert len(content) == 600
        assert content[:13] == b"console=ttyS0"
        assert content[13:] == bytes(600 - 13)
        assert b"SECRET-NEIGHBOUR" not in content

    def test_raw_size_ignores_virtual_size(self) -> None:
        pe = build_pe([(".cmdline", 600, 512, b"console=ttyS0")])
        content = pe_extract_section(pe, ".cmdline")
        assert content is not None
        assert len(content) == 512

    def test_zero_virtual_size_is_absent(self) -> None:
        pe = build_pe([(".ucode", 0, 512, b"")])
        assert pe_extract_section(pe, ".ucode", use_virtual_size=True) is None

    def test_section_past_end_of_image_raises(self) -> None:
        pe = build_pe([(".initrd", 512, 512, b"payload")])
        with pytest.raises(ValueError, match="runs past the end"):
            pe_extract_section(pe[:-64], ".initrd", use_virtual_size=True)


class TestPESections:
    """Integration tests for PE section extraction from real UKI."""

    def test_extract_linux_section(self, uki_a3: bytes) -> None:
        content = pe_extract_section(uki_a3, ".linux")
        if content is not None:
            assert len(content) > 0

    def test_extract_osrel_section(self, uki_a3: bytes) -> None:
        content = pe_extract_section(uki_a3, ".osrel", use_virtual_size=True)
        if content is not None:
            assert len(content) > 0
            assert b"=" in content

    def test_extract_nonexistent_section(self, uki_a3: bytes) -> None:
        result = pe_extract_section(uki_a3, ".no_such_section")
        assert result is None

    def test_uki_has_measured_sections(self, uki_a3: bytes) -> None:
        """UKIs should contain at least some of the systemd-stub measured sections."""
        measured = [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"]
        found = [s for s in measured if pe_extract_section(uki_a3, s) is not None]
        assert len(found) >= 3, f"Expected >=3 measured sections, found {found}"
