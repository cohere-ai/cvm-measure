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

import pytest

from cvm_measure.tdx.pe import (
    pe_authenticode_digest,
    pe_authenticode_digest_hex,
    pe_extract_section,
    pe_list_sections,
)


class TestPEValidation:

    def test_not_pe_raises(self) -> None:
        with pytest.raises(ValueError, match="MZ"):
            pe_authenticode_digest(b"not a pe file")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="MZ"):
            pe_authenticode_digest(b"")

    def test_extract_section_not_pe_returns_none(self) -> None:
        assert pe_extract_section(b"not a pe", ".text") is None

    def test_list_sections_not_pe_returns_empty(self) -> None:
        assert pe_list_sections(b"not a pe") == []

    def test_truncated_pe_missing_signature(self) -> None:
        data = b"MZ" + b"\x00" * 62
        with pytest.raises(ValueError, match="PE signature"):
            pe_authenticode_digest(data)


class TestPEAuthenticode:
    """Integration tests using real UKI (BOOTX64.EFI) fixture."""

    def test_digest_length(self, uki_a3: bytes) -> None:
        result = pe_authenticode_digest(uki_a3)
        assert len(result) == 48

    def test_digest_hex(self, uki_a3: bytes) -> None:
        result = pe_authenticode_digest_hex(uki_a3)
        assert len(result) == 96
        int(result, 16)

    def test_digest_deterministic(self, uki_a3: bytes) -> None:
        r1 = pe_authenticode_digest(uki_a3)
        r2 = pe_authenticode_digest(uki_a3)
        assert r1 == r2

    def test_sha256_digest(self, uki_a3: bytes) -> None:
        result = pe_authenticode_digest(uki_a3, algo="sha256")
        assert len(result) == 32


class TestPESections:
    """Integration tests for PE section extraction from real UKI."""

    def test_list_sections(self, uki_a3: bytes) -> None:
        sections = pe_list_sections(uki_a3)
        assert len(sections) > 0
        names = [s["name"] for s in sections]
        assert ".linux" in names or ".text" in names

    def test_list_sections_have_metadata(self, uki_a3: bytes) -> None:
        sections = pe_list_sections(uki_a3)
        for sec in sections:
            assert "name" in sec
            assert "virtual_size" in sec
            assert "raw_size" in sec
            assert "raw_ptr" in sec

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
        sections = pe_list_sections(uki_a3)
        names = {s["name"] for s in sections}
        measured = {".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"}
        found = names & measured
        assert len(found) >= 3, f"Expected >=3 measured sections, found {found}"
