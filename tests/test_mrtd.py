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

"""Unit tests: MRTD computation helpers."""

from __future__ import annotations

import uuid

import pytest

from cvm_measure.tdx.mrtd import (
    GIB,
    MIB,
    MMIO_HOLE_END,
    MMIO_HOLE_START,
    PAGE_SIZE,
    TDX_METADATA_ATTR_EXTEND_MR,
    GuestPhysicalRegion,
    LaunchOptions,
    MaterialRegion,
    TDXMeasurement,
    _efi_bytes_to_uuid,
    _extract_material_regions,
    _parse_fw_guid_table,
    _parse_tdx_metadata,
    _uuid_to_efi_bytes,
    compute_mrtd,
    compute_mrtd_hex,
    ram_regions,
)


class TestRamRegions:

    def test_single_numa(self) -> None:
        regions = ram_regions(ram_gib=234)
        assert len(regions) == 3
        assert regions[0].start == 0
        assert regions[0].length == MMIO_HOLE_START
        assert regions[1].start == 4 * GIB - 2 * MIB
        assert regions[1].length == 2 * MIB
        assert regions[2].start == MMIO_HOLE_END
        # Total includes the 2 MiB region in the MMIO hole
        total = sum(r.length for r in regions)
        assert total == 234 * GIB + 2 * MIB

    def test_multi_numa(self) -> None:
        regions = ram_regions(ram_gib=704, numa_nodes=4, max_per_node_gib=176)
        assert len(regions) >= 3
        total = sum(r.length for r in regions)
        assert total == 704 * GIB + 2 * MIB

    def test_default_max_per_node(self) -> None:
        r1 = ram_regions(ram_gib=234)
        r2 = ram_regions(ram_gib=234, numa_nodes=1, max_per_node_gib=234)
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2):
            assert a.start == b.start
            assert a.length == b.length


class TestGuestPhysicalRegion:

    def test_end(self) -> None:
        gpr = GuestPhysicalRegion(0x1000, 0x2000)
        assert gpr.end == 0x3000

    def test_intersect_overlap(self) -> None:
        a = GuestPhysicalRegion(0, 0x2000)
        b = GuestPhysicalRegion(0x1000, 0x2000)
        result = a.intersect(b)
        assert result.start == 0x1000
        assert result.length == 0x1000

    def test_intersect_no_overlap(self) -> None:
        a = GuestPhysicalRegion(0, 0x1000)
        b = GuestPhysicalRegion(0x2000, 0x1000)
        result = a.intersect(b)
        assert result.length == 0

    def test_intersect_adjacent(self) -> None:
        a = GuestPhysicalRegion(0, 0x1000)
        b = GuestPhysicalRegion(0x1000, 0x1000)
        result = a.intersect(b)
        assert result.length == 0


class TestEFIGuidConversion:

    def test_roundtrip(self) -> None:
        u = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d")
        assert _efi_bytes_to_uuid(_uuid_to_efi_bytes(u)) == u

    def test_known_guid(self) -> None:
        u = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2")
        efi = _uuid_to_efi_bytes(u)
        assert len(efi) == 16
        assert _efi_bytes_to_uuid(efi) == u


class TestTDXMeasurementUnit:

    def test_page_add_extends_digest(self) -> None:
        m = TDXMeasurement()
        before = m._digest.copy().digest()
        m.page_add(0x1000)
        after = m.finalize()
        assert before != after

    def test_mr_extend_with_chunk(self) -> None:
        m = TDXMeasurement()
        chunk = bytes(256)
        m.mr_extend(0x1000, chunk)
        result = m.finalize()
        assert len(result) == 48

    def test_init_memory_region_unmeasured(self) -> None:
        m = TDXMeasurement()
        gpr = GuestPhysicalRegion(0, PAGE_SIZE)
        region = MaterialRegion(gpr, b"", 0)
        m.init_memory_region(region)
        result = m.finalize()
        assert len(result) == 48

    def test_init_memory_region_measured(self) -> None:
        m = TDXMeasurement()
        data = b"\xAB" * PAGE_SIZE
        gpr = GuestPhysicalRegion(0, PAGE_SIZE)
        region = MaterialRegion(gpr, data, TDX_METADATA_ATTR_EXTEND_MR)
        m.init_memory_region(region)
        result = m.finalize()
        assert len(result) == 48

    def test_region_length_mismatch_raises(self) -> None:
        m = TDXMeasurement()
        gpr = GuestPhysicalRegion(0, PAGE_SIZE)
        region = MaterialRegion(gpr, b"\x00" * 100, TDX_METADATA_ATTR_EXTEND_MR)
        with pytest.raises(ValueError, match="data length"):
            m.init_memory_region(region)

    def test_unaligned_start_raises(self) -> None:
        m = TDXMeasurement()
        gpr = GuestPhysicalRegion(0x100, PAGE_SIZE)
        region = MaterialRegion(gpr, b"", 0)
        with pytest.raises(ValueError, match="page-aligned"):
            m.init_memory_region(region)

    def test_unaligned_length_raises(self) -> None:
        m = TDXMeasurement()
        gpr = GuestPhysicalRegion(0, 0x100)
        region = MaterialRegion(gpr, b"", 0)
        with pytest.raises(ValueError, match="page-aligned"):
            m.init_memory_region(region)


class TestFirmwareParsing:
    """Integration tests using real OVMF firmware fixture."""

    def test_parse_guid_table(self, firmware_a3: bytes) -> None:
        table = _parse_fw_guid_table(firmware_a3)
        assert len(table) > 0
        for guid in table:
            assert isinstance(guid, uuid.UUID)

    def test_parse_tdx_metadata(self, firmware_a3: bytes) -> None:
        metadata = _parse_tdx_metadata(firmware_a3)
        assert metadata.version == 1
        assert len(metadata.sections) >= 4
        section_types = {s.section_type for s in metadata.sections}
        assert 0 in section_types  # BFV
        assert 1 in section_types  # CFV
        assert 2 in section_types  # TDHOB
        assert 3 in section_types  # TempMem

    def test_extract_material_regions(self, firmware_a3: bytes) -> None:
        banks = ram_regions(ram_gib=234)
        opts = LaunchOptions(measure_all_regions=False, guest_ram_banks=banks)
        regions = _extract_material_regions(firmware_a3, opts)
        assert len(regions) >= 4

    def test_compute_mrtd_returns_48_bytes(self, firmware_a3: bytes) -> None:
        result = compute_mrtd(firmware_a3)
        assert len(result) == 48

    def test_compute_mrtd_with_ram(self, firmware_a3: bytes) -> None:
        result = compute_mrtd(firmware_a3, ram_gib=234)
        assert len(result) == 48

    def test_compute_mrtd_hex_matches_golden(self, firmware_a3: bytes, golden_a3) -> None:
        result = compute_mrtd_hex(firmware_a3, ram_gib=234)
        assert len(result) == 96
        assert result == golden_a3.mrtd

    def test_compute_mrtd_deterministic(self, firmware_a3: bytes) -> None:
        r1 = compute_mrtd(firmware_a3, ram_gib=234)
        r2 = compute_mrtd(firmware_a3, ram_gib=234)
        assert r1 == r2

    def test_mrtd_without_ram_matches_with_ram(self, firmware_a3: bytes) -> None:
        """Without measure_all_regions, TDHOB is not measured so RAM doesn't affect MRTD."""
        r_none = compute_mrtd(firmware_a3)
        r_234 = compute_mrtd(firmware_a3, ram_gib=234)
        assert r_none == r_234


class TestFirmwareValidation:

    def test_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="too small"):
            _parse_fw_guid_table(b"\x00" * 10)

    def test_missing_footer_raises(self) -> None:
        with pytest.raises(ValueError, match="footer"):
            _parse_fw_guid_table(b"\x00" * 100)
