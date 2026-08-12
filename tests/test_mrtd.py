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

import hashlib
import struct
import uuid

import pytest

from cvm_measure.tdx.guid import uuid_to_efi_bytes
from cvm_measure.tdx.mrtd import (
    FW_GUID_ENTRY_SIZE,
    FW_GUID_TABLE_END_OFFSET,
    FW_GUID_TABLE_FOOTER,
    GIB,
    MIB,
    MMIO_HOLE_END,
    MMIO_HOLE_START,
    PAGE_SIZE,
    TDX_METADATA_ATTR_EXTEND_MR,
    TDX_METADATA_GUID,
    TDX_METADATA_MAGIC,
    TDX_METADATA_OFFSET_GUID,
    TDX_METADATA_VERSION,
    TDX_SECTION_BFV,
    TDX_SECTION_CFV,
    TDX_SECTION_TDHOB,
    GuestPhysicalRegion,
    LaunchOptions,
    MaterialRegion,
    TDXMeasurement,
    _extract_material_regions,
    _parse_fw_guid_table,
    _parse_tdx_metadata,
    cfv_image,
    compute_mrtd,
    ram_regions,
)

# (section_type, data_offset, data_size, memory_base, memory_size, attributes)
SyntheticSection = tuple[int, int, int, int, int, int]


def build_firmware(sections: list[SyntheticSection], size: int = 0x40000) -> bytes:
    """Build a minimal firmware image carrying a TDX metadata descriptor.

    Only the structures the parser walks are real: the trailing GUID table, the
    metadata offset entry, and the section descriptor array.
    """
    descriptor = struct.pack(
        "<IIII", TDX_METADATA_MAGIC, 16 + 32 * len(sections), TDX_METADATA_VERSION,
        len(sections),
    )
    for section_type, data_offset, data_size, mem_base, mem_size, attrs in sections:
        descriptor += struct.pack(
            "<IIQQII", data_offset, data_size, mem_base, mem_size, section_type, attrs
        )

    offset_block = (
        struct.pack("<I", 0)  # patched below, once the layout is known
        + struct.pack("<H", 4 + FW_GUID_ENTRY_SIZE)
        + uuid_to_efi_bytes(TDX_METADATA_OFFSET_GUID)
    )
    footer = struct.pack(
        "<H", len(offset_block) + FW_GUID_ENTRY_SIZE
    ) + uuid_to_efi_bytes(FW_GUID_TABLE_FOOTER)

    table = offset_block + footer
    tail = bytes(FW_GUID_TABLE_END_OFFSET)
    metadata_blob = uuid_to_efi_bytes(TDX_METADATA_GUID) + descriptor

    body_len = size - len(table) - len(tail) - len(metadata_blob)
    if body_len < 0:
        raise ValueError("synthetic firmware too small for its metadata")
    image = bytearray(bytes(body_len) + metadata_blob + table + tail)

    # The offset entry counts backwards from the end of the image to the GUID
    # that precedes the descriptor.
    guid_pos = body_len
    struct.pack_into("<I", image, guid_pos + len(metadata_blob), len(image) - guid_pos - 16)
    return bytes(image)


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

    def test_node_cap_below_total_is_rejected(self) -> None:
        """Nodes that cannot hold ram_gib must raise instead of truncating."""
        with pytest.raises(ValueError, match="cannot hold"):
            ram_regions(ram_gib=10, numa_nodes=1, max_per_node_gib=5)

    def test_node_cap_below_mmio_hole_is_rejected(self) -> None:
        """The first node absorbs the 3 GiB hole, so a smaller cap cannot fit."""
        with pytest.raises(ValueError, match="cannot hold"):
            ram_regions(ram_gib=10, numa_nodes=4, max_per_node_gib=2)

    def test_exact_capacity_is_accepted(self) -> None:
        regions = ram_regions(ram_gib=16, numa_nodes=2, max_per_node_gib=8)
        assert sum(r.length for r in regions) == 16 * GIB + 2 * MIB


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
        result = compute_mrtd(firmware_a3, ram_gib=234).hex()
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


class TestSyntheticFirmware:
    """The builder has to produce something the real parser accepts."""

    def test_round_trips_through_the_metadata_parser(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_CFV, 0, 0x1000, 0xFFE00000, 0x1000, 0),
        ])
        metadata = _parse_tdx_metadata(firmware)
        assert metadata.version == TDX_METADATA_VERSION
        assert [s.section_type for s in metadata.sections] == [TDX_SECTION_CFV]


class TestCfvImage:
    """The CFV is located from firmware metadata, not assumed to be at 0."""

    def test_a3_cfv_is_the_first_128_kib(self, firmware_a3: bytes) -> None:
        """The build this was developed against puts the CFV at offset 0."""
        assert cfv_image(firmware_a3) == firmware_a3[0:0x20000]

    def test_follows_a_relocated_cfv(self) -> None:
        firmware = bytearray(build_firmware([
            (TDX_SECTION_BFV, 0, 0x1000, 0xFFE01000, 0x1000, 1),
            (TDX_SECTION_CFV, 0x2000, 0x1000, 0xFFE00000, 0x1000, 0),
        ]))
        firmware[0x2000:0x3000] = b"\xa5" * 0x1000
        image = cfv_image(bytes(firmware))
        assert image == b"\xa5" * 0x1000
        assert hashlib.sha384(image).digest() != hashlib.sha384(bytes(0x1000)).digest()

    def test_zero_fills_to_the_mapped_size(self) -> None:
        firmware = bytearray(build_firmware([
            (TDX_SECTION_CFV, 0x2000, 0x400, 0xFFE00000, 0x1000, 0),
        ]))
        firmware[0x2000:0x2400] = b"\xa5" * 0x400
        assert cfv_image(bytes(firmware)) == b"\xa5" * 0x400 + bytes(0xC00)

    def test_rejects_firmware_without_a_cfv(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_BFV, 0, 0x1000, 0xFFE01000, 0x1000, 1),
        ])
        with pytest.raises(ValueError, match="0 CFV section"):
            cfv_image(firmware)

    def test_rejects_firmware_with_two_cfvs(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_CFV, 0, 0x1000, 0xFFE00000, 0x1000, 0),
            (TDX_SECTION_CFV, 0x1000, 0x1000, 0xFFE01000, 0x1000, 0),
        ])
        with pytest.raises(ValueError, match="2 CFV section"):
            cfv_image(firmware)

    def test_rejects_cfv_past_the_end_of_the_image(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_CFV, 0x3F000, 0x20000, 0xFFE00000, 0x20000, 0),
        ])
        with pytest.raises(ValueError, match="past the end"):
            cfv_image(firmware)

    def test_rejects_cfv_larger_than_its_memory_region(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_CFV, 0, 0x2000, 0xFFE00000, 0x1000, 0),
        ])
        with pytest.raises(ValueError, match="unusable CFV"):
            cfv_image(firmware)

    def test_hardware_log_records_the_golden_cfv_digest(
        self, ccel_data_a3: bytes, golden_a3
    ) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log

        log = parse_event_log(ccel_data_a3)
        recorded = next(
            e.digests[TPM_ALG_SHA384]
            for e in log.events_for_rtmr(0)
            if "PLATFORM_FIRMWARE" in e.event_type_name
        )
        assert recorded.hex() == golden_a3.cfv

    def test_derived_region_matches_the_hardware_cfv_digest(
        self, firmware_a3: bytes, golden_a3
    ) -> None:
        """The metadata-derived region reproduces what a real VM measured."""
        assert hashlib.sha384(cfv_image(firmware_a3)).hexdigest() == golden_a3.cfv


class TestTdhobSectionValidation:

    def test_rejects_two_tdhob_sections(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_TDHOB, 0, 0, 0x809000, 0x2000, 0),
            (TDX_SECTION_TDHOB, 0, 0, 0x80B000, 0x2000, 0),
        ])
        with pytest.raises(ValueError, match="Multiple TDHOB"):
            _extract_material_regions(firmware, LaunchOptions())

    def test_rejects_firmware_without_a_tdhob(self) -> None:
        firmware = build_firmware([
            (TDX_SECTION_CFV, 0, 0x1000, 0xFFE00000, 0x1000, 0),
        ])
        with pytest.raises(ValueError, match="No TDHOB"):
            _extract_material_regions(firmware, LaunchOptions())
