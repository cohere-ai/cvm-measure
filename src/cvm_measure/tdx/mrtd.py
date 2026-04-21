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

"""MRTD computation from an OVMF firmware binary.

Simulates the TDX hardware's TD-build process to produce the 48-byte MRTD:

  1. Parse the OVMF binary's embedded GUID table to locate TDX metadata.
  2. Extract material guest physical regions (BFV, CFV, TDHOB, TempMem).
  3. Construct the TD Handover Block (TDHOB) based on the RAM topology.
  4. For every 4 KiB page in each region:
       TDH.MEM.PAGE.ADD  -> extend SHA-384 with 128-byte header
     If the page data is measured (ExtendMR attribute):
       For every 256-byte chunk:
         TDH.MR.EXTEND    -> extend SHA-384 with header + 256 bytes of data
  5. Finalize the SHA-384 digest to produce the 48-byte MRTD.

Reference: Intel TDX Module Base Architecture Spec, section 12.2.1.
"""

from __future__ import annotations

import hashlib
import io
import struct
import uuid
from dataclasses import dataclass, field

PAGE_SIZE = 4096
MR_EXTEND_CHUNK_SIZE = 256
EXTENSION_BUFFER_SIZE = 128

GIB = 0x4000_0000
MIB = 0x10_0000
MMIO_HOLE_START = 3 * GIB
MMIO_HOLE_END = 4 * GIB

TDX_SECTION_BFV = 0
TDX_SECTION_CFV = 1
TDX_SECTION_TDHOB = 2
TDX_SECTION_TEMPMEM = 3

TDX_METADATA_ATTR_EXTEND_MR = 0x0000_0001
TDX_METADATA_VERSION = 1
TDX_METADATA_MAGIC = 0x46564454  # 'T','D','V','F' in LE

FW_GUID_TABLE_END_OFFSET = 0x20
FW_GUID_ENTRY_SIZE = 18
FW_GUID_TABLE_FOOTER = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d")
TDX_METADATA_OFFSET_GUID = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2")
TDX_METADATA_GUID = uuid.UUID("e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae")

EFI_HOB_TYPE_HANDOFF = 1
EFI_HOB_TYPE_RESOURCE_DESCRIPTOR = 3
EFI_HOB_TYPE_END_OF_HOB_LIST = 0xFFFF
EFI_HOB_HANDOFF_TABLE_VERSION = 9
BOOT_WITH_FULL_CONFIGURATION = 0
EFI_RESOURCE_SYSTEM_MEMORY = 0
EFI_RESOURCE_MEMORY_UNACCEPTED = 7
EFI_RESOURCE_ATTR_PRESENT = 1
EFI_RESOURCE_ATTR_INITIALIZED = 2
EFI_RESOURCE_ATTR_TESTED = 4
EFI_RESOURCE_ATTR_NEEDS_EARLY_ACCEPT = 0x1000_0000
TDHOB_BASE_ATTRIBUTES = (
    EFI_RESOURCE_ATTR_PRESENT
    | EFI_RESOURCE_ATTR_INITIALIZED
    | EFI_RESOURCE_ATTR_TESTED
)

SIZEOF_HOB_GENERIC_HEADER = 8
SIZEOF_HOB_HANDOFF_INFO = 56
SIZEOF_HOB_RESOURCE_DESCRIPTOR = 48


# -- EFI GUID binary helpers --------------------------------------------------


def _uuid_to_efi_bytes(u: uuid.UUID) -> bytes:
    """Convert a Python UUID to EFI mixed-endian GUID bytes."""
    b = u.bytes
    return struct.pack("<IHH", *struct.unpack(">IHH", b[:8])) + b[8:]


def _efi_bytes_to_uuid(data: bytes) -> uuid.UUID:
    """Convert EFI mixed-endian GUID bytes to a Python UUID."""
    d1, d2, d3 = struct.unpack_from("<IHH", data, 0)
    rest = data[8:16]
    be = struct.pack(">IHH", d1, d2, d3) + rest
    return uuid.UUID(bytes=be)


# -- OVMF GUID table parsing --------------------------------------------------


def _parse_fw_guid_table(firmware: bytes) -> dict[uuid.UUID, bytes]:
    """Parse the GUID table embedded at the end of the OVMF firmware binary.

    Walks backwards from the firmware footer, reading size+GUID entries
    until the table is exhausted. Returns a dict of GUID -> raw block bytes.
    """
    min_size = FW_GUID_TABLE_END_OFFSET + FW_GUID_ENTRY_SIZE
    if len(firmware) < min_size:
        raise ValueError(f"Firmware too small ({len(firmware)} < {min_size})")

    footer_offset = len(firmware) - FW_GUID_TABLE_END_OFFSET - FW_GUID_ENTRY_SIZE
    entry_size = struct.unpack_from("<H", firmware, footer_offset)[0]
    entry_guid = _efi_bytes_to_uuid(firmware[footer_offset + 2 : footer_offset + 18])

    if entry_guid != FW_GUID_TABLE_FOOTER:
        raise ValueError(f"Missing GUID table footer (got {entry_guid})")
    if entry_size < FW_GUID_ENTRY_SIZE:
        raise ValueError(f"Invalid GUID table footer size: {entry_size}")

    table_end = len(firmware) - FW_GUID_TABLE_END_OFFSET - FW_GUID_ENTRY_SIZE
    table_contents_len = entry_size - FW_GUID_ENTRY_SIZE
    table_start = table_end - table_contents_len
    table = firmware[table_start:table_end]

    result: dict[uuid.UUID, bytes] = {}
    remaining = len(table)
    while remaining > 0:
        if remaining < FW_GUID_ENTRY_SIZE:
            raise ValueError("Corrupted GUID table")
        ent_off = remaining - FW_GUID_ENTRY_SIZE
        ent_size = struct.unpack_from("<H", table, ent_off)[0]
        ent_guid = _efi_bytes_to_uuid(table[ent_off + 2 : ent_off + 18])
        if ent_size < FW_GUID_ENTRY_SIZE or ent_size > remaining:
            raise ValueError(f"Corrupted GUID table entry: size={ent_size}")
        block_start = remaining - ent_size
        result[ent_guid] = table[block_start : block_start + ent_size]
        remaining -= ent_size
    return result


# -- TDX metadata parsing -----------------------------------------------------


@dataclass
class TDXMetadataSection:
    """One firmware region described in the OVMF TDX metadata table."""

    data_offset: int  # offset into firmware binary
    data_size: int
    memory_base: int  # guest physical address
    memory_size: int
    section_type: int  # BFV, CFV, TDHOB, or TempMem
    attributes: int


@dataclass
class TDXMetadata:
    """Parsed TDX metadata from the OVMF GUID table."""

    version: int
    sections: list[TDXMetadataSection]


def _parse_tdx_metadata(firmware: bytes) -> TDXMetadata:
    """Locate and parse the TDX metadata descriptor from the firmware.

    Follows: GUID table → offset entry → metadata GUID → descriptor header
    → array of section descriptors (BFV, CFV, TDHOB, TempMem).
    """
    guid_blocks = _parse_fw_guid_table(firmware)
    offset_block = guid_blocks.get(TDX_METADATA_OFFSET_GUID)
    if offset_block is None:
        raise ValueError("TDX metadata offset GUID not found")

    metadata_offset = struct.unpack_from("<I", offset_block, 0)[0]
    fw_len = len(firmware)

    if metadata_offset < 16 or metadata_offset > fw_len - 16:
        raise ValueError(f"Invalid TDX metadata offset: 0x{metadata_offset:X}")

    guid_pos = fw_len - metadata_offset - 16
    found_guid = _efi_bytes_to_uuid(firmware[guid_pos : guid_pos + 16])
    if found_guid != TDX_METADATA_GUID:
        raise ValueError(f"TDX metadata GUID mismatch: got {found_guid}")

    desc_pos = guid_pos + 16
    signature, length, version, section_count = struct.unpack_from(
        "<IIII", firmware, desc_pos
    )

    if signature != TDX_METADATA_MAGIC:
        raise ValueError(f"Bad TDX metadata signature: 0x{signature:08X}")
    if version != TDX_METADATA_VERSION:
        raise ValueError(f"Unsupported TDX metadata version: {version}")

    sections = []
    sec_pos = desc_pos + 16
    for _ in range(section_count):
        do, ds, mb, ms, st, attr = struct.unpack_from("<IIQQII", firmware, sec_pos)
        sections.append(TDXMetadataSection(do, ds, mb, ms, st, attr))
        sec_pos += 32

    return TDXMetadata(version=version, sections=sections)


# -- Guest physical region types -----------------------------------------------


@dataclass
class GuestPhysicalRegion:
    """A contiguous range of guest physical address space."""

    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + self.length

    def intersect(self, other: GuestPhysicalRegion) -> GuestPhysicalRegion:
        if self.start >= other.end or other.start >= self.end:
            return GuestPhysicalRegion(0, 0)
        s = max(self.start, other.start)
        e = min(self.end, other.end)
        return GuestPhysicalRegion(s, e - s) if e > s else GuestPhysicalRegion(0, 0)


@dataclass
class MaterialRegion:
    """A firmware region with its data, ready for MRTD measurement."""

    gpr: GuestPhysicalRegion
    host_buffer: bytes  # page content to measure (or empty if unmeasured)
    tdvf_attributes: int


# -- TDHOB construction --------------------------------------------------------


def _write_hob_header(buf: io.BytesIO, hob_type: int, hob_length: int) -> None:
    """Write a generic EFI HOB header (type, length, reserved)."""
    buf.write(struct.pack("<HHI", hob_type, hob_length, 0))


def _write_handoff_info(buf: io.BytesIO, end_of_hob_list_addr: int) -> None:
    """Write the EFI_HOB_HANDOFF_INFO_TABLE at the start of the HOB list."""
    _write_hob_header(buf, EFI_HOB_TYPE_HANDOFF, SIZEOF_HOB_HANDOFF_INFO)
    buf.write(struct.pack("<II", EFI_HOB_HANDOFF_TABLE_VERSION, BOOT_WITH_FULL_CONFIGURATION))
    buf.write(struct.pack("<QQQQQ", 0, 0, 0, 0, end_of_hob_list_addr))


def _write_resource_descriptor(
    buf: io.BytesIO, resource_type: int, attributes: int, gpr: GuestPhysicalRegion
) -> None:
    """Write one EFI_HOB_RESOURCE_DESCRIPTOR for a memory region."""
    _write_hob_header(buf, EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, SIZEOF_HOB_RESOURCE_DESCRIPTOR)
    buf.write(b"\x00" * 16)
    buf.write(struct.pack("<II", resource_type, attributes))
    buf.write(struct.pack("<QQ", gpr.start, gpr.length))


def _write_end_of_hob_list(buf: io.BytesIO) -> None:
    """Write the end-of-list sentinel HOB."""
    _write_hob_header(buf, EFI_HOB_TYPE_END_OF_HOB_LIST, SIZEOF_HOB_GENERIC_HEADER)


def _unaccepted_mem_ranges(
    private_resources: list[GuestPhysicalRegion],
    ram_resources: list[GuestPhysicalRegion],
) -> list[GuestPhysicalRegion]:
    """Compute RAM ranges not covered by private firmware regions.

    Sweeps through RAM banks and subtracts any overlap with private
    (firmware-owned) regions, returning the leftover gaps as unaccepted memory.
    """
    sorted_private = sorted(private_resources, key=lambda g: g.start)
    sorted_ram = sorted(ram_resources, key=lambda g: g.start)
    unaccepted: list[GuestPhysicalRegion] = []
    priv_idx = 0

    for ram in sorted_ram:
        if ram.length == 0:
            continue
        cur_start = ram.start
        cur_end = ram.end

        while priv_idx < len(sorted_private):
            priv = sorted_private[priv_idx]
            if priv.length == 0:
                priv_idx += 1
                continue
            if priv.end <= cur_start:
                priv_idx += 1
                continue
            if priv.start >= cur_end:
                break
            cur_gpr = GuestPhysicalRegion(cur_start, cur_end - cur_start)
            intersection = cur_gpr.intersect(priv)
            if intersection.start > cur_start:
                unaccepted.append(GuestPhysicalRegion(cur_start, intersection.start - cur_start))
            cur_start = intersection.end
            if cur_start >= cur_end:
                break

        if cur_start < cur_end:
            unaccepted.append(GuestPhysicalRegion(cur_start, cur_end - cur_start))

    return unaccepted


def _build_tdhob(
    gpr: GuestPhysicalRegion,
    private_resources: list[GuestPhysicalRegion],
    unaccepted_resources: list[GuestPhysicalRegion],
    disable_early_accept: bool,
) -> bytes:
    """Build the TD Handover Block (TDHOB) binary from memory layout.

    The TDHOB is an EFI HOB list that the VMM passes to the TD guest firmware
    describing which memory is pre-accepted vs. unaccepted. Its content
    affects MRTD because it occupies a measured region.
    """
    num_descriptors = len(private_resources) + len(unaccepted_resources)
    hob_size = SIZEOF_HOB_RESOURCE_DESCRIPTOR * num_descriptors
    end_of_hob_offset = SIZEOF_HOB_HANDOFF_INFO + hob_size

    buf = io.BytesIO()
    _write_handoff_info(buf, gpr.start + end_of_hob_offset)

    for priv_gpr in private_resources:
        _write_resource_descriptor(buf, EFI_RESOURCE_SYSTEM_MEMORY, TDHOB_BASE_ATTRIBUTES, priv_gpr)

    for unacc_gpr in unaccepted_resources:
        attrs = TDHOB_BASE_ATTRIBUTES
        if unacc_gpr.end <= 4 * GIB or not disable_early_accept:
            attrs |= EFI_RESOURCE_ATTR_NEEDS_EARLY_ACCEPT
        _write_resource_descriptor(buf, EFI_RESOURCE_MEMORY_UNACCEPTED, attrs, unacc_gpr)

    _write_end_of_hob_list(buf)

    data = buf.getvalue()
    if len(data) > gpr.length:
        raise ValueError(f"TDHOB overflows region: {len(data)} > {gpr.length}")
    return data.ljust(gpr.length, b"\x00")


# -- RAM region computation ----------------------------------------------------


def ram_regions(
    ram_gib: int,
    numa_nodes: int = 1,
    max_per_node_gib: int | None = None,
) -> list[GuestPhysicalRegion]:
    """Compute guest physical memory regions for given RAM topology.

    Args:
        ram_gib: Total guest RAM in GiB.
        numa_nodes: Number of NUMA nodes.
        max_per_node_gib: Maximum GiB per NUMA node. Defaults to ram_gib.
    """
    if ram_gib < 4:
        raise ValueError(f"ram_gib must be >= 4 (got {ram_gib}); TDX VMs require RAM above the 3 GiB MMIO hole")
    if max_per_node_gib is None:
        max_per_node_gib = ram_gib

    regions = [
        GuestPhysicalRegion(0, MMIO_HOLE_START),
        GuestPhysicalRegion(4 * GIB - 2 * MIB, 2 * MIB),
    ]
    start = MMIO_HOLE_END
    taken = MMIO_HOLE_START
    remaining = ram_gib * GIB - taken
    max_node = max_per_node_gib * GIB
    for _node in range(numa_nodes):
        length = max_node - taken
        if remaining < length:
            length = remaining
        if length > 0:
            regions.append(GuestPhysicalRegion(start, length))
            start += length
            remaining -= length
        taken = 0
    return regions


# -- Region extraction from firmware -------------------------------------------


@dataclass
class LaunchOptions:
    """Controls which regions contribute to the MRTD digest."""

    measure_all_regions: bool = False
    disable_unaccepted_memory: bool = False
    guest_ram_banks: list[GuestPhysicalRegion] = field(default_factory=list)


def _extract_material_regions(
    firmware: bytes, opts: LaunchOptions
) -> list[MaterialRegion]:
    """Extract measurable regions from firmware using TDX metadata.

    Parses section descriptors, slices out BFV/CFV data from the firmware
    binary, builds the TDHOB from RAM topology, and returns all regions
    in the order the TDX module would measure them.
    """
    metadata = _parse_tdx_metadata(firmware)
    regions: list[MaterialRegion] = []
    private_resources: list[GuestPhysicalRegion] = []
    tdhob_index: int | None = None

    for i, sec in enumerate(metadata.sections):
        gpr = GuestPhysicalRegion(sec.memory_base, sec.memory_size)
        attrs = sec.attributes
        if opts.measure_all_regions:
            attrs |= TDX_METADATA_ATTR_EXTEND_MR
        private_resources.append(gpr)

        if sec.section_type in (TDX_SECTION_BFV, TDX_SECTION_CFV):
            data = firmware[sec.data_offset : sec.data_offset + sec.data_size]
            regions.append(MaterialRegion(gpr, data, attrs))
        elif sec.section_type == TDX_SECTION_TDHOB:
            if tdhob_index is not None:
                raise ValueError("Multiple TDHOB sections found")
            tdhob_index = len(regions)
            buf = b"\x00" * sec.memory_size if opts.measure_all_regions else b""
            regions.append(MaterialRegion(gpr, buf, attrs))
        elif sec.section_type == TDX_SECTION_TEMPMEM:
            buf = b"\x00" * sec.memory_size if opts.measure_all_regions else b""
            regions.append(MaterialRegion(gpr, buf, attrs))
        else:
            raise ValueError(f"Unknown TDX metadata section type: {sec.section_type}")

    if tdhob_index is None:
        raise ValueError("No TDHOB section in TDX metadata")

    ram_banks = opts.guest_ram_banks
    unaccepted = _unaccepted_mem_ranges(private_resources, ram_banks) if ram_banks else []

    disable_early = opts.disable_unaccepted_memory or not opts.measure_all_regions
    tdhob_gpr = regions[tdhob_index].gpr
    tdhob_buf = _build_tdhob(tdhob_gpr, private_resources, unaccepted, disable_early)
    regions[tdhob_index] = MaterialRegion(tdhob_gpr, tdhob_buf, regions[tdhob_index].tdvf_attributes)

    return regions


# -- TDX measurement simulation -----------------------------------------------


class TDXMeasurement:
    """Simulates the TDX module's MRTD build-time measurement."""

    def __init__(self, *, measure_all_regions: bool = False):
        self._digest = hashlib.sha384()
        self.measure_all_regions = measure_all_regions

    def _extend(self, data: bytes) -> None:
        """Feed data into the running SHA-384 digest."""
        self._digest.update(data)

    def page_add(self, gpa: int) -> None:
        """Simulate TDH.MEM.PAGE.ADD: extend with a 128-byte header."""
        buf = bytearray(EXTENSION_BUFFER_SIZE)
        buf[0:12] = b"MEM.PAGE.ADD"
        struct.pack_into("<Q", buf, 16, gpa)
        self._extend(bytes(buf))

    def mr_extend(self, gpa: int, chunk: bytes) -> None:
        """Simulate TDH.MR.EXTEND: extend with header + 256 bytes of content.

        Each call feeds three blocks into the hash: a 128-byte header,
        then the 256-byte chunk split into two 128-byte halves.
        """
        assert len(chunk) == MR_EXTEND_CHUNK_SIZE
        buf = bytearray(EXTENSION_BUFFER_SIZE)
        buf[0:9] = b"MR.EXTEND"
        struct.pack_into("<Q", buf, 16, gpa)
        self._extend(bytes(buf))
        self._extend(chunk[:EXTENSION_BUFFER_SIZE])
        self._extend(chunk[EXTENSION_BUFFER_SIZE:])

    def init_memory_region(self, region: MaterialRegion) -> None:
        """Measure all pages in a region.

        Walks the region in 256-byte steps. At each 4 KiB page boundary,
        calls page_add. If the region has ExtendMR set, also calls
        mr_extend for each 256-byte chunk to measure the actual content.
        """
        gpr = region.gpr
        data = region.host_buffer
        measure_bytes = bool(region.tdvf_attributes & TDX_METADATA_ATTR_EXTEND_MR)
        if self.measure_all_regions:
            measure_bytes = True

        if measure_bytes and gpr.length != len(data):
            raise ValueError(f"Region length {gpr.length} != data length {len(data)}")
        if gpr.start % PAGE_SIZE != 0:
            raise ValueError(f"Region start 0x{gpr.start:X} not page-aligned")
        if gpr.length % PAGE_SIZE != 0:
            raise ValueError(f"Region length 0x{gpr.length:X} not page-aligned")

        gpa = gpr.start
        for i in range(0, gpr.length, MR_EXTEND_CHUNK_SIZE):
            if i % PAGE_SIZE == 0:
                self.page_add(gpa + i)
            if measure_bytes:
                self.mr_extend(gpa + i, data[i : i + MR_EXTEND_CHUNK_SIZE])

    def finalize(self) -> bytes:
        """Return the final 48-byte MRTD digest."""
        return self._digest.digest()


# -- Public API ----------------------------------------------------------------


def compute_mrtd(
    firmware: bytes,
    ram_gib: int | None = None,
    numa_nodes: int = 1,
    max_per_node_gib: int | None = None,
) -> bytes:
    """Compute the 48-byte MRTD for a given OVMF firmware binary.

    Args:
        firmware: Raw OVMF firmware bytes.
        ram_gib: Total guest RAM in GiB. If None, no RAM topology is applied.
        numa_nodes: Number of NUMA nodes (default 1).
        max_per_node_gib: Max GiB per NUMA node (default same as ram_gib).
    """
    banks: list[GuestPhysicalRegion] = []
    if ram_gib is not None:
        banks = ram_regions(ram_gib, numa_nodes, max_per_node_gib)

    opts = LaunchOptions(measure_all_regions=False, guest_ram_banks=banks)
    regions = _extract_material_regions(firmware, opts)
    m = TDXMeasurement(measure_all_regions=opts.measure_all_regions)
    for region in regions:
        m.init_memory_region(region)
    return m.finalize()
