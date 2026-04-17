"""Unit tests: MRTD computation helpers."""

from __future__ import annotations

from cvm_measure.tdx.mrtd import (
    GIB,
    MIB,
    MMIO_HOLE_END,
    MMIO_HOLE_START,
    GuestPhysicalRegion,
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
