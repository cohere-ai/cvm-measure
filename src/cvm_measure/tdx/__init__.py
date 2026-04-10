"""cvm_measure.tdx -- Intel TDX register computation.

Public API:
    compute_mrtd()           -- compute only the MRTD from firmware + RAM topology
    compute_all_registers()  -- compute MRTD + RTMR[0-3] from firmware, UKI, baseline
    load_baseline()          -- load a baseline JSON file
"""

from __future__ import annotations

from pathlib import Path

from .baseline import Baseline
from .baseline import load as _load_baseline
from .mrtd import compute_mrtd as _compute_mrtd_raw
from .registers import ComputedRegisters, compute_all


def compute_mrtd(
    firmware: bytes,
    ram_gib: int | None = None,
    numa_nodes: int = 1,
    max_per_node_gib: int | None = None,
) -> str:
    """Compute the MRTD register value from an OVMF firmware binary.

    Args:
        firmware: Raw OVMF firmware bytes.
        ram_gib: Total guest RAM in GiB. None for no RAM topology.
        numa_nodes: Number of NUMA nodes (default 1).
        max_per_node_gib: Max GiB per NUMA node (default same as ram_gib).

    Returns:
        96-character hex string (48-byte SHA-384 MRTD).
    """
    return _compute_mrtd_raw(firmware, ram_gib, numa_nodes, max_per_node_gib).hex()


def compute_all_registers(
    firmware: bytes,
    uki: bytes,
    baseline: Baseline,
    ram_gib: int,
    numa_nodes: int = 1,
    max_per_node_gib: int | None = None,
    rtmr3_hex: str | None = None,
) -> ComputedRegisters:
    """Compute all TDX registers (MRTD + RTMR[0-3]) from published inputs.

    Args:
        firmware: Raw OVMF firmware bytes.
        uki: Raw UKI (BOOTX64.EFI) bytes.
        baseline: Loaded Baseline object.
        ram_gib: Total guest RAM in GiB.
        numa_nodes: Number of NUMA nodes (default 1).
        max_per_node_gib: Max GiB per NUMA node (default same as ram_gib).
        rtmr3_hex: Pre-computed RTMR[3] hex. Defaults to all zeros.

    Returns:
        ComputedRegisters with mrtd, rtmr0, rtmr1, rtmr2, rtmr3 as hex strings.
    """
    return compute_all(
        firmware, uki, baseline, ram_gib, numa_nodes, max_per_node_gib, rtmr3_hex
    )


def load_baseline(path: str | Path) -> Baseline:
    """Load a baseline from a JSON file.

    Args:
        path: Path to baseline JSON file.

    Returns:
        Baseline object with machine_type, secureboot_enabled, and events.
    """
    return _load_baseline(Path(path))
