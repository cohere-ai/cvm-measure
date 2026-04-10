"""Pytest fixtures for cvm-measure tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@dataclass
class GoldenValues:
    """Expected register values from a known-good VM, used as test oracle."""

    machine_type: str
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str

    def as_dict(self) -> dict[str, str]:
        return {
            "mrtd": self.mrtd,
            "rtmr0": self.rtmr0,
            "rtmr1": self.rtmr1,
            "rtmr2": self.rtmr2,
            "rtmr3": self.rtmr3,
        }


def load_golden(machine_type: str) -> GoldenValues:
    path = FIXTURES_DIR / "golden" / f"{machine_type}.json"
    data = json.loads(path.read_text())
    return GoldenValues(
        machine_type=data["machine_type"],
        mrtd=data["mrtd"],
        rtmr0=data["rtmr0"],
        rtmr1=data["rtmr1"],
        rtmr2=data["rtmr2"],
        rtmr3=data["rtmr3"],
    )


@pytest.fixture
def golden_a3() -> GoldenValues:
    return load_golden("a3-highgpu-1g")


@pytest.fixture
def ccel_data_a3() -> bytes:
    path = FIXTURES_DIR / "ccel" / "a3-highgpu-1g.bin"
    if not path.exists():
        pytest.skip(f"CCEL fixture not found: {path}")
    return path.read_bytes()


@pytest.fixture
def baseline_a3():
    from cvm_measure.tdx.baseline import load

    path = FIXTURES_DIR / "baselines" / "a3-highgpu-1g.json"
    if not path.exists():
        pytest.skip(f"Baseline fixture not found: {path}")
    return load(path)
