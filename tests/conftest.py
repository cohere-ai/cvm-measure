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

"""Pytest fixtures for cvm-measure tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@dataclass
class GoldenValues:
    """Expected values from a known-good VM, used as test oracle.

    The registers come from that VM's attestation token. The single-event
    digests come from the CCEL of the same boot, and pin the inputs a register
    is built from rather than only the folded result.
    """

    machine_type: str
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    cfv: str
    uki_image_digest: str
    kernel_image_digest: str

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
        cfv=data["cfv"],
        uki_image_digest=data["uki_image_digest"],
        kernel_image_digest=data["kernel_image_digest"],
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


@pytest.fixture
def firmware_a3() -> bytes:
    path = FIXTURES_DIR / "firmware" / "ovmf-a3-highgpu-1g.fd"
    if not path.exists():
        pytest.skip(f"Firmware fixture not found: {path}")
    return path.read_bytes()


@pytest.fixture
def uki_a3() -> bytes:
    path = FIXTURES_DIR / "uki" / "bootx64-a3-highgpu-1g.efi"
    if not path.exists():
        pytest.skip(f"UKI fixture not found: {path}")
    return path.read_bytes()


# -- Azure SEV-SNP -------------------------------------------------------------
#
# Committed, so nothing that uses them is ever skipped. See
# fixtures/eventlog/README.md for how they were captured.

AZURE_MACHINE_TYPE = "azure-snp-ncc40ads-h100-v5"


@pytest.fixture
def azure_eventlog() -> bytes:
    return (FIXTURES_DIR / "eventlog" / f"{AZURE_MACHINE_TYPE}.bin").read_bytes()


@pytest.fixture
def azure_golden() -> dict[str, str]:
    """PCR values from the same VM's signed vTPM quote."""
    data = json.loads((FIXTURES_DIR / "golden" / f"{AZURE_MACHINE_TYPE}.json").read_text())
    return {k: v for k, v in data.items() if not k.startswith("_")}


@pytest.fixture
def azure_initdata() -> Path:
    return FIXTURES_DIR / "initdata" / "coco-dummy.toml"
