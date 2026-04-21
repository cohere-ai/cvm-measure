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

"""Tests for the public API surface (cvm_measure.tdx)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cvm_measure.tdx import compute_all_registers, compute_mrtd, load_baseline
from cvm_measure.tdx.registers import ComputedRegisters

FIXTURES_DIR = Path(__file__).parent / "fixtures"
BASELINE_PATH = FIXTURES_DIR / "baselines" / "a3-highgpu-1g.json"


class TestLoadBaseline:

    def test_loads_from_path_object(self) -> None:
        if not BASELINE_PATH.exists():
            pytest.skip(f"Baseline fixture not found: {BASELINE_PATH}")
        baseline = load_baseline(BASELINE_PATH)
        assert baseline.machine_type == "a3-highgpu-1g"
        assert len(baseline.events) == 14

    def test_loads_from_str_path(self) -> None:
        if not BASELINE_PATH.exists():
            pytest.skip(f"Baseline fixture not found: {BASELINE_PATH}")
        baseline = load_baseline(str(BASELINE_PATH))
        assert baseline.machine_type == "a3-highgpu-1g"

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_baseline(tmp_path / "nonexistent.json")


class TestComputeMrtd:

    def test_returns_96_char_hex(self, firmware_a3: bytes) -> None:
        result = compute_mrtd(firmware_a3)
        assert len(result) == 96
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self, firmware_a3: bytes) -> None:
        a = compute_mrtd(firmware_a3)
        b = compute_mrtd(firmware_a3)
        assert a == b

    def test_with_ram(self, firmware_a3: bytes) -> None:
        result = compute_mrtd(firmware_a3, ram_gib=234)
        assert len(result) == 96

    def test_matches_golden(self, firmware_a3: bytes, golden_a3) -> None:
        result = compute_mrtd(firmware_a3, ram_gib=234)
        assert result == golden_a3.mrtd


class TestComputeAllRegisters:

    def test_returns_computed_registers(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3, golden_a3
    ) -> None:
        regs = compute_all_registers(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234,
        )
        assert isinstance(regs, ComputedRegisters)

    def test_all_fields_are_96_char_hex(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3
    ) -> None:
        regs = compute_all_registers(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234,
        )
        for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
            value = getattr(regs, name)
            assert len(value) == 96, f"{name} length is {len(value)}"
            assert all(c in "0123456789abcdef" for c in value), f"{name} is not hex"

    def test_matches_golden(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3, golden_a3
    ) -> None:
        regs = compute_all_registers(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234,
        )
        assert regs.mrtd == golden_a3.mrtd
        assert regs.rtmr0 == golden_a3.rtmr0
        assert regs.rtmr1 == golden_a3.rtmr1
        assert regs.rtmr2 == golden_a3.rtmr2

    def test_as_dict_keys(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3
    ) -> None:
        regs = compute_all_registers(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234,
        )
        d = regs.as_dict()
        assert set(d.keys()) == {"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}

    def test_custom_rtmr3(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3
    ) -> None:
        custom = "aa" * 48
        regs = compute_all_registers(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234, rtmr3_hex=custom,
        )
        assert regs.rtmr3 == custom
