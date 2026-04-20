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

"""Unit tests: public API surface."""

from __future__ import annotations

from pathlib import Path

from cvm_measure.tdx import compute_all_registers, compute_mrtd, load_baseline

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestPublicAPI:

    def test_load_baseline(self) -> None:
        path = FIXTURES_DIR / "baselines" / "a3-highgpu-1g.json"
        if not path.exists():
            return
        baseline = load_baseline(path)
        assert baseline.machine_type == "a3-highgpu-1g"
        assert len(baseline.events) == 14

    def test_load_baseline_str_path(self) -> None:
        path = FIXTURES_DIR / "baselines" / "a3-highgpu-1g.json"
        if not path.exists():
            return
        baseline = load_baseline(str(path))
        assert baseline.machine_type == "a3-highgpu-1g"

    def test_compute_mrtd_import(self) -> None:
        """Verify compute_mrtd is importable from the public API."""
        assert callable(compute_mrtd)

    def test_compute_all_registers_import(self) -> None:
        """Verify compute_all_registers is importable from the public API."""
        assert callable(compute_all_registers)
