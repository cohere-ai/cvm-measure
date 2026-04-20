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

"""Unit tests: baseline loading and structure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cvm_measure.tdx.baseline import Baseline, BaselineEvent, _infer_provider, load, save


class TestBaselineLoad:

    def test_secureboot_disabled(self, baseline_a3) -> None:
        assert baseline_a3.secureboot_enabled is False

    def test_vmm_event_count(self, baseline_a3) -> None:
        assert len(baseline_a3.events) == 14

    def test_rtmr0_has_13_events(self, baseline_a3) -> None:
        events = baseline_a3.rtmr_events(0)
        assert len(events) == 13
        assert events[0].label == "TdxTable"
        assert events[1].label == "PK"
        assert events[2].label == "KEK"
        assert events[3].label == "db"
        assert events[4].label == "dbx"

    def test_rtmr1_has_1_event(self, baseline_a3) -> None:
        events = baseline_a3.rtmr_events(1)
        assert len(events) == 1
        assert events[0].label == "GPT"

    def test_rtmr2_has_0_events(self, baseline_a3) -> None:
        assert len(baseline_a3.rtmr_events(2)) == 0

    def test_firmware_sha384(self, baseline_a3) -> None:
        assert len(baseline_a3.firmware_sha384) == 96


class TestInferProvider:

    @pytest.mark.parametrize("machine_type,expected", [
        ("a3-highgpu-1g", "gcp"),
        ("n2-standard-4", "gcp"),
        ("Standard_DC4as_v5", "azure"),
        ("Standard_EC4as_v5", "azure"),
        ("m7i.metal", "aws"),
        ("c6i.xlarge", "aws"),
        ("r6i.large", "aws"),
        ("t3.micro", "aws"),
        ("t3.nano", "aws"),
        ("custom-type", "gcp"),
    ])
    def test_infer_provider(self, machine_type: str, expected: str) -> None:
        assert _infer_provider(machine_type) == expected


class TestBaselineRoundTrip:

    def test_save_and_load(self, tmp_path: Path) -> None:
        original = Baseline(
            machine_type="test-machine",
            firmware_sha384="aa" * 48,
            secureboot_enabled=True,
            provider="gcp",
            platform="tdx",
            events=[
                BaselineEvent(rtmr=0, event_type="EV_TEST", label="test", digest="bb" * 48),
            ],
        )
        path = tmp_path / "baseline.json"
        save(original, path)
        loaded = load(path)

        assert loaded.machine_type == "test-machine"
        assert loaded.firmware_sha384 == "aa" * 48
        assert loaded.secureboot_enabled is True
        assert loaded.provider == "gcp"
        assert loaded.platform == "tdx"
        assert len(loaded.events) == 1
        assert loaded.events[0].label == "test"
        assert loaded.events[0].digest == "bb" * 48

    def test_save_omits_empty_provider_platform(self, tmp_path: Path) -> None:
        baseline = Baseline(machine_type="test")
        path = tmp_path / "baseline.json"
        save(baseline, path)
        data = json.loads(path.read_text())
        assert "provider" not in data
        assert "platform" not in data

    def test_save_includes_provider_platform(self, tmp_path: Path) -> None:
        baseline = Baseline(machine_type="test", provider="azure", platform="tdx")
        path = tmp_path / "baseline.json"
        save(baseline, path)
        data = json.loads(path.read_text())
        assert data["provider"] == "azure"
        assert data["platform"] == "tdx"

    def test_load_without_provider_platform(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps({"machine_type": "legacy", "firmware_sha384": "", "secureboot_enabled": False, "events": []}))
        loaded = load(path)
        assert loaded.provider == ""
        assert loaded.platform == ""

    def test_save_creates_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "nested" / "baseline.json"
        baseline = Baseline(machine_type="test")
        save(baseline, path)
        assert path.exists()
