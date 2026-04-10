"""Unit tests: baseline loading and structure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cvm_measure.tdx.baseline import Baseline, BaselineEvent, load, save


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


class TestBaselineRoundTrip:

    def test_save_and_load(self, tmp_path: Path) -> None:
        original = Baseline(
            machine_type="test-machine",
            firmware_sha384="aa" * 48,
            secureboot_enabled=True,
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
        assert len(loaded.events) == 1
        assert loaded.events[0].label == "test"
        assert loaded.events[0].digest == "bb" * 48

    def test_save_creates_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / "deep" / "nested" / "baseline.json"
        baseline = Baseline(machine_type="test")
        save(baseline, path)
        assert path.exists()
