"""Unit tests: CLI argument parsing and basic flows."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cvm_measure.cli import main


class TestCLIHelp:

    def test_version(self, capsys) -> None:
        with pytest.raises(SystemExit, match="0"):
            main(["--version"])
        out = capsys.readouterr().out
        assert "cvm-measure" in out

    def test_no_args_shows_help(self, capsys) -> None:
        with pytest.raises(SystemExit, match="1"):
            main([])

    def test_tdx_help(self, capsys) -> None:
        with pytest.raises(SystemExit, match="0"):
            main(["tdx", "--help"])


class TestCLIExtractBaseline:

    def test_extract_baseline_to_stdout(self, ccel_data_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)

        main(["tdx", "extract-baseline", "--ccel", str(ccel_path), "--machine-type", "a3-highgpu-1g"])

        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["machine_type"] == "a3-highgpu-1g"
        assert "events" in data
        assert len(data["events"]) > 0

    def test_extract_baseline_to_file(self, ccel_data_a3, tmp_path) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)
        out_path = tmp_path / "baseline.json"

        main([
            "tdx", "extract-baseline",
            "--ccel", str(ccel_path),
            "--machine-type", "test-type",
            "-o", str(out_path),
        ])

        data = json.loads(out_path.read_text())
        assert data["machine_type"] == "test-type"


class TestCLIInitdata:

    def test_initdata_computes_rtmr3(self, tmp_path, capsys) -> None:
        """--initdata should produce a non-zero RTMR[3] matching extend(zeros, sha384(file))."""
        import hashlib
        from cvm_measure.tdx.rtmr import SHA384_SIZE

        toml_content = b'version = "0.1.0"\nalgorithm = "sha384"\n\n[data]\n"policy.rego" = \'\'\'package agent_policy\ndefault AllowRequestsFailingPolicy := false\n\'\'\'\n'
        initdata_path = tmp_path / "initdata.toml"
        initdata_path.write_bytes(toml_content)

        digest = hashlib.sha384(toml_content).digest()
        expected_rtmr3 = hashlib.sha384(bytes(SHA384_SIZE) + digest).hexdigest()

        from cvm_measure.cli import _resolve_rtmr3
        import argparse
        args = argparse.Namespace(initdata=initdata_path, rtmr3=None)
        parser = argparse.ArgumentParser()
        result = _resolve_rtmr3(args, parser)
        assert result == expected_rtmr3

    def test_initdata_and_rtmr3_mutually_exclusive(self, tmp_path) -> None:
        initdata_path = tmp_path / "initdata.toml"
        initdata_path.write_bytes(b'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n')

        from cvm_measure.cli import _resolve_rtmr3
        import argparse
        args = argparse.Namespace(initdata=initdata_path, rtmr3="ab" * 48)
        parser = argparse.ArgumentParser()
        with pytest.raises(SystemExit):
            _resolve_rtmr3(args, parser)


class TestCLIReplay:

    def test_replay(self, ccel_data_a3, golden_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)

        main(["tdx", "replay", "--ccel", str(ccel_path)])

        out = capsys.readouterr().out
        lines = out.strip().split("\n")
        assert len(lines) == 4

        rtmr_values = {}
        for line in lines:
            key, value = line.split(":", 1)
            rtmr_values[key.strip()] = value.strip()

        assert rtmr_values["rtmr0"] == golden_a3.rtmr0
        assert rtmr_values["rtmr1"] == golden_a3.rtmr1
        assert rtmr_values["rtmr2"] == golden_a3.rtmr2
