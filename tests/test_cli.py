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

"""Unit tests: CLI argument parsing and basic flows."""

from __future__ import annotations

import json

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
        assert data["provider"] == "gcp"
        assert data["platform"] == "tdx"
        assert "events" in data
        assert len(data["events"]) > 0
        assert not any(e["label"] == "GPT" for e in data["events"])

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
        assert data["provider"] == "gcp"
        assert data["platform"] == "tdx"

    def test_extract_baseline_infers_azure(self, ccel_data_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)

        main(["tdx", "extract-baseline", "--ccel", str(ccel_path), "--machine-type", "Standard_DC4as_v5"])

        data = json.loads(capsys.readouterr().out)
        assert data["provider"] == "azure"
        assert data["platform"] == "tdx"

    def test_extract_baseline_infers_aws(self, ccel_data_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)

        main(["tdx", "extract-baseline", "--ccel", str(ccel_path), "--machine-type", "m7i.metal"])

        data = json.loads(capsys.readouterr().out)
        assert data["provider"] == "aws"
        assert data["platform"] == "tdx"

    def test_extract_baseline_provider_override(self, ccel_data_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)

        main([
            "tdx", "extract-baseline",
            "--ccel", str(ccel_path),
            "--machine-type", "a3-highgpu-1g",
            "--provider", "custom-cloud",
        ])

        data = json.loads(capsys.readouterr().out)
        assert data["provider"] == "custom-cloud"
        assert data["platform"] == "tdx"

    def test_extract_baseline_platform_override(self, ccel_data_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)

        main([
            "tdx", "extract-baseline",
            "--ccel", str(ccel_path),
            "--machine-type", "a3-highgpu-1g",
            "--platform", "sev-snp",
        ])

        data = json.loads(capsys.readouterr().out)
        assert data["provider"] == "gcp"
        assert data["platform"] == "sev-snp"

    def test_extract_baseline_firmware_sha384(self, ccel_data_a3, tmp_path, capsys) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)
        fw_sha = "aa" * 48

        main([
            "tdx", "extract-baseline",
            "--ccel", str(ccel_path),
            "--machine-type", "a3-highgpu-1g",
            "--firmware-sha384", fw_sha,
        ])

        data = json.loads(capsys.readouterr().out)
        assert data["firmware_sha384"] == fw_sha

    def test_extract_baseline_firmware_sha384_to_file(self, ccel_data_a3, tmp_path) -> None:
        ccel_path = tmp_path / "ccel.bin"
        ccel_path.write_bytes(ccel_data_a3)
        out_path = tmp_path / "baseline.json"
        fw_sha = "bb" * 48

        main([
            "tdx", "extract-baseline",
            "--ccel", str(ccel_path),
            "--machine-type", "a3-highgpu-1g",
            "--firmware-sha384", fw_sha,
            "-o", str(out_path),
        ])

        data = json.loads(out_path.read_text())
        assert data["firmware_sha384"] == fw_sha


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

        import argparse

        from cvm_measure.cli import _resolve_rtmr3

        args = argparse.Namespace(initdata=initdata_path, rtmr3=None)
        parser = argparse.ArgumentParser()
        result = _resolve_rtmr3(args, parser)
        assert result == expected_rtmr3

    def test_initdata_and_rtmr3_mutually_exclusive(self, tmp_path) -> None:
        initdata_path = tmp_path / "initdata.toml"
        initdata_path.write_bytes(b'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n')

        import argparse

        from cvm_measure.cli import _resolve_rtmr3

        args = argparse.Namespace(initdata=initdata_path, rtmr3="ab" * 48)
        parser = argparse.ArgumentParser()
        with pytest.raises(SystemExit):
            _resolve_rtmr3(args, parser)


class TestCLIOutputFormat:

    def test_output_format_json(self, capsys) -> None:
        from cvm_measure.cli import _output_registers
        data = {"mrtd": "aa" * 48, "rtmr0": "bb" * 48}
        _output_registers(data, "json")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["mrtd"] == "aa" * 48
        assert parsed["rtmr0"] == "bb" * 48

    def test_output_format_text(self, capsys) -> None:
        from cvm_measure.cli import _output_registers
        data = {"mrtd": "aa" * 48, "rtmr0": "bb" * 48}
        _output_registers(data, "text")
        out = capsys.readouterr().out
        assert "mrtd:" in out
        assert "rtmr0:" in out


class TestCLIFileValidation:

    def test_missing_firmware(self, tmp_path, capsys) -> None:
        with pytest.raises(SystemExit):
            main([
                "tdx",
                "--firmware", str(tmp_path / "nonexistent.fd"),
                "--ram", "234",
                "--mode", "mrtd",
            ])
        err = capsys.readouterr().err
        assert "not found" in err

    def test_missing_uki(self, firmware_a3, tmp_path, capsys) -> None:
        fw_path = tmp_path / "fw.fd"
        fw_path.write_bytes(firmware_a3)
        with pytest.raises(SystemExit):
            main([
                "tdx",
                "--firmware", str(fw_path),
                "--uki", str(tmp_path / "nonexistent.efi"),
                "--baseline", str(tmp_path / "baseline.json"),
                "--ram", "234",
            ])

    def test_missing_baseline(self, firmware_a3, uki_a3, tmp_path, capsys) -> None:
        fw_path = tmp_path / "fw.fd"
        fw_path.write_bytes(firmware_a3)
        uki_path = tmp_path / "uki.efi"
        uki_path.write_bytes(uki_a3)
        with pytest.raises(SystemExit):
            main([
                "tdx",
                "--firmware", str(fw_path),
                "--uki", str(uki_path),
                "--baseline", str(tmp_path / "nonexistent.json"),
                "--ram", "234",
            ])


class TestCLIMrtdOnly:

    def test_mrtd_text(self, firmware_a3, golden_a3, tmp_path, capsys) -> None:
        fw_path = tmp_path / "fw.fd"
        fw_path.write_bytes(firmware_a3)

        main([
            "tdx",
            "--firmware", str(fw_path),
            "--ram", "234",
            "--mode", "mrtd",
        ])

        out = capsys.readouterr().out
        assert "mrtd:" in out
        assert golden_a3.mrtd in out

    def test_mrtd_json(self, firmware_a3, golden_a3, tmp_path, capsys) -> None:
        fw_path = tmp_path / "fw.fd"
        fw_path.write_bytes(firmware_a3)

        main([
            "tdx",
            "--firmware", str(fw_path),
            "--ram", "234",
            "--mode", "mrtd",
            "--output-format", "json",
        ])

        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["mrtd"] == golden_a3.mrtd


class TestCLIComputeAll:

    def test_compute_all_text(
        self, firmware_a3, uki_a3, baseline_a3, golden_a3, tmp_path, capsys
    ) -> None:
        fw_path = tmp_path / "fw.fd"
        fw_path.write_bytes(firmware_a3)
        uki_path = tmp_path / "uki.efi"
        uki_path.write_bytes(uki_a3)

        from cvm_measure.tdx.baseline import save
        bl_path = tmp_path / "baseline.json"
        save(baseline_a3, bl_path)

        main([
            "tdx",
            "--firmware", str(fw_path),
            "--uki", str(uki_path),
            "--baseline", str(bl_path),
            "--ram", "234",
        ])

        out = capsys.readouterr().out
        assert "mrtd:" in out
        assert golden_a3.mrtd in out

    def test_compute_all_json(
        self, firmware_a3, uki_a3, baseline_a3, golden_a3, tmp_path, capsys
    ) -> None:
        fw_path = tmp_path / "fw.fd"
        fw_path.write_bytes(firmware_a3)
        uki_path = tmp_path / "uki.efi"
        uki_path.write_bytes(uki_a3)

        from cvm_measure.tdx.baseline import save
        bl_path = tmp_path / "baseline.json"
        save(baseline_a3, bl_path)

        main([
            "tdx",
            "--firmware", str(fw_path),
            "--uki", str(uki_path),
            "--baseline", str(bl_path),
            "--ram", "234",
            "--output-format", "json",
        ])

        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["mrtd"] == golden_a3.mrtd
        assert data["rtmr0"] == golden_a3.rtmr0
        assert data["rtmr2"] == golden_a3.rtmr2


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
