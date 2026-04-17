"""Unit tests: CoCo initdata TOML parsing and digest."""

from __future__ import annotations

import hashlib

from cvm_measure.tdx.initdata import _parse_toml_text, compute_digest


class TestInitDataDigest:

    def test_digest_is_sha384_of_raw_bytes(self, tmp_path) -> None:
        toml_content = b'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n'
        path = tmp_path / "initdata.toml"
        path.write_bytes(toml_content)
        assert compute_digest(path) == hashlib.sha384(toml_content).digest()


class TestParseToml:

    def test_parse_simple(self) -> None:
        text = 'version = "0.1.0"\nalgorithm = "sha384"\n\n[data]\n"policy.rego" = \'\'\'allow = true\'\'\'\n'
        result = _parse_toml_text(text)
        assert result.version == "0.1.0"
        assert result.algorithm == "sha384"
        assert "policy.rego" in result.data

    def test_parse_multiline(self) -> None:
        text = 'version = "1.0"\nalgorithm = "sha384"\n\n[data]\n"config" = \'\'\'\nline1\nline2\n\'\'\'\n'
        result = _parse_toml_text(text)
        assert "config" in result.data
        assert "line1" in result.data["config"]
        assert "line2" in result.data["config"]

    def test_parse_empty_data(self) -> None:
        text = 'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n'
        result = _parse_toml_text(text)
        assert result.version == "0.1.0"
        assert len(result.data) == 0
