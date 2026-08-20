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

"""Unit tests: CoCo initdata digest."""

from __future__ import annotations

import hashlib

import pytest

from cvm_measure.initdata import compute_digest as compute_any_digest
from cvm_measure.initdata import parse_algorithm
from cvm_measure.tdx.initdata import compute_digest


def write_toml(tmp_path, content: bytes):
    path = tmp_path / "initdata.toml"
    path.write_bytes(content)
    return path


class TestInitDataDigest:

    def test_digest_is_sha384_of_raw_bytes(self, tmp_path) -> None:
        toml_content = b'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n'
        path = write_toml(tmp_path, toml_content)
        assert compute_digest(path) == hashlib.sha384(toml_content).digest()

    @pytest.mark.parametrize("algorithm", ["sha256", "sha384", "sha512"])
    def test_digest_follows_the_declared_algorithm(self, tmp_path, algorithm) -> None:
        """CoCo switches on this key, so hardcoding one hash would put a
        wrong value in a register that looks like a right one."""
        toml_content = f'algorithm = "{algorithm}"\nversion = "0.1.0"\n'.encode()
        path = write_toml(tmp_path, toml_content)
        expected = hashlib.new(algorithm, toml_content).digest()
        assert compute_any_digest(path) == expected


class TestAlgorithmParsing:

    def test_reads_a_quoted_top_level_key(self) -> None:
        assert parse_algorithm(b"algorithm = 'sha512'\n") == "sha512"

    def test_stops_at_the_first_table(self) -> None:
        """An algorithm key inside [data] is someone's payload, not the
        key CoCo digests with."""
        with pytest.raises(ValueError, match="no top-level 'algorithm'"):
            parse_algorithm(b'version = "0.1.0"\n[data]\nalgorithm = "sha256"\n')

    def test_rejects_an_algorithm_coco_does_not_implement(self) -> None:
        with pytest.raises(ValueError, match="does not implement"):
            parse_algorithm(b'algorithm = "sha1"\n')

    def test_rejects_a_file_that_declares_none(self) -> None:
        with pytest.raises(ValueError, match="no top-level 'algorithm'"):
            parse_algorithm(b'version = "0.1.0"\n')


class TestTdxRequiresSha384:

    def test_refuses_a_shorter_digest_than_rtmr3_holds(self, tmp_path) -> None:
        """RTMR[3] is a 48-byte interface, so a sha256 initdata describes a
        measurement TDX cannot perform."""
        path = write_toml(tmp_path, b'algorithm = "sha256"\nversion = "0.1.0"\n')
        with pytest.raises(ValueError, match="measures a sha384 digest"):
            compute_digest(path)
