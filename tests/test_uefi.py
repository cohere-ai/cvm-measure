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

"""Unit tests: UEFI variable measurement."""

from __future__ import annotations

from cvm_measure.tdx.uefi import (
    build_uefi_variable_data,
    compute_secureboot_digest,
    compute_variable_digest,
    guid_to_bytes,
)


class TestGuidToBytes:

    def test_known_guid(self) -> None:
        result = guid_to_bytes("8be4df61-93ca-11d2-aa0d-00e098032b8c")
        assert len(result) == 16
        assert result[:4] == b"\x61\xdf\xe4\x8b"

    def test_round_trip(self) -> None:
        guid = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        result = guid_to_bytes(guid)
        assert len(result) == 16


class TestBuildUefiVariableData:

    def test_structure_layout(self) -> None:
        data = build_uefi_variable_data(
            "8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "SecureBoot",
            b"\x00",
        )
        assert len(data) == 16 + 8 + 8 + 20 + 1  # guid + name_len + data_len + name_utf16 + data

    def test_digest_is_deterministic(self) -> None:
        d1 = compute_variable_digest("8be4df61-93ca-11d2-aa0d-00e098032b8c", "SecureBoot", b"\x00")
        d2 = compute_variable_digest("8be4df61-93ca-11d2-aa0d-00e098032b8c", "SecureBoot", b"\x00")
        assert d1 == d2
        assert len(d1) == 48


class TestSecureBootDigest:

    def test_sb_off(self) -> None:
        digest = compute_secureboot_digest("SecureBoot", b"\x00")
        assert len(digest) == 48

    def test_sb_on_different(self) -> None:
        off = compute_secureboot_digest("SecureBoot", b"\x00")
        on = compute_secureboot_digest("SecureBoot", b"\x01")
        assert off != on

    def test_pk_uses_global_guid(self) -> None:
        digest = compute_secureboot_digest("PK", b"\x00")
        assert len(digest) == 48
