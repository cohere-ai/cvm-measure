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

"""Unit tests: EFI_GUID mixed-endian encoding."""

from __future__ import annotations

import uuid

from cvm_measure.tdx.guid import (
    efi_bytes_to_uuid,
    guid_str_to_efi_bytes,
    uuid_to_efi_bytes,
)


class TestEFIGuidConversion:

    def test_roundtrip(self) -> None:
        u = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d")
        assert efi_bytes_to_uuid(uuid_to_efi_bytes(u)) == u

    def test_known_guid(self) -> None:
        u = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2")
        efi = uuid_to_efi_bytes(u)
        assert len(efi) == 16
        assert efi_bytes_to_uuid(efi) == u

    def test_first_field_is_little_endian(self) -> None:
        result = guid_str_to_efi_bytes("8be4df61-93ca-11d2-aa0d-00e098032b8c")
        assert len(result) == 16
        assert result[:4] == b"\x61\xdf\xe4\x8b"

    def test_str_and_uuid_helpers_agree(self) -> None:
        guid = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        assert guid_str_to_efi_bytes(guid) == uuid_to_efi_bytes(uuid.UUID(guid))
