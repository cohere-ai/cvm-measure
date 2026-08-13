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

"""UEFI variable measurement: build UEFI_VARIABLE_DATA and compute digests.

Per the TCG PC Client Platform Firmware Profile Specification, the
EV_EFI_VARIABLE_DRIVER_CONFIG event measures a UEFI_VARIABLE_DATA structure:

    EFI_GUID  VariableName        (16 bytes, mixed-endian)
    UINT64    UnicodeNameLength   (character count, not bytes)
    UINT64    VariableDataLength  (byte count)
    CHAR16    UnicodeName[]       (UnicodeNameLength * 2 bytes)
    UINT8     VariableData[]      (VariableDataLength bytes)

The measured digest is SHA-384 of this entire structure.
"""

from __future__ import annotations

import hashlib
import struct

from .guid import guid_str_to_efi_bytes

EFI_GLOBAL_VARIABLE_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
EFI_IMAGE_SECURITY_DATABASE_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

SECUREBOOT_VAR_GUIDS = {
    "SecureBoot": EFI_GLOBAL_VARIABLE_GUID,
    "PK": EFI_GLOBAL_VARIABLE_GUID,
    "KEK": EFI_GLOBAL_VARIABLE_GUID,
    "db": EFI_IMAGE_SECURITY_DATABASE_GUID,
    "dbx": EFI_IMAGE_SECURITY_DATABASE_GUID,
}


def build_uefi_variable_data(
    guid: str,
    name: str,
    data: bytes,
) -> bytes:
    """Build a UEFI_VARIABLE_DATA binary structure."""
    guid_bytes = guid_str_to_efi_bytes(guid)
    name_utf16 = name.encode("utf-16-le")
    return (
        guid_bytes
        + struct.pack("<Q", len(name))
        + struct.pack("<Q", len(data))
        + name_utf16
        + data
    )


def compute_variable_digest(guid: str, name: str, data: bytes) -> bytes:
    """Compute SHA-384(UEFI_VARIABLE_DATA) for a UEFI variable measurement."""
    blob = build_uefi_variable_data(guid, name, data)
    return hashlib.sha384(blob).digest()


def compute_secureboot_digest(name: str, data: bytes) -> bytes:
    """Compute measurement digest for a Secure Boot variable by name."""
    guid = SECUREBOOT_VAR_GUIDS[name]
    return compute_variable_digest(guid, name, data)
