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

"""EFI_GUID binary encoding.

An EFI_GUID is mixed-endian: the first three fields are little-endian, the
remaining eight bytes are stored in order. Both firmware parsing and UEFI
variable measurement need this encoding, so it lives in one place.
"""

from __future__ import annotations

import struct
import uuid

GUID_SIZE = 16


def uuid_to_efi_bytes(u: uuid.UUID) -> bytes:
    """Convert a Python UUID to EFI mixed-endian GUID bytes."""
    b = u.bytes
    return struct.pack("<IHH", *struct.unpack(">IHH", b[:8])) + b[8:]


def efi_bytes_to_uuid(data: bytes) -> uuid.UUID:
    """Convert EFI mixed-endian GUID bytes to a Python UUID."""
    d1, d2, d3 = struct.unpack_from("<IHH", data, 0)
    return uuid.UUID(bytes=struct.pack(">IHH", d1, d2, d3) + data[8:GUID_SIZE])


def guid_str_to_efi_bytes(guid_str: str) -> bytes:
    """Convert a canonical GUID string to EFI mixed-endian GUID bytes."""
    return uuid_to_efi_bytes(uuid.UUID(guid_str))
