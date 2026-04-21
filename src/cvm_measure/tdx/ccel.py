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

"""CCEL (CC Event Log) binary parser and TCG constants.

Parses the TDX event log recorded in /sys/firmware/acpi/tables/data/CCEL.
The log records every RTMR extend operation performed during boot.

Binary format follows the TCG PC Client Platform Firmware Profile:
  - First event: TCG_PCClientPCREvent (spec ID header, 20-byte legacy digest)
  - Subsequent events: TCG_PCR_EVENT2 (multi-algorithm digests)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# -- TPM Algorithm IDs ---------------------------------------------------------

TPM_ALG_SHA384: int = 0x000C

ALGO_DIGEST_SIZES: dict[int, int] = {
    0x0004: 20,  # SHA-1
    0x000B: 32,  # SHA-256
    0x000C: 48,  # SHA-384
    0x000D: 64,  # SHA-512
}

# -- TCG Event Types -----------------------------------------------------------

EV_NO_ACTION: int = 0x00000003
EV_SEPARATOR: int = 0x00000004

EV_EFI_VARIABLE_DRIVER_CONFIG: int = 0x80000001
EV_EFI_VARIABLE_BOOT: int = 0x80000002
EV_EFI_BOOT_SERVICES_APPLICATION: int = 0x80000003
EV_EFI_GPT_EVENT: int = 0x80000006
EV_EFI_ACTION: int = 0x80000007
EV_EFI_PLATFORM_FIRMWARE_BLOB2: int = 0x8000000A
EV_EFI_HANDOFF_TABLES2: int = 0x8000000B
EV_PLATFORM_CONFIG_FLAGS: int = 0x0000000A

_EVENT_TYPE_NAMES: dict[int, str] = {
    EV_NO_ACTION: "EV_NO_ACTION",
    EV_SEPARATOR: "EV_SEPARATOR",
    EV_EFI_VARIABLE_DRIVER_CONFIG: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    EV_EFI_VARIABLE_BOOT: "EV_EFI_VARIABLE_BOOT",
    EV_EFI_BOOT_SERVICES_APPLICATION: "EV_EFI_BOOT_SERVICES_APPLICATION",
    EV_EFI_GPT_EVENT: "EV_EFI_GPT_EVENT",
    EV_EFI_ACTION: "EV_EFI_ACTION",
    EV_EFI_PLATFORM_FIRMWARE_BLOB2: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    EV_EFI_HANDOFF_TABLES2: "EV_EFI_HANDOFF_TABLES2",
    EV_PLATFORM_CONFIG_FLAGS: "EV_PLATFORM_CONFIG_FLAGS",
}


# -- Data structures ----------------------------------------------------------


@dataclass
class EventLogEntry:
    """One event from the CCEL, corresponding to a single RTMR extend."""

    index: int
    imr_index: int  # RTMR index (0-3)
    event_type: int
    digests: dict[int, bytes]  # algo_id -> hash bytes
    event_data: bytes

    @property
    def event_type_name(self) -> str:
        return _EVENT_TYPE_NAMES.get(self.event_type, f"UNKNOWN(0x{self.event_type:08X})")


@dataclass
class ParsedEventLog:
    """Complete parsed CCEL containing all events."""

    digest_sizes: list[tuple[int, int]]  # (algo_id, byte_size) from spec ID header
    events: list[EventLogEntry] = field(default_factory=list)

    @property
    def measurable_events(self) -> list[EventLogEntry]:
        return [e for e in self.events if e.event_type != EV_NO_ACTION]

    def events_for_rtmr(self, rtmr_index: int) -> list[EventLogEntry]:
        return [
            e for e in self.events
            if e.imr_index == rtmr_index and e.event_type != EV_NO_ACTION
        ]


# -- Parsing -------------------------------------------------------------------


def parse_event_log(data: bytes) -> ParsedEventLog:
    """Parse a raw CCEL event log binary into structured events."""
    if len(data) < 32:
        raise ValueError(f"Event log too short ({len(data)} bytes)")

    offset = 0
    event_index = 0

    entry, digest_sizes, offset = _parse_spec_id_event(data, offset, event_index)
    result = ParsedEventLog(digest_sizes=digest_sizes, events=[entry])
    event_index += 1

    algo_sizes = dict(digest_sizes)

    while offset < len(data):
        if offset + 4 > len(data):
            break
        if struct.unpack_from("<I", data, offset)[0] == 0xFFFFFFFF:
            break

        entry, offset = _parse_event2(data, offset, event_index, algo_sizes)
        result.events.append(entry)
        event_index += 1

    return result


def _parse_spec_id_event(
    data: bytes, offset: int, index: int
) -> tuple[EventLogEntry, list[tuple[int, int]], int]:
    """Parse the first event (TCG_PCClientPCREvent with 20-byte legacy digest)."""
    imr_index = struct.unpack_from("<I", data, offset)[0] - 1
    offset += 4

    event_type = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    legacy_digest = data[offset : offset + 20]
    offset += 20

    event_size = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    event_data = data[offset : offset + event_size]
    offset += event_size

    # Parse the SpecIdEvent payload to extract algorithm digest sizes.
    so = 24  # skip: 16 (signature) + 4 (platform_class) + 4 × 1 (minor/major/errata/uintn)
    num_algos = struct.unpack_from("<I", event_data, so)[0]
    so += 4

    digest_sizes: list[tuple[int, int]] = []
    for _ in range(num_algos):
        algo_id = struct.unpack_from("<H", event_data, so)[0]
        so += 2
        digest_size = struct.unpack_from("<H", event_data, so)[0]
        so += 2
        digest_sizes.append((algo_id, digest_size))

    entry = EventLogEntry(
        index=index,
        imr_index=imr_index,
        event_type=event_type,
        digests={0x0000: legacy_digest},
        event_data=event_data,
    )

    return entry, digest_sizes, offset


def _parse_event2(
    data: bytes, offset: int, index: int, algo_sizes: dict[int, int]
) -> tuple[EventLogEntry, int]:
    """Parse a TCG_PCR_EVENT2 (multi-algorithm digest, variable-length)."""
    imr_index = struct.unpack_from("<I", data, offset)[0] - 1
    offset += 4

    event_type = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    digest_count = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    digests: dict[int, bytes] = {}
    for _ in range(digest_count):
        algo_id = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        dsz = algo_sizes.get(algo_id) or ALGO_DIGEST_SIZES.get(algo_id)
        if dsz is None:
            raise ValueError(
                f"Unknown algorithm 0x{algo_id:04X} at offset {offset - 2}"
            )

        digests[algo_id] = data[offset : offset + dsz]
        offset += dsz

    event_size = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    event_data = data[offset : offset + event_size]
    offset += event_size

    return (
        EventLogEntry(
            index=index,
            imr_index=imr_index,
            event_type=event_type,
            digests=digests,
            event_data=event_data,
        ),
        offset,
    )
