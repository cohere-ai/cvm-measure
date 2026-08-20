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

"""CCEL (CC Event Log) parsing for TDX.

Parses the TDX event log recorded in /sys/firmware/acpi/tables/data/CCEL.
The log records every RTMR extend operation performed during boot.

The binary encoding is the TCG PC Client format handled by ``cvm_measure.tcg``.
What is specific to a CCEL, and lives here, is that MrIndex is the RTMR index
plus one, and that the log sits in an ACPI table allocated larger than itself
and so ends in fill.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..tcg import (
    ALGO_DIGEST_SIZES,
    EV_EFI_ACTION,
    EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_EFI_GPT_EVENT,
    EV_EFI_HANDOFF_TABLES2,
    EV_EFI_PLATFORM_FIRMWARE_BLOB2,
    EV_EFI_VARIABLE_BOOT,
    EV_EFI_VARIABLE_DRIVER_CONFIG,
    EV_NO_ACTION,
    EV_PLATFORM_CONFIG_FLAGS,
    EV_SEPARATOR,
    LOG_TERMINATOR,
    MAX_DIGEST_SIZE,
    SPEC_ID_SIGNATURE,
    TPM_ALG_SHA384,
    Cursor,
    EventLogEntry,
    parse_events,
)

__all__ = [
    "ALGO_DIGEST_SIZES",
    "EV_EFI_ACTION",
    "EV_EFI_BOOT_SERVICES_APPLICATION",
    "EV_EFI_GPT_EVENT",
    "EV_EFI_HANDOFF_TABLES2",
    "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    "EV_EFI_VARIABLE_BOOT",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    "EV_NO_ACTION",
    "EV_PLATFORM_CONFIG_FLAGS",
    "EV_SEPARATOR",
    "LOG_TERMINATOR",
    "MAX_DIGEST_SIZE",
    "MAX_MR_INDEX",
    "SPEC_ID_SIGNATURE",
    "TPM_ALG_SHA384",
    "EventLogEntry",
    "ParsedEventLog",
    "parse_event_log",
]

# MrIndex is the RTMR index plus one. Index 0 belongs to the informational
# EV_NO_ACTION records at the head of the log, which are never extended.
MAX_MR_INDEX = 4


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
            if e.register_index == rtmr_index and e.event_type != EV_NO_ACTION
        ]


def _validated_imr_index(mr_index: int, cursor: Cursor) -> int:
    """Convert MrIndex to an RTMR index, rejecting registers TDX does not have."""
    if mr_index > MAX_MR_INDEX:
        raise ValueError(
            f"Event before offset {cursor.offset} records MrIndex {mr_index}, "
            f"but TDX only has {MAX_MR_INDEX} measurement register(s)"
        )
    return mr_index - 1


def parse_event_log(data: bytes) -> ParsedEventLog:
    """Parse a raw CCEL event log binary into structured events.

    Raises ValueError on any log that is truncated, declares a length or count
    the buffer cannot hold, or carries bytes after its final event that are
    neither the TCG terminator nor ACPI table padding. The unused tail of the
    ACPI table is not a source of event bytes: a digest is refused if it
    reaches into the fill, so a truncated log cannot be completed with fill
    and replayed.
    """
    digest_sizes, events = parse_events(
        data,
        what="Event log",
        to_register_index=_validated_imr_index,
        tolerate_padding=True,
    )
    return ParsedEventLog(digest_sizes=digest_sizes, events=events)
