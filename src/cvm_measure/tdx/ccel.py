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

A CCEL describes a boot this tool did not observe, so every length and count
in it is untrusted. Reads go through a cursor that validates each one against
the bytes that remain, because a Python slice truncates silently: an
unchecked read turns a malformed log into a short digest or a skipped event
rather than an error, and a baseline extracted from it would be quietly
incomplete.
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

MAX_DIGEST_SIZE: int = 64

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


# -- Bounds-checked reading ----------------------------------------------------

SPEC_ID_SIGNATURE = b"Spec ID Event03\x00"
LOG_TERMINATOR = 0xFFFFFFFF

# MrIndex is the RTMR index plus one. Index 0 belongs to the informational
# EV_NO_ACTION records at the head of the log, which are never extended.
MAX_MR_INDEX = 4

# TCG_PCR_EVENT2 header: MrIndex + EventType + DigestCount.
_EVENT2_HEADER_SIZE = 12
# TCG_PCClientPCREvent header: MrIndex + EventType + 20-byte digest + EventSize.
_SPEC_ID_HEADER_SIZE = 32
# SpecIdEvent fields ahead of NumberOfAlgorithms: signature, PlatformClass,
# and one byte each of spec minor, major, errata, and uintnSize.
_SPEC_ID_ALGO_COUNT_OFFSET = 24

# The CCEL ACPI table is allocated larger than the log it carries, and firmware
# leaves the unused tail at the flash erase value. A zero-filled tail shows up
# in logs copied out of a zeroed buffer.
_PADDING_BYTES = (0xFF, 0x00)


class _Cursor:
    """Sequential reader that refuses to read past the end of its buffer.

    Reads normally stop at `limit`, the offset where the table's fill begins,
    so the fill cannot satisfy a length the log declares. `_require` documents
    the one crossing that is allowed and the fields excluded from it.
    """

    __slots__ = ("_data", "_fill", "_limit", "_offset", "_what")

    def __init__(
        self, data: bytes, what: str, limit: int | None = None, fill: int | None = None
    ) -> None:
        self._data = data
        self._offset = 0
        self._what = what
        self._limit = len(data) if limit is None else limit
        self._fill = fill

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def remaining(self) -> int:
        """Bytes before the fill boundary, which is where events stop."""
        return max(self._limit - self._offset, 0)

    @property
    def in_buffer(self) -> int:
        """Bytes before the end of the buffer, fill included."""
        return len(self._data) - self._offset

    def _require(self, size: int, field: str, strict: bool = False) -> None:
        if size <= self.remaining:
            return
        # The boundary is found by stripping fill from the end, so it lands
        # early whenever a real field ends in fill-valued bytes: a zero-filled
        # table hides the top bytes of an EventSize like 0x00000008, and the
        # last event's data can end in fill. Such a read may cross into bytes
        # that are all fill. Digests are read strictly instead, because a
        # digest completed out of the fill is one this tool would go on to
        # replay or write into a baseline as though the log had carried it.
        if not strict and self._fill is not None and size <= self.in_buffer:
            spill = self._data[max(self._offset, self._limit) : self._offset + size]
            if spill.count(self._fill) == len(spill):
                return
        raise ValueError(
            f"{self._what} truncated at offset {self._offset}: {field} needs "
            f"{size} byte(s), {self.in_buffer} remain"
        )

    def u8(self, field: str) -> int:
        self._require(1, field)
        value = self._data[self._offset]
        self._offset += 1
        return value

    def u16(self, field: str) -> int:
        self._require(2, field)
        value: int = struct.unpack_from("<H", self._data, self._offset)[0]
        self._offset += 2
        return value

    def u32(self, field: str) -> int:
        self._require(4, field)
        value: int = struct.unpack_from("<I", self._data, self._offset)[0]
        self._offset += 4
        return value

    def take(self, size: int, field: str, strict: bool = False) -> bytes:
        self._require(size, field, strict)
        value = self._data[self._offset : self._offset + size]
        self._offset += size
        return value

    def peek_u32(self, field: str) -> int:
        self._require(4, field)
        value: int = struct.unpack_from("<I", self._data, self._offset)[0]
        return value

    def bounded_count(self, count: int, item_size: int, field: str) -> int:
        """Reject a declared count too large for the bytes that remain.

        Without this, a count of 0xFFFFFFFF would spin through billions of
        iterations before the first out-of-bounds read stopped it.
        """
        if count * item_size > self.in_buffer:
            raise ValueError(
                f"{self._what} declares {count} {field} at offset {self._offset}, "
                f"needing at least {count * item_size} byte(s) of the "
                f"{self.in_buffer} that remain"
            )
        return count

    def tail(self) -> bytes:
        return self._data[self._offset :]


def _padding_start(data: bytes) -> tuple[int, int | None]:
    """Where the table's trailing fill begins, and the byte it repeats."""
    for pad in _PADDING_BYTES:
        stripped = data.rstrip(bytes([pad]))
        if len(stripped) != len(data):
            return len(stripped), pad
    return len(data), None


def _require_only_padding(cursor: _Cursor) -> None:
    """Refuse a log with unexplained bytes after its last event.

    What may follow the events is a terminator, table fill, or a terminator
    ahead of fill, which is what a zero-filled table holding a terminated log
    looks like.
    """
    tail = cursor.tail()
    if tail[:4] == struct.pack("<I", LOG_TERMINATOR):
        tail = tail[4:]
    if not tail or any(tail.count(pad) == len(tail) for pad in _PADDING_BYTES):
        return
    raise ValueError(
        f"Event log has {len(tail)} unparsed byte(s) after the last event at "
        f"offset {cursor.offset}, which are neither a terminator nor table padding"
    )


def _validated_imr_index(mr_index: int, cursor: _Cursor) -> int:
    """Convert MrIndex to an RTMR index, rejecting registers TDX does not have."""
    if mr_index > MAX_MR_INDEX:
        raise ValueError(
            f"Event before offset {cursor.offset} records MrIndex {mr_index}, "
            f"but TDX only has {MAX_MR_INDEX} measurement register(s)"
        )
    return mr_index - 1


# -- Parsing -------------------------------------------------------------------


def parse_event_log(data: bytes) -> ParsedEventLog:
    """Parse a raw CCEL event log binary into structured events.

    Raises ValueError on any log that is truncated, declares a length or count
    the buffer cannot hold, or carries bytes after its final event that are
    neither the TCG terminator nor ACPI table padding.
    """
    if len(data) < _SPEC_ID_HEADER_SIZE:
        raise ValueError(f"Event log too short ({len(data)} bytes)")

    # Events stop at the TCG terminator, or where the table's fill begins for
    # firmware that writes no terminator at all. The cursor knows the boundary
    # too, so a field the log overstates cannot be completed out of the fill.
    body_end, fill = _padding_start(data)
    cursor = _Cursor(data, "Event log", limit=body_end, fill=fill)

    entry, digest_sizes = _parse_spec_id_event(cursor, 0)
    result = ParsedEventLog(digest_sizes=digest_sizes, events=[entry])
    algo_sizes = dict(digest_sizes)

    index = 1
    while cursor.offset < body_end and cursor.remaining >= _EVENT2_HEADER_SIZE:
        if cursor.peek_u32("MrIndex") == LOG_TERMINATOR:
            break
        result.events.append(_parse_event2(cursor, index, algo_sizes))
        index += 1

    _require_only_padding(cursor)
    return result


def _parse_spec_id_event(
    cursor: _Cursor, index: int
) -> tuple[EventLogEntry, list[tuple[int, int]]]:
    """Parse the first event (TCG_PCClientPCREvent with 20-byte legacy digest)."""
    mr_index = cursor.u32("MrIndex")
    event_type = cursor.u32("EventType")
    legacy_digest = cursor.take(20, "legacy digest", strict=True)
    event_size = cursor.u32("EventSize")
    event_data = cursor.take(event_size, "SpecIdEvent payload")

    entry = EventLogEntry(
        index=index,
        imr_index=_validated_imr_index(mr_index, cursor),
        event_type=event_type,
        digests={0x0000: legacy_digest},
        event_data=event_data,
    )
    return entry, _parse_digest_sizes(event_data)


def _parse_digest_sizes(event_data: bytes) -> list[tuple[int, int]]:
    """Read the algorithm digest sizes the log's events use.

    Every later event is parsed against these sizes, so a lie here shifts the
    whole log. The signature is checked because the fields below are read at
    fixed offsets, and the sizes declared for algorithms with a known digest
    length have to agree with it.
    """
    if event_data[: len(SPEC_ID_SIGNATURE)] != SPEC_ID_SIGNATURE:
        raise ValueError(
            f"First event is not a SpecIdEvent: expected signature "
            f"{SPEC_ID_SIGNATURE!r}, got {event_data[: len(SPEC_ID_SIGNATURE)]!r}"
        )

    payload = _Cursor(event_data, "SpecIdEvent")
    payload.take(_SPEC_ID_ALGO_COUNT_OFFSET, "SpecIdEvent header")
    num_algos = payload.u32("NumberOfAlgorithms")
    payload.bounded_count(num_algos, 4, "algorithm(s)")
    if num_algos == 0:
        raise ValueError("SpecIdEvent declares no digest algorithms")

    digest_sizes: list[tuple[int, int]] = []
    seen: set[int] = set()
    for _ in range(num_algos):
        algo_id = payload.u16("AlgorithmId")
        digest_size = payload.u16("DigestSize")
        if algo_id in seen:
            raise ValueError(f"SpecIdEvent lists algorithm 0x{algo_id:04X} twice")
        seen.add(algo_id)

        known = ALGO_DIGEST_SIZES.get(algo_id)
        if known is not None and digest_size != known:
            raise ValueError(
                f"SpecIdEvent declares {digest_size} bytes for algorithm "
                f"0x{algo_id:04X}, which has a {known}-byte digest"
            )
        if not 0 < digest_size <= MAX_DIGEST_SIZE:
            raise ValueError(
                f"SpecIdEvent declares an unusable digest size {digest_size} "
                f"for algorithm 0x{algo_id:04X}"
            )
        digest_sizes.append((algo_id, digest_size))

    payload.take(payload.u8("VendorInfoSize"), "VendorInfo")
    if payload.remaining:
        raise ValueError(
            f"SpecIdEvent has {payload.remaining} byte(s) beyond its declared fields"
        )
    return digest_sizes


def _parse_event2(
    cursor: _Cursor, index: int, algo_sizes: dict[int, int]
) -> EventLogEntry:
    """Parse a TCG_PCR_EVENT2 (multi-algorithm digest, variable-length)."""
    mr_index = cursor.u32("MrIndex")
    event_type = cursor.u32("EventType")
    digest_count = cursor.u32("DigestCount")

    # Each entry is at least an algorithm id plus a one-byte digest.
    cursor.bounded_count(digest_count, 3, "digest(s)")

    digests: dict[int, bytes] = {}
    for _ in range(digest_count):
        algo_offset = cursor.offset
        algo_id = cursor.u16("AlgorithmId")

        dsz = algo_sizes.get(algo_id) or ALGO_DIGEST_SIZES.get(algo_id)
        if dsz is None:
            raise ValueError(f"Unknown algorithm 0x{algo_id:04X} at offset {algo_offset}")
        if algo_id in digests:
            raise ValueError(
                f"Event at offset {algo_offset} repeats algorithm 0x{algo_id:04X}"
            )

        digests[algo_id] = cursor.take(dsz, f"0x{algo_id:04X} digest", strict=True)

    event_size = cursor.u32("EventSize")
    event_data = cursor.take(event_size, "event data")

    imr_index = _validated_imr_index(mr_index, cursor)
    if event_type != EV_NO_ACTION and imr_index < 0:
        raise ValueError(
            f"Measured event at offset {cursor.offset} records MrIndex {mr_index}, "
            "which is not an RTMR"
        )

    return EventLogEntry(
        index=index,
        imr_index=imr_index,
        event_type=event_type,
        digests=digests,
        event_data=event_data,
    )
