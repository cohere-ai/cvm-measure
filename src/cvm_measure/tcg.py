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

"""TCG PC Client event log parsing, shared by the CCEL and vTPM logs.

Intel TDX's CCEL and the vTPM's binary_bios_measurements use the same
encoding from the TCG PC Client Platform Firmware Profile: a
TCG_PCClientPCREvent header carrying the SpecIdEvent, then a run of
TCG_PCR_EVENT2 records. Only two things differ between them, and both are
parameters here rather than an excuse for a second parser:

  - **The register index.** A CCEL records the RTMR index plus one; a vTPM
    log records the PCR number directly. Reading one as the other shifts
    every event by a register, so the mapping is supplied by the caller.
  - **Trailing bytes.** A CCEL lives in an ACPI table allocated larger than
    the log it carries and ends in fill; a vTPM log is exactly sized.

An event log describes a boot this tool did not observe, so every length and
count in it is untrusted. Reads go through a cursor that validates each one
against the bytes that remain, because a Python slice truncates silently: an
unchecked read turns a malformed log into a short digest or a skipped event
rather than an error, and anything derived from it would be quietly
incomplete.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass

# -- TPM Algorithm IDs ---------------------------------------------------------

TPM_ALG_SHA1: int = 0x0004
TPM_ALG_SHA256: int = 0x000B
TPM_ALG_SHA384: int = 0x000C
TPM_ALG_SHA512: int = 0x000D

ALGO_DIGEST_SIZES: dict[int, int] = {
    TPM_ALG_SHA1: 20,
    TPM_ALG_SHA256: 32,
    TPM_ALG_SHA384: 48,
    TPM_ALG_SHA512: 64,
}

MAX_DIGEST_SIZE: int = 64

# -- TCG Event Types -----------------------------------------------------------

EV_NO_ACTION: int = 0x00000003
EV_SEPARATOR: int = 0x00000004
EV_EVENT_TAG: int = 0x00000006
EV_S_CRTM_VERSION: int = 0x00000008
EV_PLATFORM_CONFIG_FLAGS: int = 0x0000000A
EV_COMPACT_HASH: int = 0x0000000C
EV_IPL: int = 0x0000000D

EV_EFI_VARIABLE_DRIVER_CONFIG: int = 0x80000001
EV_EFI_VARIABLE_BOOT: int = 0x80000002
EV_EFI_BOOT_SERVICES_APPLICATION: int = 0x80000003
EV_EFI_GPT_EVENT: int = 0x80000006
EV_EFI_ACTION: int = 0x80000007
EV_EFI_PLATFORM_FIRMWARE_BLOB: int = 0x80000008
EV_EFI_PLATFORM_FIRMWARE_BLOB2: int = 0x8000000A
EV_EFI_HANDOFF_TABLES2: int = 0x8000000B

EVENT_TYPE_NAMES: dict[int, str] = {
    EV_NO_ACTION: "EV_NO_ACTION",
    EV_SEPARATOR: "EV_SEPARATOR",
    EV_EVENT_TAG: "EV_EVENT_TAG",
    EV_S_CRTM_VERSION: "EV_S_CRTM_VERSION",
    EV_PLATFORM_CONFIG_FLAGS: "EV_PLATFORM_CONFIG_FLAGS",
    EV_COMPACT_HASH: "EV_COMPACT_HASH",
    EV_IPL: "EV_IPL",
    EV_EFI_VARIABLE_DRIVER_CONFIG: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    EV_EFI_VARIABLE_BOOT: "EV_EFI_VARIABLE_BOOT",
    EV_EFI_BOOT_SERVICES_APPLICATION: "EV_EFI_BOOT_SERVICES_APPLICATION",
    EV_EFI_GPT_EVENT: "EV_EFI_GPT_EVENT",
    EV_EFI_ACTION: "EV_EFI_ACTION",
    EV_EFI_PLATFORM_FIRMWARE_BLOB: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    EV_EFI_PLATFORM_FIRMWARE_BLOB2: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    EV_EFI_HANDOFF_TABLES2: "EV_EFI_HANDOFF_TABLES2",
}


# -- Data structures ----------------------------------------------------------


@dataclass
class EventLogEntry:
    """One event from a log, corresponding to a single register extend."""

    index: int
    register_index: int
    event_type: int
    digests: dict[int, bytes]  # algo_id -> hash bytes
    event_data: bytes

    @property
    def event_type_name(self) -> str:
        return EVENT_TYPE_NAMES.get(self.event_type, f"UNKNOWN(0x{self.event_type:08X})")


# -- Bounds-checked reading ----------------------------------------------------

SPEC_ID_SIGNATURE = b"Spec ID Event03\x00"
LOG_TERMINATOR = 0xFFFFFFFF

# TCG_PCR_EVENT2 header: RegisterIndex + EventType + DigestCount.
EVENT2_HEADER_SIZE = 12
# TCG_PCClientPCREvent header: RegisterIndex + EventType + 20-byte digest + EventSize.
SPEC_ID_HEADER_SIZE = 32
# SpecIdEvent fields ahead of NumberOfAlgorithms: signature, PlatformClass,
# and one byte each of spec minor, major, errata, and uintnSize.
_SPEC_ID_ALGO_COUNT_OFFSET = 24

# The CCEL ACPI table is allocated larger than the log it carries, and firmware
# leaves the unused tail at the flash erase value. A zero-filled tail shows up
# in logs copied out of a zeroed buffer.
_PADDING_BYTES = (0xFF, 0x00)


class Cursor:
    """Sequential reader that refuses to read past the end of its buffer.

    Reads normally stop at `limit`, the offset where any trailing fill begins,
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
    """Where the buffer's trailing fill begins, and the byte it repeats."""
    for pad in _PADDING_BYTES:
        stripped = data.rstrip(bytes([pad]))
        if len(stripped) != len(data):
            return len(stripped), pad
    return len(data), None


def _require_only_padding(cursor: Cursor) -> None:
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


# -- Parsing -------------------------------------------------------------------

# Maps the register index a log records onto this platform's register
# numbering, raising for a register the platform does not have.
RegisterIndexFn = Callable[[int, Cursor], int]


def parse_events(
    data: bytes,
    *,
    what: str,
    to_register_index: RegisterIndexFn,
    tolerate_padding: bool,
) -> tuple[list[tuple[int, int]], list[EventLogEntry]]:
    """Parse a raw event log into its digest sizes and events.

    Raises ValueError on any log that is truncated, declares a length or count
    the buffer cannot hold, or carries bytes after its final event that are
    neither the TCG terminator nor, where tolerated, table padding.
    """
    if len(data) < SPEC_ID_HEADER_SIZE:
        raise ValueError(f"{what} too short ({len(data)} bytes)")

    # Events stop at the TCG terminator, or where the fill begins for firmware
    # that writes no terminator at all. The cursor knows the boundary too, so a
    # field the log overstates cannot be completed out of the fill.
    if tolerate_padding:
        body_end, fill = _padding_start(data)
    else:
        body_end, fill = len(data), None
    cursor = Cursor(data, what, limit=body_end, fill=fill)

    entry, digest_sizes = _parse_spec_id_event(cursor, 0, to_register_index)
    events = [entry]
    algo_sizes = dict(digest_sizes)

    index = 1
    while cursor.offset < body_end and cursor.remaining >= EVENT2_HEADER_SIZE:
        if cursor.peek_u32("RegisterIndex") == LOG_TERMINATOR:
            break
        events.append(_parse_event2(cursor, index, algo_sizes, to_register_index))
        index += 1

    _require_only_padding(cursor)
    return digest_sizes, events


def _parse_spec_id_event(
    cursor: Cursor, index: int, to_register_index: RegisterIndexFn
) -> tuple[EventLogEntry, list[tuple[int, int]]]:
    """Parse the first event (TCG_PCClientPCREvent with 20-byte legacy digest)."""
    raw_index = cursor.u32("RegisterIndex")
    event_type = cursor.u32("EventType")
    legacy_digest = cursor.take(20, "legacy digest", strict=True)
    event_size = cursor.u32("EventSize")
    event_data = cursor.take(event_size, "SpecIdEvent payload")

    entry = EventLogEntry(
        index=index,
        register_index=to_register_index(raw_index, cursor),
        event_type=event_type,
        digests={0x0000: legacy_digest},
        event_data=event_data,
    )
    return entry, parse_digest_sizes(event_data)


def parse_digest_sizes(event_data: bytes) -> list[tuple[int, int]]:
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

    payload = Cursor(event_data, "SpecIdEvent")
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
    cursor: Cursor,
    index: int,
    algo_sizes: dict[int, int],
    to_register_index: RegisterIndexFn,
) -> EventLogEntry:
    """Parse a TCG_PCR_EVENT2 (multi-algorithm digest, variable-length)."""
    raw_index = cursor.u32("RegisterIndex")
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

    register_index = to_register_index(raw_index, cursor)
    if event_type != EV_NO_ACTION and register_index < 0:
        raise ValueError(
            f"Measured event at offset {cursor.offset} records register index "
            f"{raw_index}, which is not a measurement register"
        )

    return EventLogEntry(
        index=index,
        register_index=register_index,
        event_type=event_type,
        digests=digests,
        event_data=event_data,
    )
