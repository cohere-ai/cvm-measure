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
from pathlib import Path

# -- TPM Algorithm IDs ---------------------------------------------------------

TPM_ALG_ERROR: int = 0x0000
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

ALGO_NAMES: dict[int, str] = {
    TPM_ALG_ERROR: "TPM_ALG_ERROR",
    TPM_ALG_SHA1: "TPM_ALG_SHA1",
    TPM_ALG_SHA256: "TPM_ALG_SHA256",
    TPM_ALG_SHA384: "TPM_ALG_SHA384",
    TPM_ALG_SHA512: "TPM_ALG_SHA512",
}

# -- TCG Event Types -----------------------------------------------------------

EV_NO_ACTION: int = 0x00000003
EV_SEPARATOR: int = 0x00000004
EV_IPL: int = 0x0000000D

EV_EFI_EVENT_BASE: int = 0x80000000
EV_EFI_VARIABLE_DRIVER_CONFIG: int = EV_EFI_EVENT_BASE + 0x1
EV_EFI_VARIABLE_BOOT: int = EV_EFI_EVENT_BASE + 0x2
EV_EFI_BOOT_SERVICES_APPLICATION: int = EV_EFI_EVENT_BASE + 0x3
EV_EFI_GPT_EVENT: int = EV_EFI_EVENT_BASE + 0x6
EV_EFI_ACTION: int = EV_EFI_EVENT_BASE + 0x7
EV_EFI_PLATFORM_FIRMWARE_BLOB: int = EV_EFI_EVENT_BASE + 0x8
EV_EFI_PLATFORM_FIRMWARE_BLOB2: int = EV_EFI_EVENT_BASE + 0xA
EV_EFI_HANDOFF_TABLES2: int = EV_EFI_EVENT_BASE + 0xB
EV_PLATFORM_CONFIG_FLAGS: int = 0x0000000A

EVENT_TYPE_NAMES: dict[int, str] = {
    EV_NO_ACTION: "EV_NO_ACTION",
    EV_SEPARATOR: "EV_SEPARATOR",
    EV_IPL: "EV_IPL",
    EV_EFI_VARIABLE_DRIVER_CONFIG: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    EV_EFI_VARIABLE_BOOT: "EV_EFI_VARIABLE_BOOT",
    EV_EFI_BOOT_SERVICES_APPLICATION: "EV_EFI_BOOT_SERVICES_APPLICATION",
    EV_EFI_GPT_EVENT: "EV_EFI_GPT_EVENT",
    EV_EFI_ACTION: "EV_EFI_ACTION",
    EV_EFI_PLATFORM_FIRMWARE_BLOB: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    EV_EFI_PLATFORM_FIRMWARE_BLOB2: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    EV_EFI_HANDOFF_TABLES2: "EV_EFI_HANDOFF_TABLES2",
    EV_PLATFORM_CONFIG_FLAGS: "EV_PLATFORM_CONFIG_FLAGS",
}


def event_type_name(event_type: int) -> str:
    return EVENT_TYPE_NAMES.get(event_type, f"UNKNOWN(0x{event_type:08X})")


def algo_name(algo_id: int) -> str:
    return ALGO_NAMES.get(algo_id, f"UNKNOWN(0x{algo_id:04X})")


# -- Data structures ----------------------------------------------------------


@dataclass
class Digest:
    """A single hash digest from an event log entry."""

    algo_id: int
    hash: bytes

    @property
    def hex(self) -> str:
        return self.hash.hex()


@dataclass
class EventLogEntry:
    """One event from the CCEL, corresponding to a single RTMR extend."""

    index: int
    imr_index: int  # RTMR index (0-3)
    event_type: int
    digests: list[Digest]
    event_data: bytes
    is_spec_id_event: bool = False

    @property
    def event_type_name(self) -> str:
        return event_type_name(self.event_type)

    @property
    def event_data_str(self) -> str:
        try:
            text = self.event_data.decode("utf-8").rstrip("\x00")
            if text and text.isprintable():
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        if len(self.event_data) >= 2 and len(self.event_data) % 2 == 0:
            try:
                text = self.event_data.decode("utf-16-le").rstrip("\x00")
                if text and text.isprintable():
                    return text
            except (UnicodeDecodeError, ValueError):
                pass
        return self.event_data.hex()

    def get_digest(self, algo_id: int = TPM_ALG_SHA384) -> Digest | None:
        for d in self.digests:
            if d.algo_id == algo_id:
                return d
        return None


@dataclass
class SpecIdEvent:
    """Header event declaring which hash algorithms the log uses."""

    signature: bytes
    platform_class: int
    spec_version_major: int
    spec_version_minor: int
    spec_errata: int
    uintn_size: int
    digest_sizes: list[tuple[int, int]]  # (algo_id, digest_byte_size) pairs


@dataclass
class ParsedEventLog:
    """Complete parsed CCEL containing the spec ID header and all events."""

    spec_id: SpecIdEvent | None
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
    result = ParsedEventLog(spec_id=None)
    offset = 0
    event_index = 0

    if len(data) < 32:
        raise ValueError(f"Event log too short ({len(data)} bytes)")

    entry, spec_id, offset = _parse_spec_id_event(data, offset, event_index)
    result.spec_id = spec_id
    result.events.append(entry)
    event_index += 1

    while offset < len(data):
        if offset + 4 > len(data):
            break
        peek_imr = struct.unpack_from("<I", data, offset)[0]
        if peek_imr == 0xFFFFFFFF:
            break

        entry, offset = _parse_event2(data, offset, event_index, result.spec_id)
        result.events.append(entry)
        event_index += 1

    return result


def parse_event_log_file(path: str | Path) -> ParsedEventLog:
    """Parse a CCEL event log from a file path."""
    return parse_event_log(Path(path).read_bytes())


def _parse_spec_id_event(
    data: bytes, offset: int, index: int
) -> tuple[EventLogEntry, SpecIdEvent, int]:
    """Parse the first event (TCG_PCClientPCREvent with 20-byte legacy digest)."""
    imr_raw = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    imr_index = imr_raw - 1

    event_type = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    legacy_digest = data[offset : offset + 20]
    offset += 20

    event_size = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    event_data = data[offset : offset + event_size]
    offset += event_size

    so = 0
    signature = event_data[so : so + 16]
    so += 16
    platform_class = struct.unpack_from("<I", event_data, so)[0]
    so += 4
    spec_version_minor = event_data[so]
    so += 1
    spec_version_major = event_data[so]
    so += 1
    spec_errata = event_data[so]
    so += 1
    uintn_size = event_data[so]
    so += 1
    num_algos = struct.unpack_from("<I", event_data, so)[0]
    so += 4

    digest_sizes: list[tuple[int, int]] = []
    for _ in range(num_algos):
        algo_id = struct.unpack_from("<H", event_data, so)[0]
        so += 2
        digest_size = struct.unpack_from("<H", event_data, so)[0]
        so += 2
        digest_sizes.append((algo_id, digest_size))

    spec_id = SpecIdEvent(
        signature=signature,
        platform_class=platform_class,
        spec_version_major=spec_version_major,
        spec_version_minor=spec_version_minor,
        spec_errata=spec_errata,
        uintn_size=uintn_size,
        digest_sizes=digest_sizes,
    )

    entry = EventLogEntry(
        index=index,
        imr_index=imr_index,
        event_type=event_type,
        digests=[Digest(algo_id=TPM_ALG_ERROR, hash=legacy_digest)],
        event_data=event_data,
        is_spec_id_event=True,
    )

    return entry, spec_id, offset


def _parse_event2(
    data: bytes, offset: int, index: int, spec_id: SpecIdEvent
) -> tuple[EventLogEntry, int]:
    """Parse a TCG_PCR_EVENT2 (multi-algorithm digest, variable-length)."""
    imr_raw = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    imr_index = imr_raw - 1

    event_type = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    digest_count = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    algo_sizes = {aid: dsz for aid, dsz in spec_id.digest_sizes}

    digests: list[Digest] = []
    for _ in range(digest_count):
        algo_id = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        dsz = algo_sizes.get(algo_id)
        if dsz is None:
            dsz = ALGO_DIGEST_SIZES.get(algo_id)
        if dsz is None:
            raise ValueError(
                f"Unknown algorithm 0x{algo_id:04X} at offset {offset - 2}"
            )

        digest_hash = data[offset : offset + dsz]
        offset += dsz
        digests.append(Digest(algo_id=algo_id, hash=digest_hash))

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
