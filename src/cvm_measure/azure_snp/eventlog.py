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

"""vTPM event log parsing and replay.

Parses the log at /sys/kernel/security/tpm0/binary_bios_measurements, which
records every PCR extend the firmware and boot chain performed.

The binary encoding is the TCG PC Client format handled by ``cvm_measure.tcg``.
What is specific to a vTPM log, and lives here, is that the header records the
PCR number directly rather than the index-plus-one a CCEL uses, that the file
is exactly sized so there is no table fill to tolerate, and that the bank
worth replaying is SHA-256.

Replaying this log reproduces every register the firmware and boot chain
measured, which is PCRs 0-7, 9 and 11. It will never reproduce **PCR 8**:
process-user-data extends that one from userspace with tpm2_pcrextend, long
after the log is closed, so it has no record here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..tcg import (
    EV_NO_ACTION,
    TPM_ALG_SHA256,
    Cursor,
    EventLogEntry,
    parse_events,
)

NUM_PCRS = 24
SHA256_SIZE = 32


@dataclass
class ParsedEventLog:
    """A complete parsed vTPM event log."""

    digest_sizes: list[tuple[int, int]]  # (algo_id, byte_size) from spec ID header
    events: list[EventLogEntry] = field(default_factory=list)

    @property
    def measurable_events(self) -> list[EventLogEntry]:
        return [e for e in self.events if e.event_type != EV_NO_ACTION]

    def events_for_pcr(self, pcr_index: int) -> list[EventLogEntry]:
        return [
            e for e in self.events
            if e.register_index == pcr_index and e.event_type != EV_NO_ACTION
        ]


def _validated_pcr_index(pcr_index: int, cursor: Cursor) -> int:
    """Reject an event addressed to a register the TPM does not have."""
    if pcr_index >= NUM_PCRS:
        raise ValueError(
            f"Event before offset {cursor.offset} records PCRIndex {pcr_index}, "
            f"but a TPM only has {NUM_PCRS} PCRs"
        )
    return pcr_index


def parse_event_log(data: bytes) -> ParsedEventLog:
    """Parse a raw binary_bios_measurements log into structured events.

    Raises ValueError on any log that is truncated, declares a length or count
    the buffer cannot hold, or carries bytes after its final event that are
    not the TCG terminator.
    """
    digest_sizes, events = parse_events(
        data,
        what="Event log",
        to_register_index=_validated_pcr_index,
        tolerate_padding=False,
    )
    return ParsedEventLog(digest_sizes=digest_sizes, events=events)


def replay_event_log(
    parsed: ParsedEventLog, algo_id: int = TPM_ALG_SHA256
) -> dict[int, bytes]:
    """Replay a parsed log, returning each PCR it touched.

    Registers the log never mentions are omitted rather than reported as
    zero, so a caller cannot mistake "never extended" for "measured as zero".
    """
    pcrs: dict[int, bytes] = {}

    for event in parsed.events:
        if event.event_type == EV_NO_ACTION:
            continue
        digest = event.digests.get(algo_id)
        if digest is None:
            continue
        current = pcrs.get(event.register_index, bytes(SHA256_SIZE))
        pcrs[event.register_index] = hashlib.sha256(current + digest).digest()

    return pcrs
