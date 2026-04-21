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

"""Replay CCEL event log to recreate RTMR[0-3] values.

The extend operation is: RTMR_new = SHA-384(RTMR_old || digest)
Starting from all-zeros, replaying every extend event should reproduce
the exact RTMR values reported by the TDX hardware.
"""

from __future__ import annotations

import hashlib

from .ccel import EV_NO_ACTION, TPM_ALG_SHA384, EventLogEntry, ParsedEventLog

NUM_RTMRS = 4
SHA384_SIZE = 48


def replay_events(
    events: list[EventLogEntry],
    algo_id: int = TPM_ALG_SHA384,
) -> dict[int, bytes]:
    """Replay event log entries to compute RTMR values.

    Returns a dict mapping RTMR index to its 48-byte digest.
    """
    rtmrs = {i: bytes(SHA384_SIZE) for i in range(NUM_RTMRS)}

    for event in events:
        if event.event_type == EV_NO_ACTION:
            continue
        digest = event.digests.get(algo_id)
        if digest is None:
            continue
        imr = event.imr_index
        if not (0 <= imr < NUM_RTMRS):
            continue
        rtmrs[imr] = hashlib.sha384(rtmrs[imr] + digest).digest()

    return rtmrs


def replay_event_log(parsed: ParsedEventLog, algo_id: int = TPM_ALG_SHA384) -> dict[int, bytes]:
    """Replay a complete parsed event log."""
    return replay_events(parsed.events, algo_id)


def extend_rtmr(current: bytes, digest: bytes) -> bytes:
    """Single RTMR extend: SHA-384(current || digest)."""
    return hashlib.sha384(current + digest).digest()


def replay_digests(digests: list[bytes]) -> bytes:
    """Replay a sequence of raw SHA-384 digests from an initial zero state."""
    rtmr = bytes(SHA384_SIZE)
    for d in digests:
        rtmr = hashlib.sha384(rtmr + d).digest()
    return rtmr
