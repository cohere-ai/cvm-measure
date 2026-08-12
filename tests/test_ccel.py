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

"""Unit tests: CCEL event log parser."""

from __future__ import annotations

import struct

import pytest

from cvm_measure.tdx.ccel import (
    EV_EFI_ACTION,
    EV_NO_ACTION,
    SPEC_ID_SIGNATURE,
    TPM_ALG_SHA384,
    parse_event_log,
)

SHA384 = (TPM_ALG_SHA384, 48)


def build_spec_id_event(
    algos: list[tuple[int, int]] | None = None,
    *,
    mr_index: int = 1,
    signature: bytes = SPEC_ID_SIGNATURE,
    vendor_info: bytes = b"",
    declared_algos: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    """Build a TCG_PCClientPCREvent carrying a SpecIdEvent payload."""
    if algos is None:
        algos = [SHA384]

    payload = signature.ljust(16, b"\x00")
    payload += struct.pack("<I", 0)  # PlatformClass
    payload += bytes([0, 2, 0, 2])  # spec minor, major, errata, uintnSize
    payload += struct.pack("<I", len(algos) if declared_algos is None else declared_algos)
    for algo_id, digest_size in algos:
        payload += struct.pack("<HH", algo_id, digest_size)
    payload += bytes([len(vendor_info)]) + vendor_info + trailing

    return (
        struct.pack("<II", mr_index, EV_NO_ACTION)
        + bytes(20)
        + struct.pack("<I", len(payload))
        + payload
    )


def build_event2(
    *,
    mr_index: int = 2,
    event_type: int = EV_EFI_ACTION,
    digests: list[tuple[int, bytes]] | None = None,
    event_data: bytes = b"data",
    declared_digest_count: int | None = None,
    declared_event_size: int | None = None,
) -> bytes:
    """Build a TCG_PCR_EVENT2 record."""
    if digests is None:
        digests = [(TPM_ALG_SHA384, bytes(48))]

    count = len(digests) if declared_digest_count is None else declared_digest_count
    out = struct.pack("<III", mr_index, event_type, count)
    for algo_id, digest in digests:
        out += struct.pack("<H", algo_id) + digest
    size = len(event_data) if declared_event_size is None else declared_event_size
    return out + struct.pack("<I", size) + event_data


class TestCCELParser:

    def test_parse_spec_id(self, ccel_data_a3: bytes) -> None:
        log = parse_event_log(ccel_data_a3)
        assert len(log.digest_sizes) > 0

    def test_all_events_have_sha384(self, ccel_data_a3: bytes) -> None:
        log = parse_event_log(ccel_data_a3)
        for event in log.measurable_events:
            d = event.digests.get(TPM_ALG_SHA384)
            assert d is not None, f"Event {event.index} missing SHA-384 digest"
            assert len(d) == 48

    def test_parse_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse_event_log(b"")

    def test_parse_too_small_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse_event_log(b"\x00" * 16)

    def test_parses_synthetic_log(self) -> None:
        data = build_spec_id_event() + build_event2(mr_index=2)
        log = parse_event_log(data)
        assert log.digest_sizes == [SHA384]
        assert [e.imr_index for e in log.events] == [0, 1]

    @pytest.mark.parametrize("pad", [b"\xff", b"\x00"])
    def test_accepts_table_padding_after_last_event(self, pad: bytes) -> None:
        data = build_spec_id_event() + build_event2() + pad * 4096
        log = parse_event_log(data)
        assert len(log.events) == 2


class TestDeclaredLengthValidation:
    """Declared lengths and counts are untrusted: slices must not truncate."""

    def test_rejects_partial_trailing_event_header(self) -> None:
        data = build_spec_id_event() + build_event2()[:8]
        with pytest.raises(ValueError, match="unparsed byte"):
            parse_event_log(data)

    def test_rejects_truncated_digest(self) -> None:
        data = build_spec_id_event() + build_event2(
            digests=[(TPM_ALG_SHA384, bytes(20))]
        )
        with pytest.raises(ValueError, match="truncated.*digest"):
            parse_event_log(data)

    def test_rejects_event_size_past_end_of_buffer(self) -> None:
        data = build_spec_id_event() + build_event2(declared_event_size=1 << 20)
        with pytest.raises(ValueError, match="truncated.*event data"):
            parse_event_log(data)

    def test_rejects_spec_id_payload_past_end_of_buffer(self) -> None:
        event = bytearray(build_spec_id_event())
        struct.pack_into("<I", event, 28, 1 << 20)
        with pytest.raises(ValueError, match="truncated.*SpecIdEvent payload"):
            parse_event_log(bytes(event))

    def test_rejects_digest_count_larger_than_buffer(self) -> None:
        data = build_spec_id_event() + build_event2(declared_digest_count=0xFFFFFFFF)
        with pytest.raises(ValueError, match="declares 4294967295 digest"):
            parse_event_log(data)

    def test_rejects_algorithm_count_larger_than_payload(self) -> None:
        data = build_spec_id_event(declared_algos=0xFFFF)
        with pytest.raises(ValueError, match="declares 65535 algorithm"):
            parse_event_log(data)

    def test_rejects_trailing_bytes_after_last_event(self) -> None:
        data = build_spec_id_event() + build_event2() + b"leftover"
        with pytest.raises(ValueError, match="unparsed byte"):
            parse_event_log(data)

    def test_rejects_trailing_bytes_after_terminator(self) -> None:
        data = (
            build_spec_id_event()
            + build_event2()
            + struct.pack("<I", 0xFFFFFFFF)
            + b"leftover"
        )
        with pytest.raises(ValueError, match="unparsed byte"):
            parse_event_log(data)


class TestSpecIdValidation:

    def test_rejects_wrong_signature(self) -> None:
        with pytest.raises(ValueError, match="not a SpecIdEvent"):
            parse_event_log(build_spec_id_event(signature=b"Not A Spec Ev\x00"))

    def test_rejects_no_algorithms(self) -> None:
        with pytest.raises(ValueError, match="no digest algorithms"):
            parse_event_log(build_spec_id_event(algos=[]))

    def test_rejects_wrong_size_for_known_algorithm(self) -> None:
        with pytest.raises(ValueError, match="48-byte digest"):
            parse_event_log(build_spec_id_event(algos=[(TPM_ALG_SHA384, 47)]))

    def test_rejects_zero_digest_size(self) -> None:
        with pytest.raises(ValueError, match="unusable digest size"):
            parse_event_log(build_spec_id_event(algos=[(0x7F00, 0)]))

    def test_rejects_oversized_digest_size(self) -> None:
        with pytest.raises(ValueError, match="unusable digest size"):
            parse_event_log(build_spec_id_event(algos=[(0x7F00, 4096)]))

    def test_rejects_duplicate_algorithm(self) -> None:
        with pytest.raises(ValueError, match="twice"):
            parse_event_log(build_spec_id_event(algos=[SHA384, SHA384]))

    def test_rejects_payload_longer_than_declared_fields(self) -> None:
        with pytest.raises(ValueError, match="beyond its declared fields"):
            parse_event_log(build_spec_id_event(trailing=b"extra"))

    def test_accepts_vendor_info(self) -> None:
        log = parse_event_log(build_spec_id_event(vendor_info=b"vendor"))
        assert log.digest_sizes == [SHA384]


class TestEventValidation:

    def test_rejects_unknown_algorithm(self) -> None:
        data = build_spec_id_event() + build_event2(digests=[(0x7F00, bytes(48))])
        with pytest.raises(ValueError, match="Unknown algorithm"):
            parse_event_log(data)

    def test_rejects_repeated_algorithm_in_one_event(self) -> None:
        data = build_spec_id_event() + build_event2(
            digests=[(TPM_ALG_SHA384, bytes(48)), (TPM_ALG_SHA384, bytes(48))]
        )
        with pytest.raises(ValueError, match="repeats algorithm"):
            parse_event_log(data)

    def test_rejects_mr_index_beyond_tdx_registers(self) -> None:
        data = build_spec_id_event() + build_event2(mr_index=9)
        with pytest.raises(ValueError, match="measurement register"):
            parse_event_log(data)

    def test_rejects_measured_event_outside_the_rtmrs(self) -> None:
        data = build_spec_id_event() + build_event2(mr_index=0)
        with pytest.raises(ValueError, match="not an RTMR"):
            parse_event_log(data)

    def test_allows_no_action_event_outside_the_rtmrs(self) -> None:
        """SP800-155 records sit at MrIndex 0 and are never extended."""
        data = build_spec_id_event() + build_event2(
            mr_index=0, event_type=EV_NO_ACTION
        )
        log = parse_event_log(data)
        assert log.events[1].imr_index == -1
        assert log.measurable_events == []
