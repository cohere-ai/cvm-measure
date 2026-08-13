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

"""Unit tests: RTMR extend and replay operations."""

from __future__ import annotations

import hashlib

from cvm_measure.tdx.rtmr import SHA384_SIZE, extend_rtmr, replay_digests


class TestExtendRTMR:

    def test_extend_from_zeros(self) -> None:
        zeros = bytes(SHA384_SIZE)
        digest = hashlib.sha384(b"test").digest()
        result = extend_rtmr(zeros, digest)
        expected = hashlib.sha384(zeros + digest).digest()
        assert result == expected

    def test_extend_is_deterministic(self) -> None:
        current = hashlib.sha384(b"state").digest()
        digest = hashlib.sha384(b"event").digest()
        a = extend_rtmr(current, digest)
        b = extend_rtmr(current, digest)
        assert a == b

    def test_extend_order_matters(self) -> None:
        d1 = hashlib.sha384(b"first").digest()
        d2 = hashlib.sha384(b"second").digest()
        zeros = bytes(SHA384_SIZE)
        r1 = extend_rtmr(extend_rtmr(zeros, d1), d2)
        r2 = extend_rtmr(extend_rtmr(zeros, d2), d1)
        assert r1 != r2


class TestReplayDigests:

    def test_replay_single(self) -> None:
        digest = hashlib.sha384(b"hello").digest()
        result = replay_digests([digest])
        expected = hashlib.sha384(bytes(SHA384_SIZE) + digest).digest()
        assert result == expected

    def test_replay_empty(self) -> None:
        result = replay_digests([])
        assert result == bytes(SHA384_SIZE)

    def test_replay_multiple(self) -> None:
        d1 = hashlib.sha384(b"a").digest()
        d2 = hashlib.sha384(b"b").digest()
        result = replay_digests([d1, d2])
        step1 = hashlib.sha384(bytes(SHA384_SIZE) + d1).digest()
        expected = hashlib.sha384(step1 + d2).digest()
        assert result == expected


class TestReplayFromCCEL:
    """Tests that require a CCEL fixture binary."""

    def test_rtmr0_matches_golden(self, ccel_data_a3: bytes, golden_a3) -> None:
        from cvm_measure.tdx.ccel import parse_event_log
        from cvm_measure.tdx.rtmr import replay_event_log

        log = parse_event_log(ccel_data_a3)
        rtmrs = replay_event_log(log)
        assert rtmrs[0].hex() == golden_a3.rtmr0

    def test_rtmr1_matches_golden(self, ccel_data_a3: bytes, golden_a3) -> None:
        from cvm_measure.tdx.ccel import parse_event_log
        from cvm_measure.tdx.rtmr import replay_event_log

        log = parse_event_log(ccel_data_a3)
        rtmrs = replay_event_log(log)
        assert rtmrs[1].hex() == golden_a3.rtmr1

    def test_rtmr2_matches_golden(self, ccel_data_a3: bytes, golden_a3) -> None:
        from cvm_measure.tdx.ccel import parse_event_log
        from cvm_measure.tdx.rtmr import replay_event_log

        log = parse_event_log(ccel_data_a3)
        rtmrs = replay_event_log(log)
        assert rtmrs[2].hex() == golden_a3.rtmr2

    def test_rtmr3_zero_in_ccel(self, ccel_data_a3: bytes) -> None:
        from cvm_measure.tdx.ccel import parse_event_log
        from cvm_measure.tdx.rtmr import replay_event_log

        log = parse_event_log(ccel_data_a3)
        rtmrs = replay_event_log(log)
        assert rtmrs[3] == bytes(SHA384_SIZE)

    def test_event_counts(self, ccel_data_a3: bytes) -> None:
        from cvm_measure.tdx.ccel import parse_event_log

        log = parse_event_log(ccel_data_a3)
        assert len(log.events_for_rtmr(0)) == 16
        assert len(log.events_for_rtmr(1)) == 7
        assert len(log.events_for_rtmr(2)) == 12
        assert len(log.events_for_rtmr(3)) == 0
