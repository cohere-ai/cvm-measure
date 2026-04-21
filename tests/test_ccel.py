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

import pytest

from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log


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
