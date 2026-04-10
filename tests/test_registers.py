"""Unit tests: offline register computation and constants."""

from __future__ import annotations

import hashlib
import struct

import pytest

from cvm_measure.tdx.registers import EFI_ACTION_DIGESTS, SEPARATOR_DIGEST
from cvm_measure.tdx.rtmr import SHA384_SIZE, replay_digests


class TestConstants:

    def test_separator_digest_is_sha384_of_zero_u32(self) -> None:
        expected = hashlib.sha384(struct.pack("<I", 0)).digest()
        assert SEPARATOR_DIGEST == expected

    def test_efi_action_constants_correct(self) -> None:
        for name, digest in EFI_ACTION_DIGESTS.items():
            expected = hashlib.sha384(name.encode("ascii")).digest()
            assert digest == expected, f"EFI action constant mismatch for {name}"

    def test_separator_digest_length(self) -> None:
        assert len(SEPARATOR_DIGEST) == SHA384_SIZE


class TestRTMR3:

    def test_rtmr3_extend(self) -> None:
        from cvm_measure.tdx.rtmr import extend_rtmr
        fake_digest = hashlib.sha384(b"test initdata").digest()
        result = extend_rtmr(bytes(SHA384_SIZE), fake_digest)
        expected = hashlib.sha384(bytes(SHA384_SIZE) + fake_digest).digest()
        assert result == expected

    def test_rtmr3_defaults_to_zeros(self) -> None:
        assert bytes(SHA384_SIZE).hex() == "0" * 96


class TestRTMR0FromCCEL:
    """Verify RTMR[0] computed from baseline + CCEL matches golden."""

    def test_rtmr0_matches_golden(self, baseline_a3, golden_a3, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log
        from cvm_measure.tdx.uefi import compute_secureboot_digest

        log = parse_event_log(ccel_data_a3)
        cfv_event = None
        for e in log.events_for_rtmr(0):
            if "PLATFORM_FIRMWARE" in e.event_type_name:
                d = e.get_digest(TPM_ALG_SHA384)
                if d:
                    cfv_event = d.hash
                    break

        assert cfv_event is not None, "No CFV event found in CCEL"

        baseline_events = baseline_a3.rtmr_events(0)
        sb_flag_data = b"\x01" if baseline_a3.secureboot_enabled else b"\x00"

        digests = []
        bi = 0
        digests.append(bytes.fromhex(baseline_events[bi].digest)); bi += 1
        digests.append(cfv_event)
        digests.append(compute_secureboot_digest("SecureBoot", sb_flag_data))
        for _ in range(4):
            digests.append(bytes.fromhex(baseline_events[bi].digest)); bi += 1
        digests.append(SEPARATOR_DIGEST)
        while bi < len(baseline_events):
            digests.append(bytes.fromhex(baseline_events[bi].digest)); bi += 1

        rtmr0 = replay_digests(digests).hex()
        assert rtmr0 == golden_a3.rtmr0


class TestRTMR1FromCCEL:

    def test_rtmr1_from_constants_and_baseline(self, baseline_a3, golden_a3, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log

        log = parse_event_log(ccel_data_a3)
        rtmr1_events = log.events_for_rtmr(1)
        ccel_digests = [e.get_digest(TPM_ALG_SHA384).hash for e in rtmr1_events]
        gpt_digest = bytes.fromhex(baseline_a3.rtmr_events(1)[0].digest)

        digests = [
            EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
            SEPARATOR_DIGEST,
            gpt_digest,
            ccel_digests[3],
            ccel_digests[4],
            EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
            EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
        ]

        rtmr1 = replay_digests(digests).hex()
        assert rtmr1 == golden_a3.rtmr1


class TestRTMR2FromCCEL:

    def test_rtmr2_from_ccel_matches_golden(self, golden_a3, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log

        log = parse_event_log(ccel_data_a3)
        digests = [e.get_digest(TPM_ALG_SHA384).hash for e in log.events_for_rtmr(2)]
        rtmr2 = replay_digests(digests).hex()
        assert rtmr2 == golden_a3.rtmr2

    def test_rtmr2_section_name_digests_are_constants(self, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import parse_event_log

        log = parse_event_log(ccel_data_a3)
        events = log.events_for_rtmr(2)
        sections = [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"]

        for i, section in enumerate(sections):
            name_event = events[i * 2]
            from cvm_measure.tdx.ccel import TPM_ALG_SHA384
            expected = hashlib.sha384((section + "\0").encode("ascii")).digest()
            actual = name_event.get_digest(TPM_ALG_SHA384).hash
            assert actual == expected, f"Section name mismatch for {section}"
