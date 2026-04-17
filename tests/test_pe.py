"""Unit tests: PE/COFF parsing."""

from __future__ import annotations

import pytest

from cvm_measure.tdx.pe import pe_authenticode_digest, pe_extract_section, pe_list_sections


class TestPEValidation:

    def test_not_pe_raises(self) -> None:
        with pytest.raises(ValueError, match="MZ"):
            pe_authenticode_digest(b"not a pe file")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="MZ"):
            pe_authenticode_digest(b"")

    def test_extract_section_not_pe_returns_none(self) -> None:
        assert pe_extract_section(b"not a pe", ".text") is None

    def test_list_sections_not_pe_returns_empty(self) -> None:
        assert pe_list_sections(b"not a pe") == []
