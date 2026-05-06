"""Unit tests for the private verification harness library."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashcat_rosetta._verify import (
    decide_rejection_status,
    load_baseword_corpus,
)


class TestLoadBasewordCorpus:
    def test_loads_value_field_only(self, tmp_path: Path) -> None:
        corpus_file = tmp_path / "basewords.json"
        corpus_file.write_text(
            json.dumps(
                [
                    {"value": "alpha", "purpose": "letters"},
                    {"value": "", "purpose": "empty"},
                    {"value": " pass", "purpose": "leading whitespace"},
                    {"value": "pass ", "purpose": "trailing whitespace"},
                ]
            )
        )

        result = load_baseword_corpus(corpus_file)

        assert result == ["alpha", "", " pass", "pass "]

    def test_rejects_missing_value_field(self, tmp_path: Path) -> None:
        corpus_file = tmp_path / "basewords.json"
        corpus_file.write_text(json.dumps([{"purpose": "no value"}]))

        with pytest.raises(ValueError, match="missing 'value'"):
            load_baseword_corpus(corpus_file)


class TestDecideRejectionStatus:
    def test_both_rejected_is_match(self) -> None:
        assert decide_rejection_status(True, True) == "match"

    def test_neither_rejected_falls_through(self) -> None:
        assert decide_rejection_status(False, False) == "needs_string_compare"

    def test_only_ours_rejected_is_mismatch(self) -> None:
        assert decide_rejection_status(True, False) == "mismatch"

    def test_only_hashcat_rejected_is_mismatch(self) -> None:
        assert decide_rejection_status(False, True) == "mismatch"
