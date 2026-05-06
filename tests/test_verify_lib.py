"""Unit tests for the private verification harness library."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hashcat_rosetta._verify import (
    VerifyResult,
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


class TestVerifyRuleIntegration:
    """End-to-end tests; require hashcat binary on PATH."""

    @pytest.mark.integration
    def test_simple_rule_matches(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("u", "password")
        if result.status == "skipped_hashcat":
            pytest.skip("hashcat binary not available")
        assert result.status == "match", f"got {result}"

    @pytest.mark.integration
    def test_filter_rejection_agreement(self) -> None:
        """When `!a` filter fires, both sides should agree on rejection."""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("!a", "password")
        if result.status == "skipped_hashcat":
            pytest.skip("hashcat binary not available")
        assert result.status == "match", (
            f"both should reject 'password' for rule '!a', got {result}"
        )

    @pytest.mark.integration
    def test_lparen_opcode_matches_hashcat_rejection(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        # `(` is now implemented (always rejects, matching hashcat v7.x behavior).
        result = verify_rule("(p", "password")
        if result.status == "skipped_hashcat":
            pytest.skip("hashcat binary not available")
        assert result.status == "match", (
            f"both sides should reject '(p' for 'password', got {result}"
        )


class TestVerifyCorpus:
    def test_aggregates_per_baseword(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from hashcat_rosetta import _verify as verify_mod

        def fake(rule: str, baseword: str, implemented=None) -> VerifyResult:
            # Match for "u", mismatch for "X1234" (any rule starting X), unimpl for "("
            if rule.startswith("X"):
                return VerifyResult(
                    status="mismatch",
                    rule=rule,
                    baseword=baseword,
                    ours="A",
                    hashcat="B",
                )
            if rule.startswith("("):
                return VerifyResult(
                    status="skipped_unimpl",
                    rule=rule,
                    baseword=baseword,
                    unimpl_opcodes=["("],
                )
            return VerifyResult(status="match", rule=rule, baseword=baseword)

        monkeypatch.setattr(verify_mod, "verify_rule", fake)

        report = verify_mod.verify_corpus(
            rules=["u", "X1234", "(p"],
            basewords=["alpha", "beta"],
            workers=2,
        )

        assert len(report.rounds) == 2
        assert report.total_tested == 4  # 2 basewords * (1 match + 1 mismatch)
        assert report.total_matched == 2
        assert report.total_mismatches == 2
        for round_result in report.rounds:
            assert round_result["skipped_unimplemented"] == 1
