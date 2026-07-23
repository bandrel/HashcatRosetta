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


class TestHashcatUnsupportedOpcodes:
    """Rules using M or X are silently rejected by hashcat --stdout in 6.2.6+;
    treat them as unverifiable rather than mismatches."""

    def test_filter_opcode_is_unsupported(self) -> None:
        """Pure-filter rules (e.g. `!a`) cannot be verified via hashcat
        --stdout: hashcat refuses to compile a filter-only rule ("No valid
        rules left", exit 255) whether or not the filter would pass, so it
        emits no candidate to compare against. The harness classifies these as
        unverifiable rather than issuing a hashcat call."""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("!a", "password")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_M_alone_is_unsupported(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("M", "password")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_X_alone_is_unsupported(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("X005", "password")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_chained_rule_with_X_is_unsupported(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("u X005", "password")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_chained_rule_with_M_is_unsupported(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("M u", "password")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_unknown_opcode_is_unsupported(self) -> None:
        """Digits like 4/5/6/7 (JtR-only opcodes) emitted by hashcat-utils
        generate-rules but rejected by hashcat itself."""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("4", "password")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_truncated_two_arg_opcode_is_unsupported(self) -> None:
        """Hashcat rejects rules with malformed opcodes (e.g. 's.' lacking Y);
        our parser silently drops them, so we'd otherwise report a mismatch."""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("*A9 o6= s.", "admin")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_complete_rule_is_not_flagged_as_truncated(self) -> None:
        """Sanity: well-formed rules should not be flagged as truncated."""
        from hashcat_rosetta._verify import _has_truncated_opcode

        assert not _has_truncated_opcode("u")
        assert not _has_truncated_opcode("$a")
        assert not _has_truncated_opcode("sab")
        assert not _has_truncated_opcode("u $a sab")
        assert _has_truncated_opcode("s.")
        assert _has_truncated_opcode("u s.")
        assert _has_truncated_opcode("$")


class TestExtractFinal:
    """_extract_final must preserve leading/trailing whitespace in the final
    candidate. Hashcat preserves whitespace in basewords through rules; if we
    .strip() the result, every whitespace-bearing baseword becomes a spurious
    mismatch."""

    def test_preserves_trailing_whitespace(self) -> None:
        from hashcat_rosetta._verify import _extract_final

        steps = ["^L: Prepend 'L' \u2192 pass  \u2192 Lpass "]
        assert _extract_final(steps) == "Lpass "

    def test_preserves_leading_whitespace(self) -> None:
        from hashcat_rosetta._verify import _extract_final

        steps = ["u: Uppercase \u2192  pass \u2192  PASS"]
        assert _extract_final(steps) == " PASS"

    def test_empty_final(self) -> None:
        from hashcat_rosetta._verify import _extract_final

        steps = ["'0: Truncate at pos 0 \u2192 admin \u2192 "]
        assert _extract_final(steps) == ""

    def test_no_arrow_returns_line_as_is(self) -> None:
        from hashcat_rosetta._verify import _extract_final

        assert _extract_final(["already final"]) == "already final"

    def test_empty_list_or_none(self) -> None:
        from hashcat_rosetta._verify import _extract_final

        assert _extract_final([]) == ""
        assert _extract_final(None) == ""


class TestEmptyFinalRejectionParity:
    """When our explanation extracts to '', that's functionally a rejection
    (no candidate produced). Hashcat treats empty results as filter-rejections
    in --stdout mode, so the harness should as well."""

    def test_truncate_to_zero_matches_hashcat_rejection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from hashcat_rosetta import _verify as verify_mod
        from hashcat_rosetta._verify import verify_rule

        # Stub hashcat to "reject" (exit-255 path returns "")
        monkeypatch.setattr(verify_mod, "_hashcat_output", lambda r, b: ("", False))

        # Rule "'0" truncates baseword to length 0 -> our_final is "".
        # Both sides reject -> match (parity with hashcat filter).
        result = verify_rule("'0", "admin")
        assert result.status == "match", f"got {result}"


class TestOOBPositionSkip:
    """Hashcat rejects rules where a positional arg exceeds the word length
    at that step. Our parser silently no-ops, producing spurious mismatches.
    The harness should skip these rules per-baseword."""

    def test_swap_with_oob_position_is_skipped(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        # *B2 = swap pos 11 with pos 2; cat is only 3 chars, pos 11 OOB.
        result = verify_rule("*B2 p2", "cat")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_toggle_with_oob_position_is_skipped(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        # T9 = toggle pos 9 on 'cat' (3 chars) — OOB.
        result = verify_rule("T9", "cat")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_insert_with_oob_position_is_skipped(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        # i9X = insert 'X' at pos 9 on 'cat' — OOB.
        result = verify_rule("i9X", "cat")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"

    def test_length_doubling_op_makes_later_position_valid(self) -> None:
        """Length simulation: 'd' doubles 'cat' to 6 chars, so pos 5 is now in
        range. Should NOT be skipped."""
        from hashcat_rosetta._verify import _has_oob_position

        # *25 on 'cat' alone: pos 5 >= 3 → OOB
        assert _has_oob_position("*25", "cat") is True
        # d then *25: after d, len=6, pos 5 < 6 → in bounds
        assert _has_oob_position("d *25", "cat") is False

    def test_truncate_makes_later_position_oob(self) -> None:
        """Length simulation: ''3' truncates to 3 chars; subsequent pos 5 is
        then OOB even if it would have been in range originally."""
        from hashcat_rosetta._verify import _has_oob_position

        # On 'password' (8 chars), pos 5 is in bounds alone.
        assert _has_oob_position("T5", "password") is False
        # After '3 truncates to 3 chars, pos 5 is OOB.
        assert _has_oob_position("'3 T5", "password") is True

    def test_in_bounds_position_is_not_skipped(self) -> None:
        from hashcat_rosetta._verify import _has_oob_position

        assert _has_oob_position("T0", "cat") is False
        assert _has_oob_position("T2", "cat") is False  # last valid pos
        assert _has_oob_position("*01", "cat") is False
        assert _has_oob_position("u $a", "cat") is False


class TestHexValueHelper:
    def test_digit(self) -> None:
        from hashcat_rosetta._verify import _hex_value

        assert _hex_value("0") == 0
        assert _hex_value("9") == 9

    def test_uppercase_letter(self) -> None:
        from hashcat_rosetta._verify import _hex_value

        assert _hex_value("A") == 10
        assert _hex_value("B") == 11
        assert _hex_value("Z") == 35

    def test_non_position_char_returns_none(self) -> None:
        from hashcat_rosetta._verify import _hex_value

        assert _hex_value("a") is None  # lowercase
        assert _hex_value("$") is None
        assert _hex_value("") is None
        assert _hex_value("AB") is None


class TestEmptyBasewordSkip:
    """Empty basewords are not hashcat candidates; the harness must skip them
    before issuing any hashcat call so the result doesn't depend on whether
    hashcat happens to return "" or None for empty stdin."""

    def test_empty_baseword_is_skipped(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("$a", "")
        assert result.status == "skipped_hashcat_unsupported", f"got {result}"


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
