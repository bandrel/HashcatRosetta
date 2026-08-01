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
    """CPU-only opcodes (filters, M, X) are routed to the `-j` CPU oracle
    (Task 2) instead of being skipped, since `-r` (GPU) refuses to compile
    them at all. Genuinely unknown/malformed rules and out-of-bounds
    positions are still skipped."""

    def test_filter_opcode_is_verified_via_cpu_oracle(self) -> None:
        """Pure-filter rules (e.g. `!a`) can't be compiled by hashcat's `-r`
        (GPU) rule engine at all ("No valid rules left", exit 255), but `-j`
        (CPU) compiles and runs them. Task 2 routes filter opcodes to the CPU
        oracle instead of skipping them, so this is a real comparison now."""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("!a", "password")
        assert result.status != "skipped_hashcat_unsupported", f"got {result}"

    def test_M_alone_is_verified_via_cpu_oracle(self) -> None:
        """M is CPU-only and now routed to the -j oracle instead of being
        skipped. (It currently mismatches — the `explain_rule` step string
        for M isn't in the "<desc> -> <prev> -> <current>" shape _extract_final
        expects — but that bug is out of scope for this task.)"""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("M", "password")
        assert result.status != "skipped_hashcat_unsupported", f"got {result}"

    def test_X_alone_is_verified_via_cpu_oracle(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("X005", "password")
        assert result.status != "skipped_hashcat_unsupported", f"got {result}"

    def test_chained_rule_with_X_is_verified_via_cpu_oracle(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("u X005", "password")
        assert result.status != "skipped_hashcat_unsupported", f"got {result}"

    def test_chained_rule_with_M_is_verified_via_cpu_oracle(self) -> None:
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("M u", "password")
        assert result.status != "skipped_hashcat_unsupported", f"got {result}"

    def test_unknown_opcode_is_unsupported(self) -> None:
        """Digits like 5/7 (JtR-only opcodes) emitted by hashcat-utils
        generate-rules but rejected by hashcat itself. (4/6 are now real
        memory opcodes — see TestMemoryOpcodes — so they no longer serve as
        an example of an unknown opcode.)"""
        from hashcat_rosetta._verify import verify_rule

        result = verify_rule("5", "password")
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

    def test_space_is_a_valid_argument_not_truncation(self) -> None:
        """A space is a valid literal argument (e.g. decoded from \\x20), not a
        truncation marker. hashcat accepts '$ ' (append space) and 's _'
        (substitute space->_); only running off the end is real truncation."""
        from hashcat_rosetta._verify import _has_truncated_opcode

        assert not _has_truncated_opcode("s _")  # substitute space -> _
        assert not _has_truncated_opcode("$ ")  # append space
        assert not _has_truncated_opcode("i0 ")  # insert space at pos 0
        # trailing opcode still missing its args at end-of-string is truncated
        assert _has_truncated_opcode("s _ i1")


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
        monkeypatch.setattr(verify_mod, "_hashcat_output", lambda r, b, engine="gpu": ("", False))

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

    def test_3_position_encoding_validated_but_not_oob(self) -> None:
        """3NX's N is a position-ENCODED occurrence index: hashcat rejects an
        invalid encoding (lowercase 'a') but never rejects it as out-of-bounds
        (an occurrence index beyond the separators is a silent no-op)."""
        from hashcat_rosetta._verify import _has_invalid_position_arg, _has_oob_position

        assert _has_invalid_position_arg("3ab") is True  # 'a' is not 0-9/A-Z
        assert _has_invalid_position_arg("30s") is False
        assert _has_invalid_position_arg("3Az") is False  # 'A' = position 10
        # occurrence index far beyond the word is NOT out-of-bounds for '3'
        assert _has_oob_position("3Zs", "password") is False


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
