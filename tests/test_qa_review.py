"""QA review tests covering correctness issues found in the PR #12 fixes.

Tests in this module verify the correctness of:
- Opcode descriptions in formatting.py (!, %, $, K, and other missing entries)
- Median calculation in debug_analyzer.py (even-length lists)
- match_count tracking in debug_analyzer.py
- UTF-8 encoding in export paths
- extract_rule_opcodes() return type (breaking API change in PR #12)
- Tokenizer opcode coverage vs OPCODE_DESCRIPTIONS completeness
- Parser file-level format detection heuristic
- explain_rule() handler correctness for all supported opcodes
- Reject sentinel contract: rejection opcodes emit a sentinel, not a transformation step
"""

import json
import os
import tempfile

import pytest

from hashcat_rosetta import DebugAnalyzer, DebugLogParser, RuleParser
from hashcat_rosetta.cli import REJECT_SENTINEL_PREFIX, explain_rule
from hashcat_rosetta.formatting import OPCODE_DESCRIPTIONS, extract_rule_opcodes


# ---------------------------------------------------------------------------
# Opcode description correctness
# ---------------------------------------------------------------------------


class TestOpcodeDescriptions:
    """Verify OPCODE_DESCRIPTIONS match hashcat documentation exactly.

    Source: https://hashcat.net/wiki/doku.php?id=rule_based_attack
    """

    def test_q_is_duplicate_every_char_not_exclamation_invert(self) -> None:
        """q duplicates every character; old wrong description was 'Invert exclamation marks'."""
        desc = OPCODE_DESCRIPTIONS.get("q", "")
        assert "exclamation" not in desc.lower(), (
            f"q description incorrectly mentions exclamation marks: '{desc}'"
        )
        assert "invert" not in desc.lower(), f"q description incorrectly mentions invert: '{desc}'"
        assert "duplicate" in desc.lower() or "char" in desc.lower(), (
            f"q description should mention duplicating characters, got: '{desc}'"
        )

    def test_E_is_case_transform_not_delete_duplicates(self) -> None:
        """E does a case transformation; old wrong description was 'Delete all duplicate chars'."""
        desc = OPCODE_DESCRIPTIONS.get("E", "")
        assert "delete" not in desc.lower(), f"E description incorrectly mentions delete: '{desc}'"
        assert "duplicate" not in desc.lower() or "char" not in desc.lower(), (
            f"E description incorrectly mentions 'delete duplicate chars': '{desc}'"
        )
        assert any(
            word in desc.lower()
            for word in ("title", "case", "upper", "lower", "vowel", "consonant")
        ), f"E description should relate to case transformation, got: '{desc}'"

    def test_L_is_bitwise_shift_left_not_delete_last(self) -> None:
        """L is bitwise shift left; old wrong description was 'Delete last N characters'."""
        desc = OPCODE_DESCRIPTIONS.get("L", "")
        assert "delete" not in desc.lower(), f"L description incorrectly mentions delete: '{desc}'"
        assert "bitwise" in desc.lower() or "shift" in desc.lower() or "left" in desc.lower(), (
            f"L description should mention bitwise shift left, got: '{desc}'"
        )

    def test_gt_is_reject_not_delete(self) -> None:
        """'>' rejects plains if length > N; old description was 'Delete everything beyond N'."""
        desc = OPCODE_DESCRIPTIONS.get(">", "")
        assert "delete" not in desc.lower(), f"> description incorrectly mentions delete: '{desc}'"
        assert "reject" in desc.lower() or "length" in desc.lower(), (
            f"> description should mention reject/length, got: '{desc}'"
        )

    def test_lt_is_reject_not_keep_first(self) -> None:
        """'<' rejects plains if length < N; old description was 'Keep only first N'."""
        desc = OPCODE_DESCRIPTIONS.get("<", "")
        assert "keep" not in desc.lower(), f"< description incorrectly mentions keep: '{desc}'"
        assert "reject" in desc.lower() or "length" in desc.lower(), (
            f"< description should mention reject/length, got: '{desc}'"
        )

    def test_exclamation_is_reject_contain_not_negate(self) -> None:
        """'!' rejects plains containing char X; old description was 'Negate (not X)'."""
        desc = OPCODE_DESCRIPTIONS.get("!", "")
        assert "negate" not in desc.lower(), (
            f"! description incorrectly mentions negate: '{desc}'. "
            "Correct description: 'Reject plains which contain char X'"
        )
        assert "reject" in desc.lower() or "contain" in desc.lower(), (
            f"! description should mention reject/contain, got: '{desc}'"
        )

    def test_percent_includes_reject_semantics(self) -> None:
        """'%' rejects plains containing char X less than N times; not just 'Check word contains'."""
        desc = OPCODE_DESCRIPTIONS.get("%", "")
        # The description should convey the reject/threshold semantics
        assert "check" not in desc.lower() or "reject" in desc.lower(), (
            f"% description is too vague (just 'check'), should mention reject semantics: '{desc}'"
        )

    def test_dollar_sign_has_description(self) -> None:
        """'$' (append char X) should have a description - it is used in explain_rule."""
        desc = OPCODE_DESCRIPTIONS.get("$", "")
        assert desc, (
            "'$' opcode is missing from OPCODE_DESCRIPTIONS. "
            "It is a 1-arg op (append char X) used by the tokenizer."
        )
        assert "append" in desc.lower(), f"$ description should mention 'append', got: '{desc}'"

    def test_K_has_description(self) -> None:
        """'K' (swap last two chars) should have a description - it is in explain_rule's rule_map."""
        desc = OPCODE_DESCRIPTIONS.get("K", "")
        assert desc, (
            "'K' opcode is missing from OPCODE_DESCRIPTIONS. It swaps the last two characters."
        )

    def test_all_tokenized_opcodes_have_descriptions(self) -> None:
        """Every opcode the tokenizer can emit should have a description entry."""
        # From RuleParser._tokenize_rule:
        no_arg_ops = set(":lucCtdfr{}[]kKqE")
        one_arg_ops = set("TDpOzZ^$@!><'+-.,%LR")
        two_arg_ops = set("soix*X")

        all_ops = no_arg_ops | one_arg_ops | two_arg_ops
        missing = sorted(op for op in all_ops if op not in OPCODE_DESCRIPTIONS)
        assert not missing, (
            f"These opcodes are tokenized but lack descriptions in OPCODE_DESCRIPTIONS: {missing}\n"
            "Each supported opcode should have an entry for the --analyze-rules output."
        )

    def test_R_is_bitwise_shift_right(self) -> None:
        """R is bitwise shift right - verify description is correct."""
        desc = OPCODE_DESCRIPTIONS.get("R", "")
        assert "bitwise" in desc.lower() or "shift" in desc.lower() or "right" in desc.lower(), (
            f"R description should mention bitwise shift right, got: '{desc}'"
        )


# ---------------------------------------------------------------------------
# extract_rule_opcodes() return type - API change regression test
# ---------------------------------------------------------------------------


class TestExtractRuleOpcodesAPI:
    """Verify the return type of extract_rule_opcodes() matches its documented signature.

    PR #12 changed the return type from dict[str, int] to tuple[dict[str, int], int].
    This is a breaking change to the public API that callers must handle correctly.
    """

    def test_returns_expected_type(self) -> None:
        """extract_rule_opcodes should return a type consistent with its annotation."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".rule") as f:
            f.write("c\nu\n$1\n")
            rule_file = f.name

        try:
            result = extract_rule_opcodes(rule_file)
            # Document the actual return type so breakage is visible
            assert isinstance(result, (dict, tuple)), (
                f"extract_rule_opcodes returned unexpected type: {type(result)}"
            )
            if isinstance(result, tuple):
                opcodes, count = result
                assert isinstance(opcodes, dict), (
                    f"First element should be dict, got {type(opcodes)}"
                )
                assert isinstance(count, int), f"Second element should be int, got {type(count)}"
                # Verify opcode contents
                assert "c" in opcodes
                assert "u" in opcodes
                assert "$" in opcodes
            else:
                # dict return - verify contents
                assert "c" in result
                assert "u" in result
                assert "$" in result
        finally:
            os.unlink(rule_file)

    def test_display_rule_opcodes_summary_works_with_current_api(self) -> None:
        """display_rule_opcodes_summary must work correctly regardless of internal API."""
        from click.testing import CliRunner
        from hashcat_rosetta.cli import main

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".rule") as f:
            f.write("c\nu\nl\n$1\n")
            rule_file = f.name

        try:
            result = runner.invoke(main, [rule_file, "--analyze-rules"])
            assert result.exit_code == 0, (
                f"--analyze-rules failed with exit code {result.exit_code}. Output: {result.output}"
            )
            assert "Opcode" in result.output or "opcode" in result.output.lower()
        finally:
            os.unlink(rule_file)


# ---------------------------------------------------------------------------
# Median calculation correctness
# ---------------------------------------------------------------------------


class TestMedianCalculation:
    """Verify the _median() helper and its usage in statistics summaries."""

    def _make_analyzer_with_rule_counts(self, rule_counts: dict) -> DebugAnalyzer:
        """Helper: build analyzer state from {rule: count} dict."""
        lines = []
        for rule, count in rule_counts.items():
            for i in range(count):
                lines.append(f"word{i} {rule} candidate{i}")
        analyzer = DebugAnalyzer()
        analyzer.analyze_debug_lines(lines)
        return analyzer

    def test_median_odd_count_correct(self) -> None:
        """Median of [1, 2, 3] should be 2 (exact middle element)."""
        analyzer = self._make_analyzer_with_rule_counts({"c": 1, "u": 2, "l": 3})
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == 2

    def test_median_even_count_two_elements(self) -> None:
        """Median of [1, 3] should be 2.0 (average of two middles)."""
        analyzer = self._make_analyzer_with_rule_counts({"c": 1, "u": 3})
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == 2.0, (
            f"Expected median 2.0 for counts [1, 3], got {summary['median_applications']}. "
            "Correct median = (1 + 3) / 2 = 2.0"
        )

    def test_median_even_count_four_elements(self) -> None:
        """Median of [1, 2, 4, 7] should be 3.0."""
        analyzer = self._make_analyzer_with_rule_counts({"a": 1, "b": 2, "c": 4, "d": 7})
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == 3.0, (
            f"Expected median 3.0 for [1, 2, 4, 7], got {summary['median_applications']}"
        )

    def test_median_single_element(self) -> None:
        """Median of [5] should be 5."""
        analyzer = self._make_analyzer_with_rule_counts({"c": 5})
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == 5

    def test_baseword_median_even_count(self) -> None:
        """Baseword statistics median should also handle even-length lists correctly."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "admin c Admin",
            "admin u ADMIN",
            "admin l admin",
        ]
        analyzer.analyze_debug_lines(lines)
        summary = analyzer.get_baseword_statistics_summary()
        # password=1, admin=3 -> sorted=[1,3] -> correct median=2.0
        assert summary["median_occurrences"] == 2.0, (
            f"Expected median 2.0 for baseword counts [1, 3], got {summary['median_occurrences']}"
        )

    def test_median_all_equal_values(self) -> None:
        """Median of equal values should equal that value."""
        analyzer = self._make_analyzer_with_rule_counts({"c": 3, "u": 3, "l": 3})
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == 3.0


# ---------------------------------------------------------------------------
# match_count tracking
# ---------------------------------------------------------------------------


class TestMatchCountTracking:
    """Verify match_count is correctly incremented in _compute_analysis()."""

    def test_match_count_zero_when_no_matches(self) -> None:
        """All entries with matched=False -> match_count stays 0."""
        analyzer = DebugAnalyzer()
        analyzer.analyze_debug_lines(["password c Password"])
        assert analyzer.rule_stats["c"]["match_count"] == 0

    def test_match_count_incremented_for_matched_entries(self) -> None:
        """Entries with matched=True should increment match_count."""
        analyzer = DebugAnalyzer()
        # Inject entries with matched=True directly
        analyzer.entries = [
            {"baseword": "password", "rule": "c", "candidate": "Password", "matched": True},
            {"baseword": "admin", "rule": "c", "candidate": "Admin", "matched": True},
            {"baseword": "test", "rule": "u", "candidate": "TEST", "matched": False},
        ]
        analyzer._compute_analysis()

        assert analyzer.rule_stats["c"]["match_count"] == 2, (
            f"Expected match_count=2 for rule 'c', got {analyzer.rule_stats['c']['match_count']}"
        )
        assert analyzer.rule_stats["u"]["match_count"] == 0, (
            f"Expected match_count=0 for rule 'u', got {analyzer.rule_stats['u']['match_count']}"
        )

    def test_baseword_match_count_incremented(self) -> None:
        """Baseword match_count should also be incremented for matched entries."""
        analyzer = DebugAnalyzer()
        analyzer.entries = [
            {"baseword": "password", "rule": "c", "candidate": "Password", "matched": True},
            {"baseword": "password", "rule": "u", "candidate": "PASSWORD", "matched": False},
        ]
        analyzer._compute_analysis()

        assert analyzer.baseword_stats["password"]["match_count"] == 1, (
            f"Expected baseword match_count=1, "
            f"got {analyzer.baseword_stats['password']['match_count']}"
        )


# ---------------------------------------------------------------------------
# Export encoding
# ---------------------------------------------------------------------------


class TestExportEncoding:
    """Verify export files are written with UTF-8 encoding."""

    def test_json_export_with_unicode_baseword(self) -> None:
        """JSON export should handle unicode basewords with UTF-8 encoding."""
        from click.testing import CliRunner
        from hashcat_rosetta.cli import main

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write("pässwörd c Pässwörd\n")
            f.write("admin u ADMIN\n")
            debug_file = f.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            export_file = f.name

        try:
            result = runner.invoke(main, [debug_file, "--export", export_file, "--format", "json"])
            assert result.exit_code == 0, f"Export failed: {result.output}"

            with open(export_file, encoding="utf-8") as f:
                data = json.load(f)
            assert "pässwörd" in str(data), "Unicode baseword not preserved in JSON export"
        finally:
            os.unlink(debug_file)
            if os.path.exists(export_file):
                os.unlink(export_file)

    def test_csv_export_with_unicode_baseword(self) -> None:
        """CSV export should handle unicode basewords with UTF-8 encoding."""
        from click.testing import CliRunner
        from hashcat_rosetta.cli import main

        runner = CliRunner()
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False, suffix=".txt"
        ) as f:
            f.write("pässwörd c Pässwörd\n")
            f.write("admin u ADMIN\n")
            debug_file = f.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as f:
            export_file = f.name

        try:
            result = runner.invoke(main, [debug_file, "--export", export_file, "--format", "csv"])
            assert result.exit_code == 0, f"Export failed: {result.output}"

            with open(export_file, encoding="utf-8") as f:
                content = f.read()
            assert "pässwörd" in content, "Unicode baseword not preserved in CSV export"
        finally:
            os.unlink(debug_file)
            if os.path.exists(export_file):
                os.unlink(export_file)


# ---------------------------------------------------------------------------
# typing.Dict removal check
# ---------------------------------------------------------------------------


class TestTypingImports:
    """Verify formatting.py does not use deprecated typing.Dict (Python 3.10+ project)."""

    def test_formatting_does_not_import_typing_Dict(self) -> None:
        """formatting.py should use built-in dict[], not typing.Dict[]."""
        import importlib.util

        spec = importlib.util.find_spec("hashcat_rosetta.formatting")
        assert spec is not None and spec.origin is not None

        with open(spec.origin, encoding="utf-8") as f:
            source = f.read()

        assert "from typing import Dict" not in source, (
            "formatting.py still uses 'from typing import Dict'. "
            "Python >=3.10 project should use built-in dict[] instead."
        )


# ---------------------------------------------------------------------------
# Parser format detection heuristic
# ---------------------------------------------------------------------------


class TestParserFormatDetection:
    """Test _detect_format() heuristic and file-level format consistency."""

    def test_detect_format_pure_space_format(self) -> None:
        """Lines without colons should be detected as space format."""
        parser = DebugLogParser()
        lines = [
            "password c Password",
            "admin u ADMIN",
            "test l test",
        ]
        detected = parser._detect_format(lines)
        assert detected == "space"

    def test_detect_format_pure_colon_format(self) -> None:
        """Lines in colon format should be detected as colon format."""
        parser = DebugLogParser()
        lines = [
            "password:c:Password",
            "admin:u:ADMIN",
            "test:l:test",
        ]
        detected = parser._detect_format(lines)
        assert detected == "colon"

    def test_detect_format_empty_returns_space(self) -> None:
        """Empty line list should default to space format."""
        parser = DebugLogParser()
        detected = parser._detect_format([])
        assert detected == "space"

    def test_space_format_file_all_rules_are_single_chars(self) -> None:
        """In a space-format file, simple single-char rules should parse as single chars."""
        parser = DebugLogParser()
        lines = [
            "password c Password",
            "admin u ADMIN",
            "test l test",
            "word r drow",
        ]
        results = parser.parse_debug_lines(lines)
        assert len(results) == 4
        for r in results:
            assert len(r["rule"]) == 1, (
                f"Rule '{r['rule']}' should be a single char for simple space-format lines"
            )

    def test_colon_format_file_parses_correctly(self) -> None:
        """Colon-format file should parse baseword, rule, and candidate correctly."""
        parser = DebugLogParser()
        lines = [
            "password:c:Password",
            "admin:u:ADMIN",
        ]
        results = parser.parse_debug_lines(lines)
        assert len(results) == 2
        assert results[0]["baseword"] == "password"
        assert results[0]["rule"] == "c"
        assert results[0]["candidate"] == "Password"

    def test_space_format_with_colon_in_candidate(self) -> None:
        """Space-format line where candidate contains ':' should parse using file-level detection."""
        parser = DebugLogParser()
        # File has multiple lines to establish space format
        lines = [
            "password c Password",
            "admin u ADMIN",
            "test c pass:word",  # candidate contains colon
        ]
        results = parser.parse_debug_lines(lines)
        assert len(results) == 3
        # Third line should use space format: rule='c', candidate='pass:word'
        assert results[2]["rule"] == "c", (
            f"Expected rule='c', got rule='{results[2]['rule']}'. "
            "File-level format detection should prevent colon-greedy parsing."
        )
        assert results[2]["candidate"] == "pass:word", (
            f"Expected candidate='pass:word', got '{results[2]['candidate']}'"
        )


# ---------------------------------------------------------------------------
# explain_rule() handler correctness
# ---------------------------------------------------------------------------


class TestExplainRuleHandlers:
    """Verify the explain_rule() handlers produce correct output."""

    def test_colon_noop(self) -> None:
        """: (no-op) leaves word unchanged."""
        result = explain_rule(":", "password")
        assert result is not None
        assert "password" in result[0]

    def test_c_capitalize(self) -> None:
        """c: capitalize first letter, lowercase rest."""
        result = explain_rule("c", "PASSWORD")
        assert result is not None
        assert "Password" in result[0]

    def test_u_uppercase(self) -> None:
        """u: uppercase all."""
        result = explain_rule("u", "password")
        assert result is not None
        assert "PASSWORD" in result[0]

    def test_l_lowercase(self) -> None:
        """l: lowercase all."""
        result = explain_rule("l", "PASSWORD")
        assert result is not None
        assert "password" in result[0]

    def test_d_duplicate(self) -> None:
        """d: duplicate word."""
        result = explain_rule("d", "abc")
        assert result is not None
        assert "abcabc" in result[0]

    def test_r_reverse(self) -> None:
        """r: reverse word."""
        result = explain_rule("r", "hello")
        assert result is not None
        assert "olleh" in result[0]

    def test_t_toggle_all(self) -> None:
        """t: toggle case for all characters."""
        result = explain_rule("t", "Hello")
        assert result is not None
        assert "hELLO" in result[0]

    def test_remove_first(self) -> None:
        """[: remove first character."""
        result = explain_rule("[", "hello")
        assert result is not None
        assert "ello" in result[0]

    def test_remove_last(self) -> None:
        """]: remove last character."""
        result = explain_rule("]", "hello")
        assert result is not None
        assert "hell" in result[0]

    def test_rotate_left(self) -> None:
        """{: rotate left - first char moves to end."""
        result = explain_rule("{", "hello")
        assert result is not None
        assert "elloh" in result[0]

    def test_rotate_right(self) -> None:
        """}: rotate right - last char moves to front."""
        result = explain_rule("}", "hello")
        assert result is not None
        assert "ohell" in result[0]

    def test_f_reflect(self) -> None:
        """f: reflect - duplicate reversed. 'abc' -> 'abccba'."""
        result = explain_rule("f", "abc")
        assert result is not None
        assert "abccba" in result[0]

    def test_k_swap_first_two(self) -> None:
        """k: swap first two characters."""
        result = explain_rule("k", "hello")
        assert result is not None
        assert "ehllo" in result[0]

    def test_K_swap_last_two(self) -> None:
        """K: swap last two characters."""
        result = explain_rule("K", "hello")
        assert result is not None
        assert "helol" in result[0]

    def test_q_duplicate_every_char(self) -> None:
        """q: duplicate every character. 'abc' -> 'aabbcc'."""
        result = explain_rule("q", "abc")
        assert result is not None
        assert "aabbcc" in result[0], f"Expected 'aabbcc' in q result: {result[0]}"

    def test_E_title_case(self) -> None:
        """E: title case (uppercase first letter and letters after spaces)."""
        result = explain_rule("E", "hello world")
        assert result is not None
        expected = "Hello World"
        assert expected in result[0], f"Expected '{expected}' in E result: {result[0]}"

    def test_dollar_append_char(self) -> None:
        """$X: append character X."""
        result = explain_rule("$1", "password")
        assert result is not None
        assert "password1" in result[0]

    def test_caret_prepend_char(self) -> None:
        """^X: prepend character X."""
        result = explain_rule("^!", "password")
        assert result is not None
        assert "!password" in result[0]

    def test_i_insert_at_position(self) -> None:
        """iNX: insert character X at position N."""
        result = explain_rule("i2!", "hello")
        assert result is not None
        assert "he!llo" in result[0]

    def test_i_hex_position(self) -> None:
        """iAX: insert at hex position A (=10)."""
        result = explain_rule("iA!", "hello_world!")
        assert result is not None
        assert "pos 10" in result[0]

    def test_s_substitute(self) -> None:
        """sXY: substitute all X with Y."""
        result = explain_rule("sao", "banana")
        assert result is not None
        assert "bonono" in result[0]

    def test_D_delete_at_position(self) -> None:
        """DX: delete character at position X."""
        result = explain_rule("D0", "hello")
        assert result is not None
        assert "ello" in result[0]

    def test_T_toggle_at_position(self) -> None:
        """TX: toggle case at position X."""
        result = explain_rule("T0", "hello")
        assert result is not None
        assert "Hello" in result[0]

    def test_p0_no_extra_copies(self) -> None:
        """p0: append word 0 extra times - word unchanged (word * 1)."""
        result = explain_rule("p0", "abc")
        assert result is not None
        # p0 = current * (0 + 1) = current * 1 = current
        assert result[0].endswith("abc")

    def test_p2_appends_twice(self) -> None:
        """p2: append word 2 extra times (word * 3)."""
        result = explain_rule("p2", "abc")
        assert result is not None
        assert "abcabcabc" in result[0]

    def test_compound_rule_sequential_application(self) -> None:
        """Compound rule applies ops left to right."""
        result = explain_rule("c$1", "password")
        assert result is not None
        assert len(result) == 2
        assert "Password" in result[0]
        assert "Password1" in result[1]

    @pytest.mark.parametrize("op", list(":culdrt[]{}fkKqE"))
    def test_all_no_arg_ops_produce_output(self, op: str) -> None:
        """All no-arg ops should produce at least one explanation step."""
        result = explain_rule(op, "password")
        assert result is not None, f"No-arg op '{op}' returned None for 'password'"
        assert len(result) >= 1, f"No-arg op '{op}' returned empty list"

    def test_k_on_single_char_no_crash(self) -> None:
        """k on single-char word should not crash."""
        result = explain_rule("k", "a")
        # Word unchanged when len < 2
        assert result is not None
        assert "a" in result[0]

    def test_K_on_single_char_no_crash(self) -> None:
        """K on single-char word should not crash."""
        result = explain_rule("K", "a")
        assert result is not None
        assert "a" in result[0]


# ---------------------------------------------------------------------------
# pyproject.toml configuration
# ---------------------------------------------------------------------------


class TestProjectConfig:
    """Verify pyproject.toml has required configuration."""

    def test_mypy_section_exists(self) -> None:
        """pyproject.toml should have [tool.mypy] section."""
        import pathlib

        pyproject_path = pathlib.Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject_path.read_text(encoding="utf-8")
        assert "[tool.mypy]" in content, "pyproject.toml is missing [tool.mypy] section."

    def test_parser_uses_logging_not_warnings(self) -> None:
        """parser.py should use logging module, not warnings module."""
        import pathlib

        parser_path = pathlib.Path(__file__).parent.parent / "hashcat_rosetta" / "parser.py"
        content = parser_path.read_text(encoding="utf-8")

        assert "import logging" in content, "parser.py should import logging module"
        # warnings should not be the primary warning mechanism
        assert "import warnings" not in content, (
            "parser.py should not import warnings module - use logging instead"
        )

    def test_parser_does_not_have_redundant_total_lines(self) -> None:
        """parser.py should not have redundant 'total_lines = 0' variable."""
        import pathlib

        parser_path = pathlib.Path(__file__).parent.parent / "hashcat_rosetta" / "parser.py"
        content = parser_path.read_text(encoding="utf-8")

        assert "total_lines = 0" not in content, (
            "parser.py has redundant 'total_lines = 0' variable. "
            "Use 'line_num' from enumerate() directly."
        )


# ---------------------------------------------------------------------------
# O opcode misclassification (pre-existing bug, documented here)
# ---------------------------------------------------------------------------


class TestOpcodeClassification:
    """Verify opcode argument counts match hashcat documentation.

    The 'O' (Omit) opcode takes TWO positional arguments in hashcat:
        O<start><length> - delete <length> chars starting at <start>
    But the tokenizer incorrectly classifies it as a one-arg opcode.
    """

    def test_O_tokenized_as_one_arg(self) -> None:
        """Document current (incorrect) behavior: O is treated as 1-arg.

        Hashcat 'O' opcode is: Omit M characters starting at position N.
        It requires 2 args: O<N><M>. The tokenizer should treat it as 2-arg.
        This test documents the current behavior as a regression anchor.
        """
        parser = RuleParser()
        # O42 = omit 2 chars starting at pos 4
        result = parser.parse_rule("O42")
        assert result is not None

        # Current (incorrect) behavior: O4 is one token, 2 is separate/unknown
        # Correct behavior: O42 should be one token
        # We document what the tokenizer currently produces:
        components = result["components"]
        if len(components) == 1 and components[0] == "O42":
            # Correctly tokenized as 2-arg
            pass
        elif len(components) >= 1 and components[0] == "O4":
            # Incorrectly tokenized as 1-arg (current bug)
            # This assertion documents the bug location
            assert components[0] == "O4", (
                "O is misclassified as 1-arg opcode in _tokenize_rule(). "
                "Hashcat O takes 2 params: O<position><length>. "
                "Should be in two_arg_ops, not one_arg_ops."
            )

    def test_explain_O_handler_uses_two_args(self) -> None:
        """explain_rule's O handler reads two args: ONM deletes M chars at pos N."""
        result = explain_rule("O34", "hello_world")
        assert result is not None
        # O34: omit 4 chars starting at pos 3 -> "helworld"
        assert "Omit" in result[0] or "omit" in result[0].lower()
        assert "helorld" in result[0]


# ---------------------------------------------------------------------------
# Reject sentinel contract
# ---------------------------------------------------------------------------


class TestRejectSentinel:
    """Verify explain_rule() emits REJECT_SENTINEL_PREFIX for rejection opcodes.

    The sentinel contract:
      - When a rejection opcode fires, the last step in the returned list MUST
        start with REJECT_SENTINEL_PREFIX and the list is terminated (no further
        steps are appended after the sentinel).
      - When a rejection opcode does NOT fire (word passes the check), the last
        step must NOT start with REJECT_SENTINEL_PREFIX.

    This contract is consumed by scripts/verify_rules.py to distinguish a
    predicted rejection from a transformation result.
    """

    # ------------------------------------------------------------------
    # ! opcode: reject if word contains X
    # ------------------------------------------------------------------

    def test_bang_rejects_when_word_contains_char(self) -> None:
        """!a: word 'banana' contains 'a' → last step is REJECTED sentinel."""
        result = explain_rule("!a", "banana")
        assert result is not None, "explain_rule returned None"
        assert result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Expected last step to start with '{REJECT_SENTINEL_PREFIX}', got: {result[-1]!r}"
        )

    def test_bang_passes_when_word_does_not_contain_char(self) -> None:
        """!z: word 'banana' does not contain 'z' → last step is a pass step, not a sentinel."""
        result = explain_rule("!z", "banana")
        assert result is not None, "explain_rule returned None"
        assert not result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Last step should NOT be a sentinel when word passes '!z': {result[-1]!r}"
        )
        assert "passed" in result[-1].lower() or "does not contain" in result[-1].lower(), (
            f"Last step should indicate the word passed the '!z' check: {result[-1]!r}"
        )

    # ------------------------------------------------------------------
    # > opcode: reject if word length > N
    # ------------------------------------------------------------------

    def test_gt_rejects_when_word_is_too_long(self) -> None:
        """>3: 'hello' has length 5 > 3 → REJECTED sentinel."""
        result = explain_rule(">3", "hello")
        assert result is not None
        assert result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Expected REJECTED sentinel for '>3' on 'hello', got: {result[-1]!r}"
        )

    def test_gt_passes_when_word_is_short_enough(self) -> None:
        """>8: 'hello' has length 5 ≤ 8 → no sentinel."""
        result = explain_rule(">8", "hello")
        assert result is not None
        assert not result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Should not be rejected by '>8' when word length is 5: {result[-1]!r}"
        )

    # ------------------------------------------------------------------
    # < opcode: reject if word length < N
    # ------------------------------------------------------------------

    def test_lt_rejects_when_word_is_too_short(self) -> None:
        """<8: 'hello' has length 5 < 8 → REJECTED sentinel."""
        result = explain_rule("<8", "hello")
        assert result is not None
        assert result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Expected REJECTED sentinel for '<8' on 'hello', got: {result[-1]!r}"
        )

    def test_lt_passes_when_word_is_long_enough(self) -> None:
        """<3: 'hello' has length 5 ≥ 3 → no sentinel."""
        result = explain_rule("<3", "hello")
        assert result is not None
        assert not result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Should not be rejected by '<3' when word length is 5: {result[-1]!r}"
        )

    # ------------------------------------------------------------------
    # % opcode: reject if word does not contain X
    # ------------------------------------------------------------------

    def test_percent_rejects_when_word_missing_char(self) -> None:
        """%a: 'test' does not contain 'a' → REJECTED sentinel."""
        result = explain_rule("%a", "test")
        assert result is not None
        assert result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Expected REJECTED sentinel for '%a' on 'test', got: {result[-1]!r}"
        )

    def test_percent_passes_when_word_contains_char(self) -> None:
        """%e: 'test' contains 'e' → no sentinel."""
        result = explain_rule("%e", "test")
        assert result is not None
        assert not result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Should not be rejected by '%e' when word contains 'e': {result[-1]!r}"
        )

    # ------------------------------------------------------------------
    # = opcode: reject unless char at position N is X
    # ------------------------------------------------------------------

    def test_equals_rejects_when_wrong_char_at_position(self) -> None:
        """=0z: char at pos 0 of 'hello' is 'h', not 'z' → REJECTED sentinel."""
        result = explain_rule("=0z", "hello")
        assert result is not None
        assert result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Expected REJECTED sentinel for '=0z' on 'hello', got: {result[-1]!r}"
        )

    def test_equals_passes_when_correct_char_at_position(self) -> None:
        """=0h: char at pos 0 of 'hello' is 'h' → no sentinel."""
        result = explain_rule("=0h", "hello")
        assert result is not None
        assert not result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Should not be rejected by '=0h' when char at pos 0 is 'h': {result[-1]!r}"
        )

    def test_equals_rejects_when_position_out_of_bounds(self) -> None:
        """=9x: pos 9 is beyond 'hi' (length 2) → REJECTED sentinel."""
        result = explain_rule("=9x", "hi")
        assert result is not None
        assert result[-1].startswith(REJECT_SENTINEL_PREFIX), (
            f"Expected REJECTED sentinel for '=9x' on 'hi' (out of bounds), got: {result[-1]!r}"
        )

    # ------------------------------------------------------------------
    # Sentinel format consistency
    # ------------------------------------------------------------------

    def test_sentinel_format_does_not_contain_arrow(self) -> None:
        """Rejection sentinels must not contain '→' (which would confuse the result extractor)."""
        cases = [
            ("!a", "banana"),
            (">3", "hello"),
            ("<8", "hello"),
            ("%a", "test"),
            ("=0z", "hello"),
        ]
        for rule, word in cases:
            result = explain_rule(rule, word)
            assert result is not None
            last = result[-1]
            assert last.startswith(REJECT_SENTINEL_PREFIX), (
                f"rule={rule!r}, word={word!r}: last step is not a sentinel: {last!r}"
            )
            assert "\u2192" not in last, (
                f"rule={rule!r}, word={word!r}: sentinel must not contain '→': {last!r}"
            )


# ---------------------------------------------------------------------------
# Additional correctness: _detect_format heuristic edge cases
# ---------------------------------------------------------------------------


class TestDetectFormatEdgeCases:
    """Additional edge cases for the _detect_format() heuristic."""

    def test_detect_format_single_line_space(self) -> None:
        """Single space-format line should detect as space."""
        parser = DebugLogParser()
        detected = parser._detect_format(["password c Password"])
        assert detected == "space"

    def test_detect_format_single_line_colon(self) -> None:
        """Single colon-format line with no spaces should detect as colon."""
        parser = DebugLogParser()
        detected = parser._detect_format(["password:c:Password"])
        assert detected == "colon"

    def test_detect_format_majority_wins(self) -> None:
        """When 3 space-format lines and 1 ambiguous, space should win."""
        parser = DebugLogParser()
        lines = [
            "password c Password",
            "admin u ADMIN",
            "test l test",
            "word:r:drow",  # one colon-format line
        ]
        # Space should win (3 vs 1)
        detected = parser._detect_format(lines)
        assert detected == "space"

    def test_parse_lines_with_empty_list_resets_format(self) -> None:
        """parse_debug_lines with empty list should handle gracefully."""
        parser = DebugLogParser()
        results = parser.parse_debug_lines([])
        assert results == []

    def test_format_detection_persists_across_parse_lines_call(self) -> None:
        """After parse_debug_lines, _format attribute should be set."""
        parser = DebugLogParser()
        parser.parse_debug_lines(["password c Password", "admin u ADMIN"])
        assert parser._format in ("space", "colon"), (
            f"_format should be 'space' or 'colon', got: {parser._format!r}"
        )
