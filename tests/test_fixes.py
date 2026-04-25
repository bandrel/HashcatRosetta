"""Tests for fixes applied to GitHub issues.

Covers: input validation, --analyze-rules CLI flag, characteristics extraction,
JSON serialization, incomplete token warnings, and __main__.py wrapper.
"""

import json
import logging
import os
import tempfile

import pytest
from click.testing import CliRunner

from hashcat_rosetta import DebugAnalyzer, DebugLogParser, RuleAnalyzer, RuleParser
from hashcat_rosetta.cli import main


class TestInputValidation:
    """Tests for input validation added in issue #8."""

    def test_analyze_rule_rejects_int(self):
        analyzer = RuleAnalyzer()
        with pytest.raises(TypeError, match="Expected str"):
            analyzer.analyze_rule(123)  # type: ignore[arg-type]

    def test_analyze_rule_rejects_none(self):
        analyzer = RuleAnalyzer()
        with pytest.raises(TypeError, match="Expected str"):
            analyzer.analyze_rule(None)  # type: ignore[arg-type]

    def test_analyze_rule_rejects_list(self):
        analyzer = RuleAnalyzer()
        with pytest.raises(TypeError, match="Expected str"):
            analyzer.analyze_rule(["c", "u"])  # type: ignore[arg-type]

    def test_analyze_ruleset_none_returns_none(self):
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_ruleset(None)
        assert result is None

    def test_analyze_ruleset_empty_returns_none(self):
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_ruleset([])
        assert result is None

    def test_parse_rule_whitespace_only_returns_none(self):
        parser = RuleParser()
        result = parser.parse_rule("   ")
        assert result is None

    def test_parse_debug_file_empty_raises_valueerror(self):
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            filepath = f.name

        try:
            with pytest.raises(ValueError, match="No valid debug entries found"):
                parser.parse_debug_file(filepath)
        finally:
            os.unlink(filepath)

    def test_parse_debug_file_all_invalid_raises_valueerror(self):
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("not-a-valid-line\n")
            f.write("also-bad\n")
            f.flush()
            filepath = f.name

        try:
            with pytest.raises(ValueError, match="No valid debug entries found"):
                parser.parse_debug_file(filepath)
        finally:
            os.unlink(filepath)

    def test_parse_debug_file_directory_raises(self):
        parser = DebugLogParser()
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises((IsADirectoryError, PermissionError)):
                parser.parse_debug_file(tmpdir)

    def test_parse_debug_file_none_raises_typeerror(self):
        parser = DebugLogParser()
        with pytest.raises(TypeError):
            parser.parse_debug_file(None)  # type: ignore[arg-type]


class TestAnalyzeRulesCLIFlag:
    """Tests for the --analyze-rules CLI flag added in issue #11."""

    def test_analyze_rules_with_valid_rule_file(self):
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".rule") as f:
            f.write("c\n")
            f.write("u\n")
            f.write("l\n")
            f.write("$1\n")
            f.write("^!\n")
            f.flush()
            filepath = f.name

        try:
            result = runner.invoke(main, [filepath, "--analyze-rules"])
            assert result.exit_code == 0
        finally:
            os.unlink(filepath)

    def test_analyze_rules_without_file_shows_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--analyze-rules"])
        # Should fail because FILE is required
        assert result.exit_code != 0

    def test_analyze_rules_with_nonexistent_file(self):
        runner = CliRunner()
        result = runner.invoke(main, ["/nonexistent/file.rule", "--analyze-rules"])
        assert result.exit_code != 0


class TestCharacteristicsExtraction:
    """Tests for the fixed _extract_characteristics in analyzer.py."""

    def test_case_transform_detected(self):
        analyzer = RuleAnalyzer()
        for rule in ["u", "l", "c", "t"]:
            result = analyzer.analyze_rule(rule)
            assert result is not None
            assert "case_transform" in result["characteristics"], (
                f"Rule '{rule}' should have case_transform characteristic"
            )

    def test_substitution_detected(self):
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("sse")
        assert result is not None
        assert "substitution" in result["characteristics"]

    def test_insert_detected_as_substitution(self):
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("i4!")
        assert result is not None
        assert "substitution" in result["characteristics"]

    def test_position_based_detected(self):
        analyzer = RuleAnalyzer()
        for rule in ["$1", "^a"]:
            result = analyzer.analyze_rule(rule)
            assert result is not None
            assert "position_based" in result["characteristics"], (
                f"Rule '{rule}' should have position_based characteristic"
            )

    def test_reversal_detected(self):
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("r")
        assert result is not None
        assert "reversal" in result["characteristics"]

    def test_complex_detected(self):
        analyzer = RuleAnalyzer()
        # 6+ components triggers "complex"
        result = analyzer.analyze_rule("cudlrf$1")
        assert result is not None
        assert "complex" in result["characteristics"]

    def test_empty_component_guard(self):
        """Verify empty components don't cause IndexError."""
        analyzer = RuleAnalyzer()
        # Manually test the internal method with empty components
        parsed = {"components": ["", "c", ""]}
        characteristics = analyzer._extract_characteristics(parsed)
        assert "case_transform" in characteristics

    def test_multiple_characteristics(self):
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("c$1sse")
        assert result is not None
        chars = result["characteristics"]
        assert "case_transform" in chars
        assert "position_based" in chars
        assert "substitution" in chars


class TestJSONSerialization:
    """Tests for JSON serialization fix in issue #5."""

    def test_analyze_debug_lines_is_json_serializable(self):
        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "password u PASSWORD",
            "admin c Admin",
            "admin $1 admin1",
        ]
        result = analyzer.analyze_debug_lines(lines)
        # Should not raise - sets should have been converted to lists
        serialized = json.dumps(result)
        assert isinstance(serialized, str)

    def test_export_to_dict_is_json_serializable(self):
        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "password u PASSWORD",
            "admin c Admin",
        ]
        analyzer.analyze_debug_lines(lines)
        export = analyzer.export_to_dict()
        serialized = json.dumps(export)
        assert isinstance(serialized, str)

    def test_export_roundtrip(self):
        """Verify exported JSON can be loaded back."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "password u PASSWORD",
            "admin c Admin",
        ]
        analyzer.analyze_debug_lines(lines)
        export = analyzer.export_to_dict()
        serialized = json.dumps(export)
        loaded = json.loads(serialized)
        assert loaded["summary"]["total_entries"] == 3

    def test_export_json_to_file(self):
        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "admin u ADMIN",
        ]
        analyzer.analyze_debug_lines(lines)
        export = analyzer.export_to_dict()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            json.dump(export, f, indent=2)
            filepath = f.name

        try:
            with open(filepath) as f:
                loaded = json.load(f)
            assert loaded["summary"]["total_entries"] == 2
        finally:
            os.unlink(filepath)

    def test_rule_stats_sets_converted_to_lists(self):
        """Verify that sets in rule_stats are converted to sorted lists."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "admin c Admin",
        ]
        result = analyzer.analyze_debug_lines(lines)
        rule_c_stats = result["rule_stats"]["c"]
        # basewords should be a sorted list, not a set
        assert isinstance(rule_c_stats["basewords"], list)
        assert rule_c_stats["basewords"] == ["admin", "password"]


class TestIncompleteTokenWarnings:
    """Tests for incomplete token warnings in parser.py."""

    def test_incomplete_two_arg_opcode_warns(self, caplog):
        parser = RuleParser()
        with caplog.at_level(logging.WARNING, logger="hashcat_rosetta.parser"):
            parser.parse_rule("i4")
        assert len(caplog.records) == 1
        assert "Incomplete 2-arg opcode" in caplog.records[0].message

    def test_incomplete_one_arg_opcode_warns(self, caplog):
        parser = RuleParser()
        with caplog.at_level(logging.WARNING, logger="hashcat_rosetta.parser"):
            parser.parse_rule("$")
        assert len(caplog.records) == 1
        assert "Incomplete 1-arg opcode" in caplog.records[0].message

    def test_complete_opcodes_no_warnings(self, caplog):
        parser = RuleParser()
        with caplog.at_level(logging.WARNING, logger="hashcat_rosetta.parser"):
            parser.parse_rule("c$1sse")
        assert len(caplog.records) == 0

    def test_incomplete_token_still_parses_valid_tokens(self):
        """Rule with both valid and incomplete tokens should parse the valid ones."""
        parser = RuleParser()
        result = parser.parse_rule("c$1i")
        assert result is not None
        # 'c' and '$1' should parse, 'i' should warn and be skipped
        assert len(result["components"]) == 2
        assert result["components"][0] == "c"
        assert result["components"][1] == "$1"


class TestTokenizerOpcodes:
    """Tests for the rewritten tokenizer covering all opcode categories."""

    def test_no_arg_ops(self):
        parser = RuleParser()
        for op in ":lucCtdfr{}[]kKqE":
            result = parser.parse_rule(op)
            assert result is not None, f"No-arg opcode '{op}' should parse"
            assert result["components"] == [op], f"No-arg opcode '{op}' should tokenize as ['{op}']"

    def test_one_arg_ops(self):
        parser = RuleParser()
        for op in "TDpyYzZ":
            rule = f"{op}3"
            result = parser.parse_rule(rule)
            assert result is not None, f"One-arg opcode '{op}' should parse"
            assert result["components"] == [rule], (
                f"One-arg opcode '{op}3' should tokenize as ['{rule}']"
            )

    def test_two_arg_ops(self):
        parser = RuleParser()
        for op in "soix*XOB":
            rule = f"{op}ab"
            result = parser.parse_rule(rule)
            assert result is not None, f"Two-arg opcode '{op}' should parse"
            assert result["components"] == [rule], (
                f"Two-arg opcode '{op}ab' should tokenize as ['{rule}']"
            )

    def test_append_prepend(self):
        parser = RuleParser()
        result = parser.parse_rule("$a^b")
        assert result is not None
        assert result["components"] == ["$a", "^b"]

    def test_mixed_opcode_categories(self):
        parser = RuleParser()
        result = parser.parse_rule("c$1sae")
        assert result is not None
        assert result["components"] == ["c", "$1", "sae"]

    def test_spaces_as_separators(self):
        parser = RuleParser()
        result = parser.parse_rule("c $1 u")
        assert result is not None
        assert result["components"] == ["c", "$1", "u"]


class TestCLIErrorHandling:
    """Tests for CLI error handling."""

    def test_debug_file_not_found(self):
        runner = CliRunner()
        result = runner.invoke(main, ["/nonexistent/debug.txt"])
        assert result.exit_code != 0

    def test_no_file_no_explain_shows_error(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        # Should show help or error about missing FILE
        assert result.exit_code != 0 or "Error" in result.output or "Usage" in result.output

    def test_explain_mode_works(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--explain", "c$1", "--baseword", "admin"])
        assert result.exit_code == 0
        assert "Admin" in result.output or "admin" in result.output

    def test_cli_no_emojis_in_explain_output(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--explain", "c"])
        assert result.exit_code == 0
        # No emojis should appear in output
        for emoji in [
            "\U0001f4d6",
            "\u26a0\ufe0f",
            "\U0001f4ca",
            "\U0001f4cb",
            "\U0001f4dd",
            "\u2713",
        ]:
            assert emoji not in result.output, f"Found emoji {repr(emoji)} in CLI output"

    def test_cli_no_emojis_in_summary_output(self):
        runner = CliRunner()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("password c Password\n")
            f.write("admin u ADMIN\n")
            f.flush()
            filepath = f.name

        try:
            result = runner.invoke(main, [filepath])
            assert result.exit_code == 0
            for emoji in [
                "\U0001f4d6",
                "\u26a0\ufe0f",
                "\U0001f4ca",
                "\U0001f4cb",
                "\U0001f4dd",
                "\u2713",
            ]:
                assert emoji not in result.output
        finally:
            os.unlink(filepath)


class TestMainModuleWrapper:
    """Tests that __main__.py properly delegates to cli.main."""

    def test_main_module_imports_cli_main(self):
        from hashcat_rosetta.__main__ import main as main_func
        from hashcat_rosetta.cli import main as cli_main

        assert main_func is cli_main
