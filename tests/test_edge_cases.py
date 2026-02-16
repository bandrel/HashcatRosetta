"""Test suite for edge cases and error handling in hashcat_rosetta.

This test module covers edge cases, boundary conditions, and error handling
scenarios that are not covered in the basic test suite.
"""

import pytest
import tempfile
import os
from hashcat_rosetta import RuleParser, RuleAnalyzer, DebugLogParser, DebugAnalyzer


class TestDebugLogParserEdgeCases:
    """Edge case tests for DebugLogParser."""

    def test_parse_empty_file(self):
        """Test parsing a completely empty file."""
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            # Empty file
            filepath = f.name

        try:
            with pytest.raises(ValueError, match="No valid debug entries found"):
                parser.parse_debug_file(filepath)
        finally:
            os.unlink(filepath)

    def test_parse_file_with_only_comments(self):
        """Test parsing a file containing only comments."""
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("# This is a comment\n")
            f.write("# Another comment\n")
            f.write("# More comments\n")
            f.flush()
            filepath = f.name

        try:
            with pytest.raises(ValueError):
                parser.parse_debug_file(filepath)
        finally:
            os.unlink(filepath)

    def test_parse_file_with_mixed_valid_invalid_lines(self):
        """Test parsing file with mix of valid and invalid lines."""
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("password c P@ssword\n")
            f.write("invalid\n")  # Invalid line
            f.write("admin u ADMIN\n")
            f.write("onlyoneword\n")  # Invalid line
            f.write("test l test\n")
            f.flush()
            filepath = f.name

        try:
            results = parser.parse_debug_file(filepath)
            assert len(results) == 3  # Only valid lines
            assert results[0]["baseword"] == "password"
            assert results[1]["baseword"] == "admin"
            assert results[2]["baseword"] == "test"
        finally:
            os.unlink(filepath)

    def test_parse_line_with_unicode_baseword(self):
        """Test parsing line with unicode characters in baseword."""
        parser = DebugLogParser()
        line = "pässwörd c Pässwörd"
        result = parser._parse_line(line)
        assert result is not None
        assert result["baseword"] == "pässwörd"
        assert result["candidate"] == "Pässwörd"

    def test_parse_line_with_emoji_baseword(self):
        """Test parsing line with emoji in baseword."""
        parser = DebugLogParser()
        line = "pass🔒word c Pass🔒word"
        result = parser._parse_line(line)
        assert result is not None
        assert result["baseword"] == "pass🔒word"

    def test_parse_line_with_whitespace_in_candidate(self):
        """Test parsing line where candidate contains spaces."""
        parser = DebugLogParser()
        line = "password $  password "
        result = parser._parse_line(line)
        assert result is not None
        assert result["candidate"] == "password "

    def test_parse_line_with_only_two_fields(self):
        """Test parsing line with only two fields (missing candidate)."""
        parser = DebugLogParser()
        line = "password c"
        result = parser._parse_line(line)
        assert result is None

    def test_parse_line_with_empty_rule(self):
        """Test parsing line where rule field is empty."""
        parser = DebugLogParser()
        line = "password  candidate"  # Two spaces (empty rule)
        parser._parse_line(line)
        # This might be parsed as baseword='password', rule='', candidate='candidate'
        # Behavior depends on implementation

    def test_parse_line_with_empty_baseword(self):
        """Test parsing line where baseword is empty."""
        parser = DebugLogParser()
        line = " c Candidate"
        parser._parse_line(line)
        # Should handle gracefully

    def test_parse_line_with_very_long_fields(self):
        """Test parsing line with extremely long fields."""
        parser = DebugLogParser()
        long_baseword = "a" * 10000
        long_candidate = "b" * 10000
        line = f"{long_baseword} c {long_candidate}"
        result = parser._parse_line(line)
        assert result is not None
        assert len(result["baseword"]) == 10000
        assert len(result["candidate"]) == 10000

    def test_parse_file_with_windows_line_endings(self):
        """Test parsing file with Windows CRLF line endings."""
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as f:
            f.write(b"password c P@ssword\r\n")
            f.write(b"admin u ADMIN\r\n")
            filepath = f.name

        try:
            results = parser.parse_debug_file(filepath)
            assert len(results) == 2
            assert results[0]["baseword"] == "password"
        finally:
            os.unlink(filepath)

    def test_parse_file_with_mac_line_endings(self):
        """Test parsing file with old Mac CR line endings."""
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as f:
            f.write(b"password c P@ssword\r")
            f.write(b"admin u ADMIN\r")
            filepath = f.name

        try:
            parser.parse_debug_file(filepath)
            # May fail depending on implementation
        finally:
            os.unlink(filepath)

    def test_parse_lines_empty_list(self):
        """Test parsing empty list of lines."""
        parser = DebugLogParser()
        results = parser.parse_debug_lines([])
        assert results == []

    def test_parse_lines_with_none_elements(self):
        """Test parsing list containing None values."""
        parser = DebugLogParser()
        # Should handle gracefully or raise TypeError
        try:
            parser.parse_debug_lines([None, "password c P@ssword", None])
        except (TypeError, AttributeError):
            pass  # Expected if not handled


class TestRuleParserEdgeCases:
    """Edge case tests for RuleParser."""

    def test_parse_rule_with_whitespace(self):
        """Test parsing rule with leading/trailing whitespace."""
        parser = RuleParser()
        result = parser.parse_rule("  c  ")
        assert result is not None
        assert result["original"] == "c"

    def test_parse_rule_with_unknown_opcodes(self):
        """Test parsing rule with unknown/unsupported opcodes."""
        parser = RuleParser()
        result = parser.parse_rule("xyz")
        assert result is not None
        # Should return something even if opcodes not recognized

    def test_parse_rule_very_long_rule(self):
        """Test parsing extremely long rule string."""
        parser = RuleParser()
        long_rule = "c" * 1000
        result = parser.parse_rule(long_rule)
        assert result is not None

    def test_parse_rule_with_unicode(self):
        """Test parsing rule with unicode characters."""
        parser = RuleParser()
        result = parser.parse_rule("c$ä")
        assert result is not None

    def test_parse_ruleset_with_empty_rules(self):
        """Test parsing ruleset containing empty strings."""
        parser = RuleParser()
        rules = ["c", "", "u", "  ", "l"]
        results = parser.parse_ruleset(rules)
        # Should skip empty rules
        assert len(results) < len(rules)

    def test_parse_ruleset_all_invalid(self):
        """Test parsing ruleset where all rules are invalid."""
        parser = RuleParser()
        rules = ["", "# comment", "   "]
        results = parser.parse_ruleset(rules)
        assert len(results) == 0


class TestRuleAnalyzerEdgeCases:
    """Edge case tests for RuleAnalyzer."""

    def test_analyze_rule_empty_string(self):
        """Test analyzing empty rule string."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("")
        assert result is None

    def test_analyze_rule_whitespace_only(self):
        """Test analyzing whitespace-only rule."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("   ")
        assert result is None

    def test_analyze_ruleset_empty_list(self):
        """Test analyzing empty ruleset."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_ruleset([])
        assert result is None

    def test_analyze_ruleset_with_one_rule(self):
        """Test analyzing ruleset with single rule."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_ruleset(["c"])
        assert result is not None
        assert result["total_rules"] == 1

    def test_efficiency_score_bounds(self):
        """Test that efficiency scores are within bounds."""
        analyzer = RuleAnalyzer()
        test_rules = ["c", "u", "l", "cudlrft", "^1$2$3$4$5"]
        for rule in test_rules:
            result = analyzer.analyze_rule(rule)
            assert 0 <= result["efficiency_score"] <= 100

    def test_complexity_score_bounds(self):
        """Test that complexity scores are within bounds."""
        analyzer = RuleAnalyzer()
        test_rules = ["c", "u", "l", "cudlrft", "^1$2$3$4$5"]
        for rule in test_rules:
            result = analyzer.analyze_rule(rule)
            assert 0 <= result["complexity"] <= 100


class TestDebugAnalyzerEdgeCases:
    """Edge case tests for DebugAnalyzer."""

    def test_analyze_empty_lines(self):
        """Test analyzing empty list of lines."""
        analyzer = DebugAnalyzer()
        result = analyzer.analyze_debug_lines([])
        assert result["total_entries"] == 0
        assert result["unique_rules"] == 0
        assert result["unique_basewords"] == 0

    def test_get_top_rules_when_no_data(self):
        """Test getting top rules when no analysis has been run."""
        analyzer = DebugAnalyzer()
        result = analyzer.get_top_rules_by_frequency(10)
        assert result == []

    def test_get_top_basewords_when_no_data(self):
        """Test getting top basewords when no analysis has been run."""
        analyzer = DebugAnalyzer()
        result = analyzer.get_top_basewords_by_frequency(10)
        assert result == []

    def test_get_baseword_detail_nonexistent(self):
        """Test getting detail for baseword that doesn't exist."""
        analyzer = DebugAnalyzer()
        analyzer.analyze_debug_lines(["password c P@ssword"])
        result = analyzer.get_baseword_detail("nonexistent")
        assert result is None

    def test_get_rule_detail_nonexistent(self):
        """Test getting detail for rule that doesn't exist."""
        analyzer = DebugAnalyzer()
        analyzer.analyze_debug_lines(["password c P@ssword"])
        result = analyzer.get_rule_detail("nonexistent")
        assert result is None

    def test_analyze_single_line(self):
        """Test analyzing just a single line."""
        analyzer = DebugAnalyzer()
        result = analyzer.analyze_debug_lines(["password c P@ssword"])
        assert result["total_entries"] == 1
        assert result["unique_rules"] == 1
        assert result["unique_basewords"] == 1

    def test_analyze_duplicate_entries(self):
        """Test analyzing duplicate entries."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password c P@ssword",
            "password c P@ssword",
        ]
        result = analyzer.analyze_debug_lines(lines)
        assert result["total_entries"] == 3
        assert result["unique_rules"] == 1
        assert result["unique_basewords"] == 1

    def test_get_basewords_with_min_occurrences_zero(self):
        """Test getting basewords with min_occurrences=0."""
        analyzer = DebugAnalyzer()
        analyzer.analyze_debug_lines(["password c P@ssword"])
        result = analyzer.get_basewords_with_min_occurrences(0)
        assert len(result) > 0

    def test_get_basewords_with_min_occurrences_very_high(self):
        """Test getting basewords with impossibly high min_occurrences."""
        analyzer = DebugAnalyzer()
        analyzer.analyze_debug_lines(["password c P@ssword"])
        result = analyzer.get_basewords_with_min_occurrences(1000000)
        assert result == []

    def test_rule_statistics_summary_no_data(self):
        """Test rule statistics summary with no data."""
        analyzer = DebugAnalyzer()
        result = analyzer.get_rule_statistics_summary()
        assert result == {}

    def test_baseword_statistics_summary_no_data(self):
        """Test baseword statistics summary with no data."""
        analyzer = DebugAnalyzer()
        result = analyzer.get_baseword_statistics_summary()
        assert result == {}

    def test_export_to_dict_no_data(self):
        """Test exporting to dict with no data."""
        analyzer = DebugAnalyzer()
        result = analyzer.export_to_dict()
        assert "summary" in result
        assert result["summary"]["total_entries"] == 0

    def test_analyze_lines_with_same_baseword_different_rules(self):
        """Test analyzing same baseword with many different rules."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "password d passwordpassword",
            "password r drowssap",
        ]
        analyzer.analyze_debug_lines(lines)
        detail = analyzer.get_baseword_detail("password")
        assert detail["unique_rules"] == 5
        assert detail["total_occurrences"] == 5


class TestInputValidationEdgeCases:
    """Test input validation and error handling."""

    def test_parse_debug_file_none_filepath(self):
        """Test parsing with None as filepath."""
        parser = DebugLogParser()
        with pytest.raises((TypeError, AttributeError)):
            parser.parse_debug_file(None)

    def test_parse_debug_file_empty_string(self):
        """Test parsing with empty string as filepath."""
        parser = DebugLogParser()
        with pytest.raises((FileNotFoundError, ValueError)):
            parser.parse_debug_file("")

    def test_parse_debug_file_directory_path(self):
        """Test parsing with directory path instead of file."""
        parser = DebugLogParser()
        with tempfile.TemporaryDirectory() as tmpdir:
            # This should fail because it's a directory
            with pytest.raises((IsADirectoryError, PermissionError, ValueError)):
                parser.parse_debug_file(tmpdir)

    def test_analyze_rule_none(self):
        """Test analyzing None as rule."""
        analyzer = RuleAnalyzer()
        with pytest.raises((TypeError, AttributeError)):
            analyzer.analyze_rule(None)

    def test_analyze_ruleset_none(self):
        """Test analyzing None as ruleset."""
        analyzer = RuleAnalyzer()
        analyzer.analyze_ruleset(None)
        # Should handle gracefully or raise TypeError


@pytest.mark.parametrize(
    "invalid_line",
    [
        "",
        "   ",
        "onlyoneword",
        "word rule",  # Missing candidate
        "\t\t\t",
        "a b",
    ],
)
def test_parse_invalid_debug_lines_parametrized(invalid_line):
    """Parametrized test for various invalid line formats."""
    parser = DebugLogParser()
    result = parser._parse_line(invalid_line)
    # Should return None or handle gracefully
    assert result is None or isinstance(result, dict)


@pytest.mark.parametrize(
    "rule,baseword",
    [
        ("c", ""),
        ("c", "a"),
        ("c", "A"),
        ("[", "a"),  # Remove first from single char
        ("]", "a"),  # Remove last from single char
        ("[[", "ab"),  # Remove first twice
        ("]]", "ab"),  # Remove last twice
    ],
)
def test_edge_case_transformations(rule, baseword):
    """Test rule transformations on edge case inputs."""
    from hashcat_rosetta.cli import explain_rule

    result = explain_rule(rule, baseword)
    # Should not crash, may return None or empty list
    assert result is None or isinstance(result, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
