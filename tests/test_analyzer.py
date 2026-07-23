"""Test suite for hashcat rule analyzer."""

import pytest
import tempfile
import os
from hashcat_rosetta import RuleParser, RuleAnalyzer, DebugLogParser, DebugAnalyzer


class TestRuleParser:
    """Tests for RuleParser class."""

    def test_parse_empty_rule(self):
        """Test parsing an empty rule."""
        parser = RuleParser()
        result = parser.parse_rule("")
        assert result is None

    def test_parse_comment(self):
        """Test parsing a comment."""
        parser = RuleParser()
        result = parser.parse_rule("# This is a comment")
        assert result is None

    def test_parse_simple_rule(self):
        """Test parsing a simple rule."""
        parser = RuleParser()
        result = parser.parse_rule("u")
        assert result is not None
        assert result["original"] == "u"
        assert len(result["components"]) > 0

    def test_parse_complex_rule(self):
        """Test parsing a complex rule."""
        parser = RuleParser()
        result = parser.parse_rule("^1^2s11o9")
        assert result is not None
        assert result["original"] == "^1^2s11o9"


class TestRuleAnalyzer:
    """Tests for RuleAnalyzer class."""

    def test_analyze_rule(self):
        """Test analyzing a single rule."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("u")
        assert result is not None
        assert result["rule"] == "u"
        assert "efficiency_score" in result
        assert "complexity" in result

    def test_analyze_ruleset(self):
        """Test analyzing multiple rules."""
        analyzer = RuleAnalyzer()
        rules = ["u", "l", "c"]
        result = analyzer.analyze_ruleset(rules)
        assert result is not None
        assert result["total_rules"] == 3
        assert "average_complexity" in result
        assert "average_efficiency" in result

    def test_efficiency_score(self):
        """Test efficiency score calculation."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_rule("u")
        assert 0 <= result["efficiency_score"] <= 100

    def test_empty_ruleset(self):
        """Test analyzing empty ruleset."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_ruleset([])
        assert result is None


class TestDebugLogParser:
    """Tests for DebugLogParser class."""

    def test_parse_valid_line(self):
        """Test parsing a simple debug line (space-separated)."""
        parser = DebugLogParser()
        line = "password c P@ssword"
        result = parser._parse_line(line)
        assert result is not None
        assert result["baseword"] == "password"
        assert result["rule"] == "c"
        assert result["candidate"] == "P@ssword"

    def test_parse_colon_separated_line(self):
        """Test parsing a colon-separated debug line (older hashcat format)."""
        parser = DebugLogParser()
        line = "COMPUTER:} } } } t:retupmoc"
        result = parser._parse_line(line)
        assert result is not None
        assert result["baseword"] == "COMPUTER"
        assert result["rule"] == "} } } } t"
        assert result["candidate"] == "retupmoc"

    def test_parse_empty_line(self):
        """Test parsing an empty line."""
        parser = DebugLogParser()
        result = parser._parse_line("")
        assert result is None

    def test_parse_comment_line(self):
        """Test parsing a comment line."""
        parser = DebugLogParser()
        result = parser._parse_line("# This is a comment")
        assert result is None

    def test_parse_multiple_lines(self):
        """Test parsing multiple debug lines."""
        parser = DebugLogParser()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "admin l admin",
        ]
        results = parser.parse_debug_lines(lines)
        assert len(results) == 3
        assert results[0]["baseword"] == "password"
        assert results[1]["rule"] == "u"
        assert results[2]["candidate"] == "admin"

    def test_parse_debug_file(self):
        """Test parsing a debug file."""
        parser = DebugLogParser()
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("password c P@ssword\n")
            f.write("password u PASSWORD\n")
            f.write("admin l admin\n")
            f.flush()
            filepath = f.name

        try:
            results = parser.parse_debug_file(filepath)
            assert len(results) == 3
            assert results[0]["baseword"] == "password"
            assert results[1]["rule"] == "u"
            assert results[2]["candidate"] == "admin"
        finally:
            os.unlink(filepath)

    def test_parse_debug_file_not_found(self):
        """Test parsing a non-existent file."""
        parser = DebugLogParser()
        with pytest.raises(FileNotFoundError):
            parser.parse_debug_file("/nonexistent/file.txt")


class TestDebugAnalyzer:
    """Tests for DebugAnalyzer class."""

    def test_analyze_debug_lines(self):
        """Test analyzing debug output lines."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "admin c Admin",
            "admin u ADMIN",
        ]
        result = analyzer.analyze_debug_lines(lines)
        assert result["total_entries"] == 5
        assert result["unique_rules"] == 3  # c, u, l
        assert result["unique_basewords"] == 2  # password, admin

    def test_get_top_rules_by_frequency(self):
        """Test getting top rules by frequency."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "admin c Admin",
            "admin u ADMIN",
        ]
        analyzer.analyze_debug_lines(lines)
        top_rules = analyzer.get_top_rules_by_frequency(10)
        # c and u appear twice, l appears once
        assert len(top_rules) > 0
        assert top_rules[0][1] == 2  # frequency of top rule

    def test_get_top_basewords_by_frequency(self):
        """Test getting top basewords by frequency."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "admin c Admin",
            "admin u ADMIN",
        ]
        analyzer.analyze_debug_lines(lines)
        top_basewords = analyzer.get_top_basewords_by_frequency(10)
        assert len(top_basewords) == 2
        assert top_basewords[0][0] == "password"  # appears 3 times
        assert top_basewords[0][1] == 3

    def test_get_basewords_with_min_occurrences(self):
        """Test getting basewords with minimum occurrences."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "admin c Admin",
            "admin u ADMIN",
            "test d testtest",
        ]
        analyzer.analyze_debug_lines(lines)
        basewords = analyzer.get_basewords_with_min_occurrences(2)
        # password appears 3 times, admin appears 2 times
        assert len(basewords) == 2
        assert basewords[0][0] == "password"

    def test_get_baseword_detail(self):
        """Test getting detailed baseword information."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
        ]
        analyzer.analyze_debug_lines(lines)
        detail = analyzer.get_baseword_detail("password")
        assert detail["baseword"] == "password"
        assert detail["total_occurrences"] == 3
        assert detail["unique_rules"] == 3  # c, u, l

    def test_get_rule_detail(self):
        """Test getting detailed rule information."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "admin c Admin",
        ]
        analyzer.analyze_debug_lines(lines)
        detail = analyzer.get_rule_detail("c")
        assert detail["rule"] == "c"
        assert detail["total_applications"] == 2
        assert detail["unique_basewords"] == 2

    def test_rule_statistics_summary(self):
        """Test rule statistics summary."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "admin c Admin",
        ]
        analyzer.analyze_debug_lines(lines)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["total_rules"] == 3  # c, u, l
        assert summary["total_applications"] == 4

    def test_baseword_statistics_summary(self):
        """Test baseword statistics summary."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "password l password",
            "admin c Admin",
        ]
        analyzer.analyze_debug_lines(lines)
        summary = analyzer.get_baseword_statistics_summary()
        assert summary["total_basewords"] == 2
        assert summary["total_occurrences"] == 4

    def test_export_to_dict(self):
        """Test exporting analysis to dictionary."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
        ]
        analyzer.analyze_debug_lines(lines)
        export = analyzer.export_to_dict()
        assert "summary" in export
        assert "top_rules_by_frequency" in export
        assert "top_basewords" in export


class TestDebugAnalyzerWordlists:
    """Tests for wordlist aggregation (mode-5 support) in DebugAnalyzer."""

    def test_wordlist_aggregation(self):
        """Test per-wordlist aggregation from mode-5 entries."""
        analyzer = DebugAnalyzer(debug_mode=5)
        lines = [
            "password:c:Password:rockyou.txt",
            "password:u:PASSWORD:rockyou.txt",
            "admin:c:Admin:rockyou.txt",
            "root:l:root:common.txt",
        ]
        result = analyzer.analyze_debug_lines(lines)
        assert result["unique_wordlists"] == 2

        rockyou = analyzer.get_wordlist_detail("rockyou.txt")
        assert rockyou is not None
        assert rockyou["total_occurrences"] == 3
        assert rockyou["basewords"] == ["admin", "password"]
        assert rockyou["candidates"] == ["Admin", "PASSWORD", "Password"]
        assert rockyou["rules"] == ["c", "u"]

        common = analyzer.get_wordlist_detail("common.txt")
        assert common is not None
        assert common["total_occurrences"] == 1
        assert common["basewords"] == ["root"]
        assert common["rules"] == ["l"]

    def test_mode4_input_no_wordlists(self):
        """Test that mode-4 input (wordlist None) creates no wordlist buckets."""
        analyzer = DebugAnalyzer()
        lines = [
            "password c P@ssword",
            "password u PASSWORD",
            "admin c Admin",
        ]
        result = analyzer.analyze_debug_lines(lines)
        assert result["unique_wordlists"] == 0
        assert len(analyzer.wordlist_stats) == 0
        assert analyzer.get_top_wordlists() == []
        assert analyzer.get_wordlist_statistics_summary() == {}

    def test_get_top_wordlists_ordering(self):
        """Test top wordlists are ordered by count descending."""
        analyzer = DebugAnalyzer(debug_mode=5)
        lines = [
            "a:c:A:big.txt",
            "b:c:B:big.txt",
            "c:c:C:big.txt",
            "d:c:D:mid.txt",
            "e:c:E:mid.txt",
            "f:c:F:small.txt",
        ]
        analyzer.analyze_debug_lines(lines)
        top = analyzer.get_top_wordlists()
        assert top == [("big.txt", 3), ("mid.txt", 2), ("small.txt", 1)]

    def test_export_includes_wordlist_section(self):
        """Test export_to_dict includes a JSON-serializable wordlist section."""
        import json

        analyzer = DebugAnalyzer(debug_mode=5)
        lines = [
            "password:c:Password:rockyou.txt",
            "admin:c:Admin:rockyou.txt",
        ]
        analyzer.analyze_debug_lines(lines)
        export = analyzer.export_to_dict()
        assert "top_wordlists" in export
        assert "wordlists" in export["summary"]
        assert "wordlist_summary" not in export
        assert "all_wordlist_details" in export
        # Must be JSON-serializable (no sets leaking through).
        json.dumps(export)

    def test_get_wordlist_detail(self):
        """Test getting detail for a wordlist, and None for an unknown one."""
        analyzer = DebugAnalyzer(debug_mode=5)
        lines = [
            "password:c:Password:rockyou.txt",
            "password:u:PASSWORD:rockyou.txt",
            "admin:c:Admin:rockyou.txt",
        ]
        analyzer.analyze_debug_lines(lines)
        detail = analyzer.get_wordlist_detail("rockyou.txt")
        assert detail is not None
        assert detail["wordlist"] == "rockyou.txt"
        assert detail["total_occurrences"] == 3
        assert detail["unique_basewords"] == 2
        assert detail["unique_candidates"] == 3
        assert detail["unique_rules"] == 2
        assert analyzer.get_wordlist_detail("missing.txt") is None

    def test_wordlist_match_count_surfaced(self):
        """match_count for matched mode-5 entries flows to detail and summary."""
        analyzer = DebugAnalyzer(debug_mode=5)
        # Parser sets matched=False by default; inject entries directly and
        # recompute, mirroring how the rule/baseword match tests do it.
        analyzer.entries = [
            {
                "baseword": "password",
                "rule": "c",
                "candidate": "Password",
                "wordlist": "rockyou.txt",
                "matched": True,
            },
            {
                "baseword": "admin",
                "rule": "c",
                "candidate": "Admin",
                "wordlist": "rockyou.txt",
                "matched": False,
            },
        ]
        analyzer._compute_analysis()

        detail = analyzer.get_wordlist_detail("rockyou.txt")
        assert detail is not None
        assert detail["match_count"] == 1

        summary = analyzer.get_wordlist_statistics_summary()
        assert summary["total_match_count"] == 1


if __name__ == "__main__":
    pytest.main([__file__])
