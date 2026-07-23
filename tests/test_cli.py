"""Test suite for CLI interface."""

import json

import pytest
from click.testing import CliRunner

from hashcat_rosetta.cli import explain_rule, main


# Shared fixtures

SAMPLE_DEBUG_LINES = (
    "password c Password\n"
    "password u PASSWORD\n"
    "password l password\n"
    "admin c Admin\n"
    "admin u ADMIN\n"
    "test d testtest\n"
)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def debug_file(tmp_path):
    path = tmp_path / "debug.txt"
    path.write_text(SAMPLE_DEBUG_LINES)
    return str(path)


@pytest.fixture
def rule_file(tmp_path):
    path = tmp_path / "rules.rule"
    path.write_text("c\nu\nl\n$1\n^!\nsa@\n")
    return str(path)


# Mode-5 debug output: baseword:rule:candidate:wordlist
SAMPLE_DEBUG_LINES_MODE5 = (
    "password:c:Password:rockyou.txt\n"
    "password:u:PASSWORD:rockyou.txt\n"
    "admin:c:Admin:rockyou.txt\n"
    "letmein:$1:letmein1:common.txt\n"
    "letmein:c:Letmein:common.txt\n"
)


@pytest.fixture
def debug_file_mode5(tmp_path):
    path = tmp_path / "debug5.txt"
    path.write_text(SAMPLE_DEBUG_LINES_MODE5)
    return str(path)


# --- Default summary output ---


class TestDefaultSummary:
    def test_default_summary(self, runner, debug_file):
        result = runner.invoke(main, [debug_file])
        assert result.exit_code == 0
        assert "Debug File Analysis" in result.output
        assert "Total Entries" in result.output
        assert "Unique Rules" in result.output
        assert "Unique Basewords" in result.output

    def test_default_summary_shows_statistics(self, runner, debug_file):
        result = runner.invoke(main, [debug_file])
        assert "Rule Statistics" in result.output
        assert "Baseword Statistics" in result.output


# --- --rules flag with metrics ---


class TestRulesFlag:
    def test_rules_frequency(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--rules", "--metric", "frequency"])
        assert result.exit_code == 0
        assert "by Frequency" in result.output

    def test_rules_basewords(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--rules", "--metric", "basewords"])
        assert result.exit_code == 0
        assert "by Unique Basewords" in result.output

    def test_rules_candidates(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--rules", "--metric", "candidates"])
        assert result.exit_code == 0
        assert "by Unique Candidates" in result.output


# --- --basewords flag ---


class TestBasewordsFlag:
    def test_basewords(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--basewords"])
        assert result.exit_code == 0
        assert "occurrences" in result.output

    def test_basewords_detail(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--basewords", "--detail"])
        assert result.exit_code == 0
        assert "Unique Rules" in result.output
        assert "Rules Applied" in result.output


# --- --wordlists flag / --debug-mode (mode 5) ---


class TestWordlistsFlag:
    def test_debug_mode_5_wordlists(self, runner, debug_file_mode5):
        result = runner.invoke(main, [debug_file_mode5, "--debug-mode", "5", "--wordlists"])
        assert result.exit_code == 0
        assert "Wordlists" in result.output
        assert "rockyou.txt" in result.output
        assert "common.txt" in result.output

    def test_wordlists_detail(self, runner, debug_file_mode5):
        result = runner.invoke(
            main, [debug_file_mode5, "--debug-mode", "5", "--wordlists", "--detail"]
        )
        assert result.exit_code == 0
        assert "rockyou.txt" in result.output
        assert "Unique Basewords" in result.output
        assert "Unique Candidates" in result.output
        assert "Unique Rules" in result.output

    def test_wordlists_alone_no_default_summary(self, runner, debug_file_mode5):
        result = runner.invoke(main, [debug_file_mode5, "--debug-mode", "5", "--wordlists"])
        assert result.exit_code == 0
        # Default summary header must NOT appear when --wordlists is given alone.
        assert "Debug File Analysis" not in result.output

    def test_default_summary_mode5_includes_wordlist_stats(self, runner, debug_file_mode5):
        result = runner.invoke(main, [debug_file_mode5, "--debug-mode", "5"])
        assert result.exit_code == 0
        assert "Debug File Analysis" in result.output
        assert "Wordlist Statistics" in result.output
        assert "rockyou.txt" in result.output

    def test_default_summary_mode4_no_wordlist_section(self, runner, debug_file):
        result = runner.invoke(main, [debug_file])
        assert result.exit_code == 0
        assert "Debug File Analysis" in result.output
        # A mode-4 file has no wordlist data; no wordlist section should print.
        assert "Wordlist" not in result.output

    def test_debug_mode_4_forces_mode4(self, runner, debug_file_mode5):
        """Forcing mode 4 on a mode-5-looking file: no wordlist attribution."""
        result = runner.invoke(main, [debug_file_mode5, "--debug-mode", "4", "--wordlists"])
        assert result.exit_code == 0
        # No wordlist data parsed, so the wordlist names do not appear as entries.
        assert "rockyou.txt" not in result.output
        assert "common.txt" not in result.output

    def test_wordlists_auto_detect_no_debug_mode(self, runner, debug_file_mode5):
        """Without --debug-mode, 'auto' must detect mode 5 and attribute wordlists."""
        result = runner.invoke(main, [debug_file_mode5, "--wordlists"])
        assert result.exit_code == 0
        assert "rockyou.txt" in result.output
        assert "common.txt" in result.output


# --- --export flag ---


class TestExportFlag:
    def test_export_json(self, runner, debug_file, tmp_path):
        export_path = str(tmp_path / "report.json")
        result = runner.invoke(main, [debug_file, "--export", export_path, "--format", "json"])
        assert result.exit_code == 0
        assert "JSON report exported" in result.output
        with open(export_path) as f:
            data = json.load(f)
        assert "summary" in data
        assert "top_rules_by_frequency" in data

    def test_export_csv(self, runner, debug_file, tmp_path):
        export_path = str(tmp_path / "report.csv")
        result = runner.invoke(main, [debug_file, "--export", export_path, "--format", "csv"])
        assert result.exit_code == 0
        assert "CSV report exported" in result.output
        with open(export_path) as f:
            content = f.read()
        assert "Rule" in content
        assert "Baseword" in content

    def test_export_csv_mode5_includes_wordlist_section(self, runner, debug_file_mode5, tmp_path):
        export_path = str(tmp_path / "report.csv")
        result = runner.invoke(main, [debug_file_mode5, "--export", export_path, "--format", "csv"])
        assert result.exit_code == 0
        assert "CSV report exported" in result.output
        with open(export_path) as f:
            content = f.read()
        assert "# WORDLIST ANALYSIS" in content
        assert "Wordlist" in content
        assert "rockyou.txt" in content
        assert "common.txt" in content


# --- --explain flag ---


class TestExplainFlag:
    def test_explain_single_rule(self, runner):
        result = runner.invoke(main, ["--explain", "c"])
        assert result.exit_code == 0
        assert "Rule Explanation" in result.output
        assert "Capitalize" in result.output

    def test_explain_complex_rule(self, runner):
        result = runner.invoke(main, ["--explain", "c$1", "--baseword", "admin"])
        assert result.exit_code == 0
        assert "admin" in result.output.lower() or "Admin" in result.output

    def test_explain_rule_file(self, runner, rule_file):
        result = runner.invoke(main, ["--explain", rule_file])
        assert result.exit_code == 0
        assert "Rule File Explanation" in result.output

    def test_explain_unknown_rule(self, runner):
        result = runner.invoke(main, ["--explain", "Q"])
        assert result.exit_code == 0
        assert "Unknown rule" in result.output


# --- --analyze-rules flag ---


class TestAnalyzeRulesFlag:
    def test_analyze_rules(self, runner, rule_file):
        result = runner.invoke(main, [rule_file, "--analyze-rules"])
        assert result.exit_code == 0
        assert "Opcode" in result.output or "opcode" in result.output.lower()


# --- Error paths ---


class TestErrorPaths:
    def test_missing_file(self, runner):
        """FILE is required when not using --explain."""
        result = runner.invoke(main, [])
        assert result.exit_code != 0
        assert "FILE is required" in result.output or "Error" in result.output

    def test_invalid_debug_content(self, runner, tmp_path):
        """A file that exists but has no valid debug entries raises ValueError."""
        bad_file = tmp_path / "bad.txt"
        bad_file.write_text("singleword\n" * 5)
        result = runner.invoke(main, [str(bad_file)])
        assert result.exit_code != 0
        assert "Error" in result.output


# --- export_to_dict JSON serialization ---


class TestExportSerialization:
    def test_export_to_dict_is_json_serializable(self):
        from hashcat_rosetta import DebugAnalyzer

        analyzer = DebugAnalyzer()
        lines = [
            "password c Password",
            "password u PASSWORD",
            "admin c Admin",
        ]
        analyzer.analyze_debug_lines(lines)
        data = analyzer.export_to_dict()
        # Must not raise
        serialized = json.dumps(data)
        assert isinstance(serialized, str)
        roundtrip = json.loads(serialized)
        assert roundtrip["summary"]["total_entries"] == 3


# --- explain_rule() edge cases ---


class TestExplainRuleEdgeCases:
    def test_empty_rule(self):
        assert explain_rule("") is None

    def test_unknown_opcodes_only(self):
        """A string of characters not in rule_map and not parameterized."""
        result = explain_rule("QQQ")
        assert result is None

    def test_incomplete_append(self):
        """$ at end of string with no following char."""
        result = explain_rule("$")
        assert result is None

    def test_incomplete_prepend(self):
        result = explain_rule("^")
        assert result is None

    def test_incomplete_insert(self):
        """i needs 2 params - if only 1 is provided, skip."""
        result = explain_rule("i7")
        assert result is None

    def test_incomplete_substitute(self):
        # 's' needs 2 arguments (sXY). "sa" has only one char after 's', so 's' is
        # skipped as incomplete. 'a' is then processed as the append-memorized opcode.
        result = explain_rule("sa")
        assert result is not None  # 'a' (append memorized) produces a step

    def test_incomplete_delete_pos(self):
        """D at end with no position."""
        result = explain_rule("D")
        assert result is None

    def test_incomplete_toggle_pos(self):
        result = explain_rule("T")
        assert result is None

    def test_mixed_known_and_unknown(self):
        """Known ops produce steps, unknown chars are skipped."""
        result = explain_rule("cQ")
        assert result is not None
        assert len(result) == 1
        assert "Capitalize" in result[0]

    def test_all_simple_ops(self):
        """Verify all simple ops in rule_map produce output."""
        simple_ops = ":culdrt[]{}fkKqE"
        for op in simple_ops:
            result = explain_rule(op, "password")
            assert result is not None, f"Op '{op}' returned None"
            assert len(result) == 1

    def test_p_opcode_duplicate_word(self):
        """p is a 1-arg op: pN appends duplicated word N times."""
        result = explain_rule("p2", "abc")
        assert result is not None
        assert "abcabcabc" in result[0]

    def test_hex_position_insert(self):
        """Insert at hex position (A = 10)."""
        result = explain_rule("iA!")
        assert result is not None
        assert "pos 10" in result[0]

    def test_substitute_rule(self):
        result = explain_rule("sao", "banana")
        assert result is not None
        assert "bonono" in result[0] or "Substitute" in result[0]

    def test_delete_at_position(self):
        result = explain_rule("D0", "hello")
        assert result is not None
        assert "ello" in result[0]

    def test_toggle_at_position(self):
        result = explain_rule("T0", "hello")
        assert result is not None
        assert "Hello" in result[0]
