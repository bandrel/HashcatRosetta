"""Test suite for CLI interface."""

import json

import pytest
from click.testing import CliRunner

from hashcat_rosetta.cli import _escape_bytes, explain_rule, main


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

    def test_explain_high_byte_rule_file_overwrite(self, runner, high_byte_rule_file):
        """A raw 0xBA byte in the rule file must not raise UnicodeDecodeError."""
        result = runner.invoke(main, ["--explain", high_byte_rule_file])
        assert result.exit_code == 0
        assert "o1\\xba: Overwrite pos 1" in result.output

    def test_explain_high_byte_rule_file_preserves_trailing_space(
        self, runner, high_byte_rule_file
    ):
        """`$ ` (append a literal space) must not be collapsed to `$` by strip()."""
        result = runner.invoke(main, ["--explain", high_byte_rule_file])
        assert result.exit_code == 0
        assert "Append ' '" in result.output
        # The transformed candidate must retain the trailing space: default
        # baseword "password" becomes "password " (with a trailing space), not
        # "password" (which is what a lost/stripped space argument would produce).
        assert "→ password \n" in result.output

    def test_explain_high_byte_rule_file_escapes_output_bytes(self, runner, high_byte_rule_file):
        """Output must be escaped ASCII (b"\\xba"), never a raw/UTF-8-encoded high byte."""
        result = runner.invoke(main, ["--explain", high_byte_rule_file])
        assert result.exit_code == 0
        stdout_bytes = result.stdout_bytes
        assert b"o1\\xba" in stdout_bytes
        assert b"\xc2\xba" not in stdout_bytes

    def test_explain_high_byte_rule_file_skips_comment_and_blank(self, runner, high_byte_rule_file):
        result = runner.invoke(main, ["--explain", high_byte_rule_file])
        assert result.exit_code == 0
        assert "# comment" not in result.output
        assert "Line 4" not in result.output
        assert "Line 5" not in result.output
        assert "Line 6: c" in result.output
        assert "Capitalize" in result.output

    def test_explain_skips_indented_comment_and_blank_but_keeps_space_arg(
        self, runner, indented_comment_rule_file
    ):
        """An indented "#" comment and a whitespace-only line must be skipped,
        while a real rule's trailing-space argument must still survive.

        The skip decision has to be made on the *stripped* line -- otherwise
        "  # note" doesn't start with "#" (it starts with a space) and gets
        explained as a bogus rule, and "   " is treated as a real (blank)
        rule line instead of being skipped. But the line actually handed to
        explain_rule/echoed must stay un-stripped, or "$ " loses its
        trailing-space argument -- which is the inverse mistake this test
        also catches: if the fix regresses to using the stripped line for
        explain_rule, the transformed candidate loses its trailing space.
        """
        result = runner.invoke(main, ["--explain", indented_comment_rule_file])
        assert result.exit_code == 0
        assert "# note" not in result.output
        assert "Line 1" not in result.output
        assert "Line 2" not in result.output
        assert "Line 3: $ " in result.output
        assert "Append ' '" in result.output
        # The transformed candidate must retain the trailing space.
        assert "→ password \n" in result.output
        assert "Line 4: c" in result.output
        assert "Capitalize" in result.output


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


class TestHelpMatchesEntryPoint:
    """Regression guard: --help examples must use the real registered command name.

    The docstring previously showed `rosetta ...` while pyproject.toml registers
    `hashcat-rosetta` as the entry point, so copy-pasting --help output failed.
    """

    def test_help_uses_registered_entry_point_name(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "hashcat-rosetta " in result.output
        assert "rosetta " not in result.output.replace("hashcat-rosetta ", "")


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

    def test_opcode_3_consumes_two_args_in_fallback(self):
        """'3' is a 2-arg op (3NX); the fallback skip must consume both args so a
        following opcode is explained correctly rather than being swallowed."""
        result = explain_rule("31s$1", "password")
        assert result is not None
        # After '31s' is skipped (3 chars), '$1' must be explained as an append.
        assert any(step.startswith("$1:") and "Append" in step for step in result)

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


class TestAsciiOnlyCasing:
    """hashcat case ops (l u c C t E e T 3) only affect ASCII A-Z/a-z; they
    leave high bytes (0x80-0xFF) untouched. Python str casing does not, which
    diverged after L/R/B/+/- produced accented bytes (issue: BARRAGE 'L6 l')."""

    def _f(self, rule, bw):
        s = explain_rule(rule, bw)
        assert s is not None
        # strip only the ASCII spaces around the arrow, not high bytes like
        # 0xA0 (NBSP) which str.strip() would wrongly remove.
        return s[-1].split("→")[-1].strip(" ")

    def test_lower_leaves_high_byte(self):
        assert self._f("l", "\xc8") == "\xc8"  # 'È' stays (python would give è)

    def test_upper_leaves_high_byte(self):
        assert self._f("u", "\xe8") == "\xe8"  # 'è' stays

    def test_toggle_leaves_high_byte(self):
        assert self._f("t", "\xc8") == "\xc8"

    def test_L_then_lower_matches_hashcat(self):
        # 'L6 l' on 'password': L shifts byte 6 ('r'=0x72<<1=0xe4)... use the
        # observed repro pattern; the high byte must not be case-mapped.
        out = self._f("L0 l", "Password")  # L0: 'P'=0x50<<1=0xa0; l leaves 0xa0
        assert out == "\xa0assword"

    def test_ascii_casing_unchanged(self):
        assert self._f("u", "abc") == "ABC"
        assert self._f("l", "ABC") == "abc"
        assert self._f("c", "hELLO") == "Hello"
        assert self._f("t", "aBc") == "AbC"


class TestExplainToggleAtSep:
    """3NX: toggle case of the char after the Nth (0-indexed) occurrence of
    separator X. Values verified against hashcat --stdout."""

    def _final(self, rule, bw):
        steps = explain_rule(rule, bw)
        assert steps is not None, f"{rule} returned None"
        return steps[-1].split("→")[-1].strip()

    def test_3_first_occurrence(self):
        assert self._final("30s", "password") == "pasSword"

    def test_3_second_occurrence(self):
        assert self._final("31s", "password") == "passWord"

    def test_3_missing_occurrence_noop(self):
        assert self._final("32s", "password") == "password"

    def test_3_nonletter_after_sep_noop(self):
        assert self._final("30.", "a.1b") == "a.1b"

    def test_3_letter_after_sep(self):
        assert self._final("30.", "a.b") == "a.B"


class TestHexEscapeDecoding:
    """hashcat decodes \\xNN byte escapes in rules; explain_rule must too, so
    its output matches hashcat for BARRAGE rules that use them."""

    def test_substitute_space_via_hex_escape(self):
        # s\x20X = substitute space -> X. hashcat 'a b' -> 'aXb'.
        steps = explain_rule("s\\x20X", "a b")
        assert steps is not None
        assert steps[-1].split("→")[-1].strip() == "aXb"

    def test_append_hex_escape(self):
        # $\x41 = append 'A' (0x41). 'ab' -> 'abA'.
        steps = explain_rule("$\\x41", "ab")
        assert steps is not None
        assert steps[-1].split("→")[-1].strip() == "abA"

    def test_hex_escape_not_mistokenized(self):
        # \x73 = 's'; $\x73 must be "append 's'", not a substitute op.
        steps = explain_rule("$\\x73", "ab")
        assert steps is not None
        assert steps[-1].split("→")[-1].strip() == "abs"

    def test_non_hex_backslash_left_literal(self):
        # A backslash not forming \xNN is a literal char (append it).
        steps = explain_rule("$\\", "ab")
        assert steps is not None
        assert steps[-1].split("→")[-1].strip() == "ab\\"


class TestEscapeBytesHelper:
    """_escape_bytes renders raw bytes for display without touching genuine
    Unicode (issue #31)."""

    def test_high_byte_escaped(self):
        assert _escape_bytes("\x99ello0") == "\\x99ello0"

    def test_control_byte_escaped(self):
        assert _escape_bytes("\x00abc") == "\\x00abc"
        assert _escape_bytes("\x1f") == "\\x1f"

    def test_printable_ascii_unchanged(self):
        assert _escape_bytes("hello0!") == "hello0!"

    def test_unicode_above_ff_unchanged(self):
        # The '→' arrow (U+2192) is >= 0x100 and must be left intact.
        assert _escape_bytes("a → b") == "a → b"


class TestExplainBytewiseWrap:
    """explain_rule keeps raw byte values internally (so the verify harness can
    compare against hashcat) and wraps +/- mod 256 like hashcat (issue #31)."""

    def test_explain_returns_raw_high_byte(self):
        # B01 on 'hello0': 0x68 + 0x31 = 0x99. explain_rule returns the raw code
        # point; escaping for display happens only in the CLI layer.
        steps = explain_rule("B01", "hello0")
        assert steps is not None
        assert "\x99ello0" in steps[-1]

    def test_increment_wraps_mod_256(self):
        # '+0' on byte 0xff wraps to 0x00 (verified against hashcat).
        steps = explain_rule("+0", "\xffabc")
        assert steps is not None
        assert "\x00abc" in steps[-1]

    def test_decrement_wraps_mod_256_no_crash(self):
        # '-0' on byte 0x00 wraps to 0xff (verified against hashcat). Previously
        # chr(-1) raised ValueError and the step was silently dropped.
        steps = explain_rule("-0", "\x00abc")
        assert steps is not None
        assert "\xffabc" in steps[-1]


class TestExplainCliByteRendering:
    """The --explain CLI output must render high bytes as \\xNN, never as a
    UTF-8-mis-encoded multibyte sequence (issue #31)."""

    def test_cli_explain_escapes_high_byte(self, runner):
        result = runner.invoke(main, ["--explain", "B01", "--baseword", "hello0"])
        assert result.exit_code == 0
        assert "\\x99ello0" in result.output
        # The raw U+0099 code point (which would UTF-8-encode to c2 99) must not
        # appear in the user-facing output.
        assert "\x99" not in result.output
