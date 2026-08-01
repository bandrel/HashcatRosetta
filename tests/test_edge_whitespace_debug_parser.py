"""Edge-whitespace tests for DebugLogParser.parse_debug_file.

parse_debug_file used a full `.strip()` on each raw line rather than
stripping only the line terminator. `.strip()` removes whitespace from
*both* ends of the raw line, not just the terminator. Since baseword is the
first colon-separated field, a baseword that legitimately starts with a
space (a real password candidate) had that leading space silently deleted.
Symmetrically, a trailing field (candidate for mode 4, wordlist for mode 5)
that ends with a space had that space deleted too. The fix replaces
`.strip()` with `rstrip("\\r\\n")` at both call sites (the per-line parse
call and the `sample` list used for format/mode detection).

Note: this file only covers the whitespace-stripping bug. The encoding
(utf-8 + errors="ignore") is left as-is by design for debug-log parsing --
see the comment at parser.py's parse_debug_file open() call -- so there is
no test here for non-UTF-8 byte preservation in debug logs (compare to
tests/test_byte_safe_analyze_rules.py, which covers the rule-file reader
that *is* byte-safe via latin-1).

These tests use the shared fixtures in tests/fixtures/high_byte_rules.py
(registered globally via tests/conftest.py's pytest_plugins).
"""

from hashcat_rosetta.parser import DebugLogParser, _DETECTION_SAMPLE_SIZE


def _mode5_colon_line(n: int) -> str:
    return f"password{n}:c:Password{n}:rockyou.txt\n"


class TestDebugParserWhitespaceOnlyLinesDoNotStarveDetectionSample:
    """Regression test: whitespace-only lines must not survive into the
    format/mode detection sample.

    parse_debug_file's sample-building filter changed from `if line.strip()`
    to `if line.rstrip("\\r\\n")`. A truly empty line ("\\n") rstrips to ""
    (falsy) and is still filtered, but a whitespace-only line (e.g. "   \\n")
    rstrips to "   " (truthy) and now survives into the sample. Since the
    sample is capped at _DETECTION_SAMPLE_SIZE (20) lines, and whitespace-only
    lines cast no format/mode vote but still consume a slot, enough of them
    prepended before the real data starves the real lines out of the sample
    entirely -- silently degrading mode-5 detection to mode-4, and eventually
    raising "No valid debug entries found" even though every real line in the
    file is well-formed mode-5 colon data.
    """

    def _build_file(self, tmp_path, num_whitespace_lines, num_real_lines=50):
        lines = ["   \n"] * num_whitespace_lines
        lines += [_mode5_colon_line(i) for i in range(num_real_lines)]
        path = tmp_path / "whitespace_starved.log"
        path.write_text("".join(lines))
        return str(path)

    def test_whitespace_only_lines_excluded_from_detection_sample_directly(self):
        sample_input = ["   \n", "\t\n", "password:c:Password:rockyou.txt\n"]
        # Mirrors the filter used to build `sample` in parse_debug_file.
        sample = [
            line.rstrip("\r\n")
            for line in sample_input
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert sample == ["password:c:Password:rockyou.txt"]

    def test_whitespace_only_lines_do_not_degrade_mode_detection(self, tmp_path):
        # Fewer whitespace-only lines than the sample cap: real lines still
        # get in, but should not be diluted.
        filepath = self._build_file(tmp_path, num_whitespace_lines=5)
        parser = DebugLogParser()
        entries = parser.parse_debug_file(filepath)
        assert parser._mode == 5
        assert len(entries) == 50
        assert entries[0]["wordlist"] == "rockyou.txt"
        assert entries[0]["candidate"] == "Password0"

    def test_whitespace_only_lines_at_sample_cap_do_not_break_mode5_detection(self, tmp_path):
        # Exactly _DETECTION_SAMPLE_SIZE whitespace-only lines prepended: under
        # the bug, this fully starves the sample of real lines, silently
        # degrading detection from mode 5 to mode 4 (wordlist attribution
        # destroyed) instead of raising or correctly detecting mode 5.
        filepath = self._build_file(tmp_path, num_whitespace_lines=_DETECTION_SAMPLE_SIZE)
        parser = DebugLogParser()
        entries = parser.parse_debug_file(filepath)
        assert parser._mode == 5
        assert len(entries) == 50
        assert entries[0]["wordlist"] == "rockyou.txt"

    def test_whitespace_only_lines_beyond_sample_cap_do_not_raise(self, tmp_path):
        # Twice the sample cap of whitespace-only lines prepended: under the
        # bug, this raises ValueError("No valid debug entries found") even
        # though every real line in the file is well-formed mode-5 data.
        filepath = self._build_file(tmp_path, num_whitespace_lines=_DETECTION_SAMPLE_SIZE * 2)
        parser = DebugLogParser()
        entries = parser.parse_debug_file(filepath)
        assert parser._mode == 5
        assert len(entries) == 50


class TestParseDebugLinesMatchesParseDebugFile:
    """parse_debug_lines (the in-memory sibling of parse_debug_file, reached
    from debug_analyzer.py) must apply the same edge-whitespace-faithful
    rstrip("\\r\\n") pattern, not .strip(), so the two paths do not drift.
    """

    def test_leading_whitespace_on_mode4_baseword_survives(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(["  password:c:Password"])

        assert entries[0]["baseword"] == "  password"
        assert entries[0]["rule"] == "c"
        assert entries[0]["candidate"] == "Password"

    def test_trailing_whitespace_on_mode5_wordlist_survives(self):
        parser = DebugLogParser()
        lines = [
            "password:c:Password:wordlist.txt",
            "password2:c:Password2:wordlist.txt ",
            "password3:c:Password3:wordlist.txt",
        ]
        entries = parser.parse_debug_lines(lines)

        assert parser._mode == 5
        assert entries[1]["wordlist"] == "wordlist.txt "

    def test_whitespace_only_lines_do_not_starve_detection_sample(self):
        parser = DebugLogParser()
        lines = ["   "] * _DETECTION_SAMPLE_SIZE * 2
        lines += [_mode5_colon_line(i).rstrip("\n") for i in range(50)]
        entries = parser.parse_debug_lines(lines)

        assert parser._mode == 5
        assert len(entries) == 50
        assert entries[0]["wordlist"] == "rockyou.txt"


class TestDebugParserEdgeWhitespace:
    def test_mode4_leading_space_on_baseword_survives(self, edge_whitespace_debug_mode4_file):
        """A baseword with a leading space must parse with that space intact.

        Under the old `.strip()` reader, the leading space -- which sits at
        the very start of the raw line, since baseword is the first field --
        was silently deleted, corrupting the baseword ("  password" ->
        "password").
        """
        parser = DebugLogParser()
        entries = parser.parse_debug_file(edge_whitespace_debug_mode4_file)

        assert entries[0]["baseword"] == "  password"
        assert entries[0]["rule"] == "c"
        assert entries[0]["candidate"] == "Password"
        assert entries[0]["wordlist"] is None

    def test_mode5_majority_vote_and_trailing_space_on_wordlist_survive(
        self, edge_whitespace_debug_mode5_file
    ):
        """Mode-5 majority-vote detection isn't thrown off by one odd line,
        and that odd line's trailing space (part of its wordlist field) must
        survive rather than being silently deleted.

        Under the old `.strip()` reader, the trailing space -- which sits at
        the very end of that line, since wordlist is the last field -- was
        silently deleted, corrupting the wordlist ("wordlist.txt " ->
        "wordlist.txt").
        """
        parser = DebugLogParser()
        entries = parser.parse_debug_file(edge_whitespace_debug_mode5_file)

        assert parser._format == "colon"
        assert parser._mode == 5
        assert len(entries) == 3
        assert entries[0]["wordlist"] == "wordlist.txt"
        # Trailing space belongs to the wordlist field and must be preserved.
        assert entries[1]["wordlist"] == "wordlist.txt "
        assert entries[2]["wordlist"] == "wordlist.txt"
