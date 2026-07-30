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

from hashcat_rosetta.parser import DebugLogParser


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
