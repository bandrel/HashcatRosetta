"""Tests for DebugLogParser mode-4 / mode-5 handling.

Covers the trailing WORDLIST field added by hashcat --debug-mode 5, colon
preservation inside candidates, auto-detection of the debug mode from a sample
of lines, and the explicit debug_mode override.
"""

from hashcat_rosetta.parser import DebugLogParser


class TestModeFourColon:
    """Mode-4 colon format (baseword:rule:candidate) backward compatibility."""

    def test_basic_line_wordlist_none(self):
        parser = DebugLogParser(debug_mode=4)
        entries = parser.parse_debug_lines(["password:c:Password"])
        assert len(entries) == 1
        entry = entries[0]
        assert entry["baseword"] == "password"
        assert entry["rule"] == "c"
        assert entry["candidate"] == "Password"
        assert entry["wordlist"] is None

    def test_candidate_with_internal_colon_preserved(self):
        parser = DebugLogParser(debug_mode=4)
        entries = parser.parse_debug_lines(["password:c:Pass:word"])
        assert len(entries) == 1
        assert entries[0]["candidate"] == "Pass:word"
        assert entries[0]["wordlist"] is None


class TestModeFiveColon:
    """Mode-5 colon format (baseword:rule:candidate:wordlist)."""

    def test_basic_line(self):
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Password:rockyou.txt"])
        assert len(entries) == 1
        entry = entries[0]
        assert entry["baseword"] == "password"
        assert entry["rule"] == "c"
        assert entry["candidate"] == "Password"
        assert entry["wordlist"] == "rockyou.txt"

    def test_candidate_not_polluted_with_wordlist(self):
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Password:/opt/wordlists/x.txt"])
        assert entries[0]["candidate"] == "Password"
        assert entries[0]["wordlist"] == "/opt/wordlists/x.txt"

    def test_candidate_with_internal_colon_preserved(self):
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Pass:word:rockyou.txt"])
        assert entries[0]["baseword"] == "password"
        assert entries[0]["rule"] == "c"
        assert entries[0]["candidate"] == "Pass:word"
        assert entries[0]["wordlist"] == "rockyou.txt"


class TestAutoDetection:
    """Auto-detection of debug mode from a sample of lines."""

    def test_detects_mode_five_sample(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(
            [
                "password:c:Password:rockyou.txt",
                "admin:$1:admin1:rockyou.txt",
                "root:u:ROOT:rockyou.txt",
            ]
        )
        assert all(e["wordlist"] == "rockyou.txt" for e in entries)
        assert entries[0]["candidate"] == "Password"

    def test_detects_mode_four_sample(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(
            [
                "password:c:Password",
                "admin:$1:admin1",
                "root:u:ROOT",
            ]
        )
        assert all(e["wordlist"] is None for e in entries)
        assert entries[0]["candidate"] == "Password"

    def test_sentinel_stdin_detected_as_mode_five(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(["password:c:Password:<stdin>", "admin:u:ADMIN:<stdin>"])
        assert entries[0]["wordlist"] == "<stdin>"
        assert entries[0]["candidate"] == "Password"

    def test_sentinel_generic_detected_as_mode_five(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(
            ["password:c:Password:<generic>", "admin:u:ADMIN:<generic>"]
        )
        assert entries[0]["wordlist"] == "<generic>"
        assert entries[0]["candidate"] == "Password"

    def test_sentinel_none_detected_as_mode_five(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(["password:c:Password:<none>", "admin:u:ADMIN:<none>"])
        assert entries[0]["wordlist"] == "<none>"
        assert entries[0]["candidate"] == "Password"


class TestOverride:
    """Explicit debug_mode override wins over the heuristic."""

    def test_force_mode_five_against_heuristic(self):
        # Trailing field "word" is not path-like, so the heuristic would pick
        # mode 4, but the explicit override forces mode 5.
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Password:word"])
        assert entries[0]["candidate"] == "Password"
        assert entries[0]["wordlist"] == "word"

    def test_force_mode_four_against_heuristic(self):
        # Trailing field is path-like, so the heuristic would pick mode 5, but
        # the explicit override forces mode 4 (candidate keeps the trailer).
        parser = DebugLogParser(debug_mode=4)
        entries = parser.parse_debug_lines(["password:c:Password:rockyou.txt"])
        assert entries[0]["candidate"] == "Password:rockyou.txt"
        assert entries[0]["wordlist"] is None


class TestSpaceFormat:
    """Legacy space format stays 3-field with wordlist None."""

    def test_space_line_wordlist_none(self):
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(["password c Password"])
        assert len(entries) == 1
        assert entries[0]["baseword"] == "password"
        assert entries[0]["rule"] == "c"
        assert entries[0]["candidate"] == "Password"
        assert entries[0]["wordlist"] is None
