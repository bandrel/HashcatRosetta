"""Tests for DebugLogParser mode-4 / mode-5 handling.

Covers the trailing WORDLIST field added by hashcat --debug-mode 5, colon
preservation inside candidates, auto-detection of the debug mode from a sample
of lines, and the explicit debug_mode override.
"""

import tempfile

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

    def test_extra_colon_belongs_to_the_rule_not_the_candidate(self):
        """A colon past the first separator is part of the rule.

        hashcat never emits a raw colon in the candidate -- it hex-encodes any
        plaintext containing the field separator. Captured from hashcat 7.1.2
        cracking md5("abc:") with the rule ``$:``::

            abc:$::$HEX[6162633a]:words.txt

        Rules, by contrast, contain colons routinely: ``:`` (no-op), ``$:``,
        ``c $:``. So the last colon is the separator, not the first.
        """
        parser = DebugLogParser(debug_mode=4)
        entries = parser.parse_debug_lines(["password:c:Pass:word"])
        assert len(entries) == 1
        assert entries[0]["rule"] == "c:Pass"
        assert entries[0]["candidate"] == "word"
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

    def test_extra_colon_belongs_to_the_rule_not_the_candidate(self):
        """See the mode-4 counterpart: candidates are hex-encoded, rules are not."""
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Pass:word:rockyou.txt"])
        assert entries[0]["baseword"] == "password"
        assert entries[0]["rule"] == "c:Pass"
        assert entries[0]["candidate"] == "word"
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
        # the explicit override forces mode 4, which knows nothing of a
        # wordlist field. The trailing colon is then read as part of the rule,
        # since a mode-4 candidate cannot contain a raw colon.
        parser = DebugLogParser(debug_mode=4)
        entries = parser.parse_debug_lines(["password:c:Password:rockyou.txt"])
        assert entries[0]["rule"] == "c:Password"
        assert entries[0]["candidate"] == "rockyou.txt"
        assert entries[0]["wordlist"] is None

    def test_force_mode_five_three_field_line_skipped(self):
        # A 3-field line has no wordlist field. Forcing mode 5 must skip it
        # rather than silently misassigning the candidate to the wordlist.
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Password"])
        assert entries == []

    def test_force_mode_five_trailing_colon_empty_wordlist(self):
        # Trailing colon => explicit empty wordlist field. Candidate keeps its
        # value and wordlist is the empty string.
        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_lines(["password:c:Password:"])
        assert len(entries) == 1
        assert entries[0]["candidate"] == "Password"
        assert entries[0]["wordlist"] == ""


class TestDetectModeMajorityVote:
    """Mode auto-detection uses a majority vote, tolerating odd lines."""

    def test_single_odd_line_does_not_flip_to_mode_four(self):
        # Majority of lines are clearly mode 5; one odd line (trailing field
        # not wordlist-like) must not flip the whole file to mode 4.
        lines = [
            "password:c:Password:rockyou.txt",
            "admin:c:Admin:rockyou.txt",
            "letmein:c:Letmein:rockyou.txt",
            "weird:c:Weird:notawordlist",
        ]
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(lines)
        assert len(entries) == 4
        assert entries[0]["wordlist"] == "rockyou.txt"

    def test_majority_mode_four_stays_mode_four(self):
        lines = [
            "password:c:Password",
            "admin:c:Admin",
            "letmein:c:Letmein",
            "weird:c:Weird:rockyou.txt",
        ]
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(lines)
        assert all(e["wordlist"] is None for e in entries)


class TestParseDebugFile:
    """parse_debug_file (on-disk) honors the debug_mode constructor arg."""

    def test_file_with_explicit_mode_five(self):
        content = (
            "password:c:Password:rockyou.txt\n"
            "admin:c:Admin:rockyou.txt\n"
            "letmein:c:Letmein:rockyou.txt\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            path = tf.name

        parser = DebugLogParser(debug_mode=5)
        entries = parser.parse_debug_file(path)
        assert len(entries) == 3
        assert entries[0]["baseword"] == "password"
        assert entries[0]["candidate"] == "Password"
        assert entries[0]["wordlist"] == "rockyou.txt"
        assert all(e["wordlist"] == "rockyou.txt" for e in entries)


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
