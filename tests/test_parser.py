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
        """The odd line out is read on its own terms, not the file's.

        The file is mode 4 by majority, but the last line carries a
        wordlist-like trailing field, so it is a mode-5 record and is parsed
        as one. Forcing the file's mode onto it would glue the candidate to
        the rule (``c:Weird``) and hand the wordlist back as the candidate.
        """
        lines = [
            "password:c:Password",
            "admin:c:Admin",
            "letmein:c:Letmein",
            "weird:c:Weird:rockyou.txt",
        ]
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(lines)
        assert [e["wordlist"] for e in entries] == [None, None, None, "rockyou.txt"]
        assert [e["rule"] for e in entries] == ["c", "c", "c", "c"]
        assert entries[3]["candidate"] == "Weird"


class TestMixedModeFile:
    """One log can hold both modes: hashcat appends, and hate_crack switched
    from --debug-mode 4 to 5 mid-life, so old and new records share a file."""

    def test_mode_five_records_in_a_mode_four_file_keep_their_rule(self):
        lines = ["a:c:A", "b:c:B", "c:c:C"] + ["password:$1 $2:password12:/wordlists/rockyou.txt"]
        parser = DebugLogParser()
        entry = parser.parse_debug_lines(lines)[3]
        assert entry["rule"] == "$1 $2"
        assert entry["candidate"] == "password12"
        assert entry["wordlist"] == "/wordlists/rockyou.txt"

    def test_mode_four_records_in_a_mode_five_file_are_kept(self):
        """These used to be dropped with a warning, losing real cracks."""
        lines = [
            "password:c:Password:rockyou.txt",
            "admin:c:Admin:rockyou.txt",
            "letmein:c:Letmein",
        ]
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(lines)
        assert len(entries) == 3
        assert entries[2]["rule"] == "c"
        assert entries[2]["candidate"] == "Letmein"
        assert entries[2]["wordlist"] is None

    def test_no_derived_rule_contains_a_wordlist_path(self):
        """The reported symptom: rules.rule lines hashcat rejects."""
        lines = ["a:c:A", "b:c:B"] + [
            f"word{i}:$x $y:word{i}x:/Users/me/lists/rockyou.txt" for i in range(5)
        ]
        parser = DebugLogParser()
        rules = {e["rule"] for e in parser.parse_debug_lines(lines)}
        assert not [r for r in rules if "/" in r], rules

    def test_colon_bearing_rule_still_wins_over_the_wordlist_guess(self):
        """A rule containing a colon must not be mistaken for a mode boundary.

        ``$:`` appends a colon, so this mode-4 record has three separators.
        Its trailing field is the hex-encoded candidate, not wordlist-like, so
        the line stays mode 4. Captured from hashcat 7.1.2 cracking
        md5("abc:") with the rule ``$:``.
        """
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(["abc:$::$HEX[6162633a]", "def:c:Def", "ghi:c:Ghi"])
        assert entries[0]["rule"] == "$:"
        assert entries[0]["candidate"] == "$HEX[6162633a]"
        assert entries[0]["wordlist"] is None

    def test_explicit_mode_is_still_obeyed_literally(self):
        """A forced mode is an instruction, not a hint: no per-line rescue."""
        parser = DebugLogParser(debug_mode=4)
        entries = parser.parse_debug_lines(["password:c:Password:rockyou.txt"])
        assert entries[0]["rule"] == "c:Password"
        assert entries[0]["wordlist"] is None


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


class TestParseDebugFiles:
    """parse_debug_files detects format/mode independently per file."""

    @staticmethod
    def _write(content: str) -> str:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write(content)
            return tf.name

    def test_mixed_mode_four_and_five_files_both_parse(self):
        mode_four = self._write(
            "\n".join(
                [
                    "Moldmastersmmkr:r i45 i52 r:Moldmasters25mmkr",
                    "Customerserv24:^e ^m ^D T3:Dmecustomerserv24",
                ]
            )
            + "\n"
        )
        mode_five = self._write(
            "\n".join(
                [
                    "password:c:Password:rockyou.txt",
                    "admin:c:Admin:rockyou.txt",
                ]
            )
            + "\n"
        )

        parser = DebugLogParser()
        entries = parser.parse_debug_files([mode_four, mode_five])

        assert len(entries) == 4
        four_entries = [
            e for e in entries if e["baseword"] in {"Moldmastersmmkr", "Customerserv24"}
        ]
        assert len(four_entries) == 2
        assert all(e["wordlist"] is None for e in four_entries)
        five_entries = [e for e in entries if e["baseword"] in {"password", "admin"}]
        assert len(five_entries) == 2
        assert all(e["wordlist"] == "rockyou.txt" for e in five_entries)

    def test_mode_four_file_first_does_not_starve_mode_five_file(self):
        """Order shouldn't matter: each file's own sample drives its own mode."""
        mode_four = self._write("baseword:r:candidate\n" * 25)
        mode_five = self._write("password:c:Password:rockyou.txt\n")

        parser = DebugLogParser()
        entries = parser.parse_debug_files([mode_four, mode_five])

        assert len(entries) == 26
        five_entry = next(e for e in entries if e["baseword"] == "password")
        assert five_entry["wordlist"] == "rockyou.txt"


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
