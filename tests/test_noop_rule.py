"""Parsing debug logs whose rule is hashcat's no-op rule ``:``.

A wordlist run with no rule file still writes a rule field, and that field is
``:``. On the wire the line therefore carries two adjacent separators around
it -- ``baseword:::candidate`` -- which defeats both the format vote and the
field split unless they account for it.

Regression coverage for a real log in which 7836 of 7851 lines were silently
discarded and the 15 survivors produced rules hashcat rejected outright.
"""

from hashcat_rosetta.parser import DebugLogParser


def _mode5_lines(n: int) -> list[str]:
    """Mode-5 lines from a no-rule wordlist run: rule is the no-op ``:``."""
    return [f"Password{i}:::Password{i}:/wordlists/rockyou.txt" for i in range(n)]


def _mode4_lines(n: int) -> list[str]:
    """Mode-4 lines from a no-rule wordlist run."""
    return [f"Password{i}:::Password{i}" for i in range(n)]


class TestNoopRuleFormatDetection:
    """The format vote must not abstain just because the rule field is ``:``."""

    def test_mode5_noop_detected_as_colon(self) -> None:
        parser = DebugLogParser()
        assert parser._detect_format(_mode5_lines(25)) == "colon"

    def test_mode4_noop_detected_as_colon(self) -> None:
        parser = DebugLogParser()
        assert parser._detect_format(_mode4_lines(25)) == "colon"

    def test_no_lines_are_dropped(self) -> None:
        """Every line is a crack; none may be silently discarded."""
        lines = _mode5_lines(25)
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(lines)
        assert len(entries) == len(lines)

    def test_truly_empty_rule_is_still_rejected(self) -> None:
        """``a::b`` has an empty rule, not a no-op one, and stays unvoted.

        Relaxing the vote must not turn arbitrary colon-bearing text into a
        parseable debug line.
        """
        parser = DebugLogParser()
        assert parser._detect_format(["alpha::beta"] * 25) == "space"


class TestNoopRuleFieldSplit:
    """``:`` must survive as the rule rather than collapsing into an empty one."""

    def test_mode5_fields(self) -> None:
        parser = DebugLogParser(debug_mode=5)
        parser._format = "colon"
        entry = parser._parse_colon_line("Password0:::Password0:/wordlists/rockyou.txt")
        assert entry["baseword"] == "Password0"
        assert entry["rule"] == ":"
        assert entry["candidate"] == "Password0"
        assert entry["wordlist"] == "/wordlists/rockyou.txt"

    def test_mode4_fields(self) -> None:
        parser = DebugLogParser(debug_mode=4)
        parser._format = "colon"
        entry = parser._parse_colon_line("Password0:::Password0")
        assert entry["baseword"] == "Password0"
        assert entry["rule"] == ":"
        assert entry["candidate"] == "Password0"

    def test_rule_ending_in_a_colon(self) -> None:
        """``$:`` appends a colon; the candidate is hex-encoded because of it.

        Splitting left-to-right truncated this to ``$``, an append with no
        argument, which hashcat rejects outright.
        """
        parser = DebugLogParser(debug_mode=5)
        parser._format = "colon"
        entry = parser._parse_colon_line(
            "Flowers56:$::$HEX[466c6f7765727335363a]:/wordlists/found.txt"
        )
        assert entry["baseword"] == "Flowers56"
        assert entry["rule"] == "$:"
        assert entry["candidate"] == "$HEX[466c6f7765727335363a]"
        assert entry["wordlist"] == "/wordlists/found.txt"

    def test_multi_function_rule_containing_a_colon(self) -> None:
        parser = DebugLogParser(debug_mode=5)
        parser._format = "colon"
        entry = parser._parse_colon_line("word:c $::$HEX[deadbeef]:/w.txt")
        assert entry["rule"] == "c $:"
        assert entry["candidate"] == "$HEX[deadbeef]"

    def test_ordinary_rules_are_unaffected(self) -> None:
        parser = DebugLogParser(debug_mode=4)
        parser._format = "colon"
        entry = parser._parse_colon_line("football:u:FOOTBALL")
        assert entry["baseword"] == "football"
        assert entry["rule"] == "u"
        assert entry["candidate"] == "FOOTBALL"

    def test_end_to_end_yields_the_noop_rule(self) -> None:
        """The mined rule set is the no-op rule, not an empty string.

        An empty line in a .rule file is not a rule; hashcat rejects the file
        rather than treating it as a pass-through.
        """
        parser = DebugLogParser()
        entries = parser.parse_debug_lines(_mode5_lines(25))
        assert {e["rule"] for e in entries} == {":"}
        assert all(e["candidate"] == e["baseword"] for e in entries)


class TestHashLeadingBaseword:
    """A password starting with '#' is data, not a comment."""

    def test_hash_leading_baseword_is_parsed(self) -> None:
        parser = DebugLogParser(debug_mode=5)
        parser._format = "colon"
        entry = parser._parse_colon_line("#Jesus1225:::#Jesus1225:/w.txt")
        assert entry is not None
        assert entry["baseword"] == "#Jesus1225"
        assert entry["rule"] == ":"

    def test_annotation_line_is_still_a_comment(self) -> None:
        parser = DebugLogParser()
        assert parser._parse_line("# This is a comment") is None

    def test_hash_leading_basewords_survive_a_full_parse(self) -> None:
        lines = [f"#Password{i}:::#Password{i}:/w.txt" for i in range(25)]
        parser = DebugLogParser()
        assert len(parser.parse_debug_lines(lines)) == len(lines)
