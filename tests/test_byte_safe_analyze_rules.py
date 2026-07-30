"""Byte-safety tests for the --analyze-rules path (formatting.extract_rule_opcodes).

Task 1 fixed cli.py's --explain reader, which crashed outright on non-UTF-8
bytes. extract_rule_opcodes has the same underlying bug (utf-8 + errors="ignore"
plus a full strip()) but it manifests as silent data loss instead of a crash:
high-byte rule lines get mangled into "incomplete opcode" and are skipped, and
lines that are otherwise fine but happen to have leading/trailing bytes that
matter get corrupted rather than raising.
"""

from hashcat_rosetta.formatting import extract_rule_opcodes


class TestExtractRuleOpcodesByteSafety:
    """extract_rule_opcodes must read rule files as latin-1 and preserve bytes."""

    def test_high_byte_rules_produce_intact_opcodes(self, high_byte_rule_file):
        """The Task 1 fixture's o/$/i opcodes must be counted, not skipped.

        Under the old utf-8 + errors="ignore" reader, the high bytes (0xBA,
        0xD0, 0xBC) are silently deleted, corrupting the rule tokens. The `o`
        and `i` opcode tokens no longer have enough characters/args and get
        skipped as "incomplete". The old full `.strip()` compounds this for
        `$ ` (append a literal space): stripping deletes the trailing-space
        argument too, leaving a bare `$` with no argument, which is also
        skipped as an incomplete 1-arg opcode. So under the old reader none
        of `o`, `$`, or `i` are counted at all. With the latin-1 + rstrip fix,
        all three opcode lines parse and are counted correctly.
        """
        opcodes, rule_count = extract_rule_opcodes(high_byte_rule_file)

        # 4 non-comment, non-blank lines: "o1\xba", "$ ", "i0\xd0 i1\xbc", "c"
        assert rule_count == 4
        assert opcodes.get("o") == 1
        assert opcodes.get("$") == 1
        assert opcodes.get("i") == 2
        assert opcodes.get("c") == 1

    def test_indented_comment_and_blank_line_are_skipped(self, indented_comment_rule_file):
        """An indented "#" comment and a whitespace-only line must be skipped,
        while a real rule's whitespace argument must still survive.

        The skip decision has to be made on the *stripped* line -- otherwise
        "  # note" doesn't start with "#" (it starts with a space) and gets
        tokenized as junk, and "   " is truthy and gets counted as a rule.
        But the line actually handed to the tokenizer must stay un-stripped,
        or "$ " loses its trailing-space argument and becomes an incomplete,
        skipped "$" token -- which is exactly the inverse mistake this test
        also catches: if the fix regresses to tokenizing the stripped line,
        `opcodes.get("$")` goes back to None here.
        """
        opcodes, rule_count = extract_rule_opcodes(indented_comment_rule_file)

        # Only 2 real rules: "$ " and "c". The comment and blank-ish line
        # must not be counted or tokenized.
        assert rule_count == 2
        assert opcodes.get("$") == 1
        assert opcodes.get("c") == 1
        # No stray opcodes from tokenizing "  # note" (e.g. its 'o'/'t'/'e').
        assert set(opcodes) == {"$", "c"}
