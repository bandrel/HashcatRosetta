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
        skipped as "incomplete", and the `$ ` token's argument byte survives
        as normal (since it's an ASCII space) but the file overall reports
        fewer opcodes than it actually has. With the latin-1 fix, all three
        opcode lines parse and are counted correctly.
        """
        opcodes, rule_count = extract_rule_opcodes(high_byte_rule_file)

        # 4 non-comment, non-blank lines: "o1\xba", "$ ", "i0\xd0 i1\xbc", "c"
        assert rule_count == 4
        assert opcodes.get("o") == 1
        assert opcodes.get("$") == 1
        assert opcodes.get("i") == 2
        assert opcodes.get("c") == 1
