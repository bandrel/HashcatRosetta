"""Shared byte-level rule-file fixture for byte-safety tests.

This fixture writes its content with ``Path.write_bytes`` rather than as a
committed text file on disk. A committed file containing high (non-UTF-8)
bytes is liable to be "helpfully" re-encoded by an editor, a linter, or git's
text handling, which would silently defeat every test that depends on these
exact byte sequences being preserved. Building the bytes in Python and
writing them out at test time avoids that risk entirely.
"""

import pytest

HIGH_BYTE_RULE_LINES = (
    b"o1\xba\n"  # BARRAGE line 513683: overwrite pos 1 with byte 0xBA
    b"$ \n"  # append a literal space - a legal argument
    b"i0\xd0 i1\xbc\n"  # BARRAGE line 1119716: two high-byte args
    b"# comment\n"
    b"\n"
    b"c\n"  # a plain ASCII rule, as a control
)


@pytest.fixture
def high_byte_rule_file(tmp_path):
    """Write a raw-byte rule file to tmp_path and return its path."""
    path = tmp_path / "high_byte_rules.rule"
    path.write_bytes(HIGH_BYTE_RULE_LINES)
    return str(path)


# Exercises the comment/blank-line detection regression: skip decisions must be
# made on the *stripped* line (so an indented "#" comment and a whitespace-only
# line are both recognized and skipped), but the line handed to
# tokenize/explain must remain un-stripped (so a real rule's leading/trailing
# whitespace argument, like "$ ", still survives). A test that tokenizes the
# fully-stripped line would wrongly count 4 rules here (comment + real rule 1
# collapses "$ " to "$", dropping its argument) instead of 2.
INDENTED_COMMENT_RULE_LINES = (
    b"  # note\n"  # indented comment - must be skipped, not tokenized as junk
    b"   \n"  # whitespace-only line - must be skipped, not counted as a rule
    b"$ \n"  # a real rule whose argument is a literal space - must survive
    b"c\n"  # a plain ASCII rule, as a control
)


@pytest.fixture
def indented_comment_rule_file(tmp_path):
    """Write a rule file with an indented comment and a blank-ish line."""
    path = tmp_path / "indented_comment_rules.rule"
    path.write_bytes(INDENTED_COMMENT_RULE_LINES)
    return str(path)


# Mode-4/mode-5 colon-format debug lines exercising the edge-whitespace bug in
# DebugLogParser.parse_debug_file: a leading space on a baseword (an edge
# adjacent to the raw line's start), and a mode-5 file where one line's
# wordlist field has a trailing space (an edge adjacent to the raw line's
# end) alongside two clean mode-5 lines so format/mode detection's majority
# vote is exercised too. Unlike HIGH_BYTE_RULE_LINES, these fixtures are pure
# ASCII: DebugLogParser.parse_debug_file deliberately stays on
# utf-8 + errors="ignore" (not latin-1) because debug-log basewords/
# candidates commonly come from real UTF-8 wordlists and export is UTF-8; see
# the comment at parser.py's parse_debug_file open() call.
EDGE_WHITESPACE_DEBUG_MODE4_LINES = (
    b"  password:c:Password\n"  # leading space belongs to the baseword
)

EDGE_WHITESPACE_DEBUG_MODE5_LINES = (
    b"password:c:Password:wordlist.txt\n"
    b"password2:c:Password2:wordlist.txt \n"  # trailing space belongs to wordlist
    b"password3:c:Password3:wordlist.txt\n"
)


@pytest.fixture
def edge_whitespace_debug_mode4_file(tmp_path):
    """Write a raw-byte mode-4 debug log to tmp_path and return its path."""
    path = tmp_path / "edge_whitespace_debug_mode4.log"
    path.write_bytes(EDGE_WHITESPACE_DEBUG_MODE4_LINES)
    return str(path)


@pytest.fixture
def edge_whitespace_debug_mode5_file(tmp_path):
    """Write a raw-byte mode-5 debug log to tmp_path and return its path."""
    path = tmp_path / "edge_whitespace_debug_mode5.log"
    path.write_bytes(EDGE_WHITESPACE_DEBUG_MODE5_LINES)
    return str(path)
