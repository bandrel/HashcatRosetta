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
