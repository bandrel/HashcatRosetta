"""Regression tests for hashcat's RP_PASSWORD_SIZE (256) length cap.

hashcat's rule engine applies a length-expanding opcode only when the
result is shorter than RP_PASSWORD_SIZE (256 bytes); otherwise the op is a
*no-op* (the word is left unchanged — hashcat does NOT truncate). These
cases reproduce the intermittent nightly accuracy failures where a long
all-'a' baseword pushed a duplicating opcode past 256: explain_rule() grew
the word unconditionally while hashcat kept the prior value.

All expected values below were confirmed against the hashcat binary
(v7.1.2) via `hashcat --stdout`.
"""

import pytest

from hashcat_rosetta.cli import explain_rule


def _final(rule: str, baseword: str) -> str:
    """Extract the final candidate from explain_rule()'s step list."""
    steps = explain_rule(rule, baseword)
    if not steps:
        return ""
    last = str(steps[-1])
    return last.rsplit(" → ", 1)[-1] if " → " in last else last


# Reproductions of the exact rules that failed on the nightly job.
@pytest.mark.parametrize(
    "rule, baseword, expected",
    [
        # p5 grows 40 -> 240 (<256, applied); the trailing doubler would hit
        # 480 (>=256) so hashcat no-ops it.
        ("p5 f", "a" * 40, "a" * 240),
        ("p5 q", "a" * 40, "a" * 240),
        # O43 omits 3 chars at pos 4 -> 37; p4 -> 37*5 = 185; d would be 370 (no-op).
        ("O43 p4 d", "a" * 40, "a" * 185),
        # p4 -> 200; sfE is a no-op on all-'a'; f would be 400 (no-op).
        ("p4 sfE f", "a" * 40, "a" * 200),
    ],
)
def test_nightly_overlength_repro(rule, baseword, expected):
    assert _final(rule, baseword) == expected


@pytest.mark.parametrize(
    "rule, baseword, expected",
    [
        # x2 duplicators: no-op at/over 256, applied below.
        ("f", "a" * 128, "a" * 128),  # ->256 : no-op
        ("f", "a" * 127, "a" * 254),  # ->254 : applied
        ("d", "a" * 128, "a" * 128),  # ->256 : no-op
        ("q", "a" * 200, "a" * 200),  # ->400 : no-op
        # z/Z (+N): exact boundary at result==256.
        ("z6", "a" * 250, "a" * 250),  # ->256 : no-op
        ("z5", "a" * 250, "a" * 255),  # ->255 : applied
        ("Z6", "a" * 250, "a" * 250),  # ->256 : no-op
        # y/Y (duplicate first/last N chars).
        ("y9", "a" * 250, "a" * 250),  # ->259 : no-op
        ("Y9", "a" * 250, "a" * 250),  # ->259 : no-op
        # single-char appenders no-op when they'd reach 256.
        ("$x", "a" * 255, "a" * 255),  # ->256 : no-op
        ("^x", "a" * 255, "a" * 255),  # ->256 : no-op
        ("i0x", "a" * 255, "a" * 255),  # ->256 : no-op
        # p at its own boundary (existing guard).
        ("p1", "a" * 128, "a" * 128),  # ->256 : no-op
        ("p1", "a" * 127, "a" * 254),  # ->254 : applied
    ],
)
def test_length_cap_boundaries(rule, baseword, expected):
    assert _final(rule, baseword) == expected
