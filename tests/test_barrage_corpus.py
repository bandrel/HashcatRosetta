"""Regression test against the real 32.4M-line BARRAGE.rule corpus.

Marked integration; skipped without the corpus. This is the test that would
have caught the original crash: decoding the corpus as strict UTF-8 raises
UnicodeDecodeError partway through (proven in the task-3 report via a scratch
script), because BARRAGE.rule contains thousands of non-UTF-8 byte sequences.
Reading it as latin-1 never raises, since every byte value 0x00-0xFF maps to
a code point in latin-1.

The corpus itself (466 MB, 32.4M lines) must never be committed to the repo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hashcat_rosetta.cli import explain_rule

CORPUS_PATH = Path.home() / "projects" / "hashcat" / "rules" / "BARRAGE.rule"

# Ground truth measured directly against this corpus (see task-3-report.md).
# Do not adjust this to match a different observed count without investigating
# why the corpus content itself changed.
EXPECTED_NON_UTF8_LINES = 33262

# Ground truth count of real lines where the trailing byte(s) removed by a
# full strip() are a *meaningful rule argument* rather than incidental
# whitespace (e.g. "i5 " inserts a literal space at position 5; "i5" alone
# is an invalid/incomplete rule). explain_rule(rstrip-only) correctly stays
# non-None for these; explain_rule(fully-stripped) incorrectly degrades to
# None. This is the exact space-argument bug the byte-safe fix protects
# against by only ever rstrip-ping the terminator for tokenize/explain, and
# reserving strip() for the separate blank/comment skip decision. If this
# count changes, either the corpus changed or explain_rule's handling of
# trailing-space arguments regressed - investigate, don't just update it.
EXPECTED_SPACE_ARG_VULNERABLE_LINES = 79


@pytest.mark.integration
def test_barrage_corpus_is_byte_safe() -> None:
    """The full corpus must be readable as latin-1 with zero decode errors.

    Also pins down, against real data, how many lines depend on rstrip-only
    (not full strip()) to keep a trailing-space rule argument intact for
    explain_rule. See EXPECTED_SPACE_ARG_VULNERABLE_LINES above.
    """
    if not CORPUS_PATH.exists():
        pytest.skip(f"BARRAGE.rule corpus not found at {CORPUS_PATH}")

    non_utf8_lines = 0
    space_arg_vulnerable_lines = 0
    examples: list[str] = []

    with open(CORPUS_PATH, "rb") as raw_file:
        for raw_bytes in raw_file:
            try:
                raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                non_utf8_lines += 1

    # latin-1 decoding never raises across the whole corpus: if this loop
    # completes at all, every line decoded successfully, since latin-1 has
    # no invalid byte sequences (unlike the utf-8 read this replaced).
    with open(CORPUS_PATH, encoding="latin-1") as rule_file:
        for raw_line in rule_file:
            rstripped = raw_line.rstrip("\r\n")
            fully_stripped = rstripped.strip()
            if not fully_stripped or fully_stripped.startswith("#"):
                continue
            if rstripped == fully_stripped:
                continue

            verdict_with_rstrip = explain_rule(rstripped)
            verdict_with_full_strip = explain_rule(fully_stripped)
            if verdict_with_rstrip is not None and verdict_with_full_strip is None:
                space_arg_vulnerable_lines += 1
                if len(examples) < 5:
                    examples.append(rstripped)

    assert non_utf8_lines == EXPECTED_NON_UTF8_LINES, (
        f"expected {EXPECTED_NON_UTF8_LINES} non-UTF-8 lines, found {non_utf8_lines}"
    )
    assert space_arg_vulnerable_lines == EXPECTED_SPACE_ARG_VULNERABLE_LINES, (
        f"expected {EXPECTED_SPACE_ARG_VULNERABLE_LINES} space-argument-vulnerable lines, "
        f"found {space_arg_vulnerable_lines}; examples: {examples}"
    )
