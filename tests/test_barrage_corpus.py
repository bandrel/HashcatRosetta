"""Regression test against the real 32.4M-line BARRAGE.rule corpus.

Marked integration; skipped without the corpus. The corpus itself (466 MB,
32.4M lines) must never be committed to the repo.

Reading the corpus as strict UTF-8 (the pre-fix behavior) raises
UnicodeDecodeError partway through, because BARRAGE.rule contains thousands
of non-UTF-8 byte sequences (proven in task-3-report.md via a scratch
script: it crashes after ~513k of 32.4M lines). Reading it as latin-1 never
raises, since every byte value 0x00-0xFF maps to a code point in latin-1.

To actually exercise the production, byte-safe reader end-to-end without
paying the cost of running it over the full 32.4M lines, this test does a
single cheap pass to find the "interesting" lines (non-UTF-8, and lines
where a trailing-space rule argument would be lost by a naive full
strip()), writes just those lines to a small distilled file, and then runs
the real production reader (`extract_rule_opcodes` from
`hashcat_rosetta.formatting`) against that distilled file. See
task-3-report.md for a mutation transcript proving this fails if the
production fixes are reverted.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from hashcat_rosetta.cli import explain_rule
from hashcat_rosetta.formatting import extract_rule_opcodes
from hashcat_rosetta.parser import RuleParser

CORPUS_PATH = Path.home() / "projects" / "hashcat" / "rules" / "BARRAGE.rule"

# Ground truth measured directly against this corpus (see task-3-report.md).
# Corpus as measured: 32,467,620 lines, 466,751,329 bytes (2026-07-30).
# To re-derive: count lines that raise UnicodeDecodeError on strict utf-8
# decode, iterating the corpus as raw bytes (see the byte loop below).
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
# reserving strip() for the separate blank/comment skip decision. To
# re-derive: for every non-blank/non-comment line where rstrip("\r\n") !=
# strip(), compare explain_rule() on both variants (see the loop below).
# If this count changes, either the corpus changed or explain_rule's
# handling of trailing-space arguments regressed - investigate, don't just
# update it.
EXPECTED_SPACE_ARG_VULNERABLE_LINES = 79


@pytest.mark.integration
def test_barrage_corpus_is_byte_safe(tmp_path: Path) -> None:
    """Single pass over the real corpus to find byte-safety edge cases,
    pin their counts as ground truth, then run the production reader
    (extract_rule_opcodes) end-to-end against a distilled file containing
    only those edge-case lines.
    """
    if not CORPUS_PATH.exists():
        pytest.skip(f"BARRAGE.rule corpus not found at {CORPUS_PATH}")

    non_utf8_lines = 0
    space_arg_vulnerable_lines = 0
    examples: list[str] = []
    distilled_lines: list[bytes] = []
    expected_rule_count = 0
    expected_opcodes: Counter[str] = Counter()
    tokenizer = RuleParser()

    # Single pass: read raw bytes once, decode via latin-1 in the same loop
    # (latin-1 never raises, so this also proves the corpus is fully
    # readable without the pre-fix utf-8 crash) instead of reading the
    # 466 MB file twice.
    with open(CORPUS_PATH, "rb") as raw_file:
        for raw_bytes in raw_file:
            is_non_utf8 = False
            try:
                raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                is_non_utf8 = True
                non_utf8_lines += 1

            raw_line = raw_bytes.decode("latin-1")
            rstripped = raw_line.rstrip("\r\n")
            fully_stripped = rstripped.strip()
            is_skipped_by_production = not fully_stripped or fully_stripped.startswith("#")

            is_space_arg_vulnerable = False
            if not is_skipped_by_production and rstripped != fully_stripped:
                verdict_with_rstrip = explain_rule(rstripped)
                verdict_with_full_strip = explain_rule(fully_stripped)
                if verdict_with_rstrip is not None and verdict_with_full_strip is None:
                    is_space_arg_vulnerable = True
                    space_arg_vulnerable_lines += 1
                    if len(examples) < 5:
                        examples.append(rstripped)

            if is_non_utf8 or is_space_arg_vulnerable:
                distilled_lines.append(raw_bytes)
                if not is_skipped_by_production:
                    expected_rule_count += 1
                    # Ground truth for tokenization: tokenize the correctly
                    # rstrip-only line, exactly as extract_rule_opcodes should.
                    # A test that only checks `opcodes` is truthy would miss a
                    # reverted rstrip->strip fix, since a missing rule argument
                    # can still tokenize to *some* opcode (just the wrong one);
                    # comparing the full Counter catches that.
                    for token in tokenizer._tokenize_rule(rstripped):
                        expected_opcodes[token[0]] += 1

    assert non_utf8_lines == EXPECTED_NON_UTF8_LINES, (
        f"expected {EXPECTED_NON_UTF8_LINES} non-UTF-8 lines, found {non_utf8_lines}"
    )
    assert space_arg_vulnerable_lines == EXPECTED_SPACE_ARG_VULNERABLE_LINES, (
        f"expected {EXPECTED_SPACE_ARG_VULNERABLE_LINES} space-argument-vulnerable lines, "
        f"found {space_arg_vulnerable_lines}; examples: {examples}"
    )

    # End-to-end check: run the real production reader against a distilled
    # file made only of the offending lines (non-UTF-8 and/or
    # space-argument-vulnerable). This is the actual code path used by
    # `hashcat-rosetta rules.txt --analyze-rules`, exercised on real,
    # previously-crash-inducing corpus data - not a reimplementation of its
    # logic. It stays fast because the distilled file is ~33k lines, not
    # 32.4M.
    distilled_path = tmp_path / "distilled_barrage.rule"
    with open(distilled_path, "wb") as distilled_file:
        distilled_file.writelines(distilled_lines)

    opcodes, rule_count = extract_rule_opcodes(str(distilled_path))

    assert rule_count == expected_rule_count, (
        f"expected extract_rule_opcodes to count {expected_rule_count} non-blank/non-comment "
        f"distilled lines as rules, got {rule_count}"
    )
    assert opcodes == dict(expected_opcodes), (
        "extract_rule_opcodes's opcode counts diverged from tokenizing the correctly "
        "rstrip-only lines directly; this is exactly what a reverted rstrip->strip fix "
        f"would produce. got={opcodes} expected={dict(expected_opcodes)}"
    )
