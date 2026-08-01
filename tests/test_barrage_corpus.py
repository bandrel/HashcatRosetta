"""Regression test against the real 32.4M-line BARRAGE.rule corpus.

Marked integration; skipped without the corpus. The corpus itself (466 MB,
32.4M lines) must never be committed to the repo.

Reading the corpus as strict UTF-8 (the pre-fix behavior) raises
UnicodeDecodeError partway through, because BARRAGE.rule contains thousands
of non-UTF-8 byte sequences (proven in task-3-report.md via a scratch
script: it crashes after ~513k of 32.4M lines). Reading it as latin-1 never
raises, since every byte value 0x00-0xFF maps to a code point in latin-1.

To actually exercise the production, byte-safe readers end-to-end without
paying the cost of running them over the full 32.4M lines, this test does a
single cheap pass to find the "interesting" lines (non-UTF-8, and lines
where a trailing-space rule argument would be lost by a naive full
strip()), writes just those lines to small distilled files, and then runs
both real production readers against them:

- `extract_rule_opcodes` (`hashcat_rosetta.formatting`), the
  `--analyze-rules` code path.
- `main` (`hashcat_rosetta.cli`) invoked with `--explain <file>` via
  `click.testing.CliRunner`, the `--explain <rule-file>` code path. This is
  the path where the original crash actually occurred
  (`hashcat-rosetta --explain BARRAGE.rule` raised UnicodeDecodeError), so
  it must be covered directly, not just `--analyze-rules`.

See task-3-report.md for a mutation transcript proving both assertions
fail if their respective production fixes are reverted.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from click.testing import CliRunner

from hashcat_rosetta.cli import _escape_bytes, explain_rule, main
from hashcat_rosetta.formatting import extract_rule_opcodes
from hashcat_rosetta.parser import RuleParser

CORPUS_PATH = Path.home() / "projects" / "hashcat" / "rules" / "BARRAGE.rule"

# A known non-UTF-8 line ("o1\xba", opcode 'o' at position 1 replacing with
# byte 0xba) at this 1-indexed line number in the corpus, used to anchor the
# --explain end-to-end subset below. Verified via:
#   sed -n '513683p' ~/projects/hashcat/rules/BARRAGE.rule | xxd
EXPLAIN_ANCHOR_LINE_NUMBER = 513683
EXPLAIN_ANCHOR_ESCAPED_BYTES = b"o1\\xba"

# Cap on how many of the (non-UTF-8 or space-arg-vulnerable) edge-case lines
# get driven through the much slower --explain CLI path. --explain produces
# several lines of output per rule, so running it over the full ~33k-line
# distilled corpus-property file would be needlessly slow/memory-heavy for
# what is fundamentally a smoke check that the production --explain file
# reader survives real non-UTF-8 bytes and preserves trailing-space rule
# arguments. The anchor line above and the first space-argument-vulnerable
# line encountered are force-included even if they fall outside this cap.
EXPLAIN_SUBSET_LINE_CAP = 300

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

    explain_subset_lines: list[bytes] = []
    anchor_raw_bytes: bytes | None = None
    first_space_arg_raw_bytes: bytes | None = None
    first_space_arg_verdict: list | None = None

    # Single pass: read raw bytes once, decode via latin-1 in the same loop
    # (latin-1 never raises, so this also proves the corpus is fully
    # readable without the pre-fix utf-8 crash) instead of reading the
    # 466 MB file twice.
    with open(CORPUS_PATH, "rb") as raw_file:
        for line_number, raw_bytes in enumerate(raw_file, 1):
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
                    if first_space_arg_raw_bytes is None:
                        first_space_arg_raw_bytes = raw_bytes
                        first_space_arg_verdict = verdict_with_rstrip

            if line_number == EXPLAIN_ANCHOR_LINE_NUMBER:
                anchor_raw_bytes = raw_bytes
                assert raw_bytes.rstrip(b"\r\n") == b"o1\xba", (
                    f"expected line {EXPLAIN_ANCHOR_LINE_NUMBER} to be b'o1\\xba', "
                    f"got {raw_bytes!r} - corpus content changed, update the anchor"
                )

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

                # Build a small subset for the (much slower) --explain
                # end-to-end check below: the first EXPLAIN_SUBSET_LINE_CAP
                # edge-case lines encountered. The anchor line and the first
                # space-argument-vulnerable line are force-included after the
                # loop below even if they fall outside this cap.
                if len(explain_subset_lines) < EXPLAIN_SUBSET_LINE_CAP:
                    explain_subset_lines.append(raw_bytes)

    assert non_utf8_lines == EXPECTED_NON_UTF8_LINES, (
        f"expected {EXPECTED_NON_UTF8_LINES} non-UTF-8 lines, found {non_utf8_lines}"
    )
    assert space_arg_vulnerable_lines == EXPECTED_SPACE_ARG_VULNERABLE_LINES, (
        f"expected {EXPECTED_SPACE_ARG_VULNERABLE_LINES} space-argument-vulnerable lines, "
        f"found {space_arg_vulnerable_lines}; examples: {examples}"
    )
    assert anchor_raw_bytes is not None, (
        f"expected corpus to have at least {EXPLAIN_ANCHOR_LINE_NUMBER} lines "
        "(anchor line for --explain end-to-end check)"
    )
    assert first_space_arg_raw_bytes is not None and first_space_arg_verdict is not None, (
        "expected at least one space-argument-vulnerable line for the --explain end-to-end check"
    )

    # Force-include the anchor and first space-arg line in the --explain
    # subset even if the cap above already filled up before reaching them.
    if anchor_raw_bytes not in explain_subset_lines:
        explain_subset_lines.append(anchor_raw_bytes)
    if first_space_arg_raw_bytes not in explain_subset_lines:
        explain_subset_lines.append(first_space_arg_raw_bytes)

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

    # Second end-to-end check: the real --explain <rule-file> code path
    # (cli.py's `main`, via CliRunner), which is where the original crash
    # this whole task exists to guard against actually happened
    # (`hashcat-rosetta --explain BARRAGE.rule` raised UnicodeDecodeError).
    # Driven over a small subset (see EXPLAIN_SUBSET_LINE_CAP) rather than
    # the full ~33k-line distilled corpus-property file, since --explain
    # produces multiple lines of output per rule and doing so over the full
    # distilled file is unnecessarily slow for what is a smoke check that
    # this specific reader survives real non-UTF-8 bytes and preserves a
    # trailing-space rule argument. The corpus-property assertions above
    # (33,262 / 79) already cover the full corpus; only this CLI smoke
    # check is subset-limited.
    explain_subset_path = tmp_path / "explain_subset_barrage.rule"
    with open(explain_subset_path, "wb") as explain_subset_file:
        explain_subset_file.writelines(explain_subset_lines)

    result = CliRunner().invoke(main, ["--explain", str(explain_subset_path)])

    assert result.exit_code == 0, (
        f"--explain over the distilled subset should succeed, got exit code "
        f"{result.exit_code}: {result.output}"
    )

    # Must be checked against the raw bytes, not the decoded str: a UTF-8
    # mis-encoding of the same high byte would satisfy a naive `in
    # result.output` check without actually being the correct escaped form.
    stdout_bytes = result.stdout_bytes
    assert EXPLAIN_ANCHOR_ESCAPED_BYTES in stdout_bytes, (
        f"expected the escaped high-byte line {EXPLAIN_ANCHOR_ESCAPED_BYTES!r} in --explain "
        "output; a reverted latin-1->utf-8 fix would crash before producing any output at all"
    )

    # The trailing-space argument on the space-arg-vulnerable line must
    # still be explained (not silently dropped to "[!] Unknown rule").
    # Mirror exactly what the CLI does to the explanation string
    # (_escape_bytes, then utf-8 encode - the explanation text can contain
    # genuine Unicode like the U+2192 "->" arrow, which _escape_bytes
    # deliberately leaves intact since it's >= 0x100, so utf-8 -- not
    # latin-1 -- is the correct encoding here).
    assert first_space_arg_verdict is not None  # narrows type for mypy
    expected_explanation_bytes = _escape_bytes(first_space_arg_verdict[0]).encode("utf-8")
    assert expected_explanation_bytes in stdout_bytes, (
        "expected --explain to preserve the trailing-space rule argument and produce "
        f"{expected_explanation_bytes!r}; a reverted rstrip->strip fix would instead "
        "show '[!] Unknown rule or no explanation available' for this line"
    )
