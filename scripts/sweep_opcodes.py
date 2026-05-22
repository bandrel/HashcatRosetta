#!/usr/bin/env python3
"""Systematic per-opcode correctness sweep.

For each opcode in `_DEFAULT_IMPLEMENTED`, generates a small set of rules
covering a canonical arg grid, runs them against the baseword corpus via
`hashcat_rosetta._verify.verify_corpus`, and emits a per-opcode matrix
identifying any opcode with mismatches.

Exit code is `0` if every mismatch is on an opcode in `KNOWN_LATENT`, else `1`.

Usage:
    uv run python scripts/sweep_opcodes.py [--report PATH] [--json PATH]

Requires: hashcat binary in PATH.
"""

from __future__ import annotations

# Arg-grid constants. These define the script's input contract; widening
# them is a deliberate design choice. See spec section "Arg Grid".

# Hashcat encodes positions 0-9 as '0'-'9' and 10-35 as 'A'-'Z'.
# Picks: start, near-start, mid, end-of-9, double-digit boundary.
POSITION_ARGS: tuple[str, ...] = ("0", "1", "5", "9", "A")

# Representative characters: lowercase letter, digit, symbol, uppercase, space.
CHAR_ARGS: tuple[str, ...] = ("a", "1", "!", "Z", " ")

# 3x3 grid for 2-arg opcodes. Each entry is a 2-char string of (arg1, arg2).
# Picked to exercise: same/different, letter/digit/symbol, low/mid/high position.
TWO_ARG_GRID: tuple[str, ...] = (
    "ab",  # letter-letter
    "a1",  # letter-digit
    "01",  # digit-digit position-like
    "12",  # adjacent digits
    "59",  # mid + high digits
    "0A",  # low + double-digit position boundary
    "!a",  # symbol-letter
    "Za",  # uppercase-lowercase
    " a",  # space-letter
)

# For 3-arg (`X` = insert substring from memory at N, length M).
# X requires a prior M (memorize) opcode to have valid memory state, but the
# sweep tests it in isolation; expect skipped_hashcat_unsupported or rejection.
THREE_ARG_GRID: tuple[str, ...] = (
    "012",
    "013",
    "025",
    "111",
    "123",
    "1A2",
    "201",
    "501",
    "9A1",
)

# Opcode-to-reason allowlist of known latent bugs. Empty on day one.
# Each entry MUST cite a tracked issue or spec section. No bare `# TODO`.
KNOWN_LATENT: dict[str, str] = {}


def main() -> None:
    """Wire-up filled in subsequent tasks."""
    raise NotImplementedError
