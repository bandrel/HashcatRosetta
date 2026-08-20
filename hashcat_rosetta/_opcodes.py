"""Single source of truth for hashcat rule-opcode arity and argument kinds.

These tables used to live in ``_verify.py``; they were lifted here so
``parser.py`` can validate rule syntax without importing ``_verify`` (which
imports ``cli``, which imports ``parser`` — a cycle). ``_verify`` re-exports
them under its historical private names, so there is still exactly one copy.

Underscore prefix: internal module, not part of the public API.

Ground truth is hashcat's own rule engine, ``src/rp_cpu.c::_old_apply_rule``
(the function whose ``RULE_RC_SYNTAX_ERROR`` return makes hashcat skip a rule
at load time), cross-checked with ``hashcat --stdout`` on v7.1.2.
"""

from __future__ import annotations

# Mirrors scripts/verify_rules.py - keep in sync if hashcat adds opcodes.
#
# These are byte-for-byte the sets that used to live as literals in
# ``_verify.py`` (which now re-exports them), so lifting them here changes no
# behavior for ``verify_rules.py`` / ``sweep_opcodes.py``. In particular ``%``
# stays in the TWO-arg set, matching hashcat's ``%NX`` ("reject plains which
# contain char X less than N times") and ``explain_rule``'s own two-char read
# of it; ``UNVALIDATABLE_OPCODES`` below is what keeps parser.py from trying to
# walk it. ``test_opcode_tables_match_verify_literals`` pins the equivalence.
THREE_ARG_OPCODES: set[str] = set("X")
TWO_ARG_OPCODES: set[str] = set("soix*=vOB3%")
ONE_ARG_OPCODES: set[str] = set("TDpyYezZ^$@!><'+-.,LR()e")
ZERO_ARG_OPCODES: set[str] = set(":culdrt[]{}fkKqCEMahHS46Q")
ALL_KNOWN_OPCODES = THREE_ARG_OPCODES | TWO_ARG_OPCODES | ONE_ARG_OPCODES | ZERO_ARG_OPCODES

# Zero-arg opcodes hashcat accepts. Verified with the binary: `h` / `H`
# hex-encode the word (lower/upper), `S` shifts case. `4` / `6`
# (append/prepend memory) are CPU-only — hashcat's kernel-rule converter
# refuses them, but they are *syntactically* valid, and this module only judges
# syntax. Now a subset of ZERO_ARG_OPCODES above rather than an addition to it;
# kept as a named set because parser.py reports these separately.
EXTRA_ZERO_ARG_OPCODES: set[str] = set("ShH46")

# Opcodes whose syntax this module deliberately refuses to judge:
#
#   ! / ( ) = % < > _ Q   the reject class. hashcat's --stdout pipeline
#       discards any rule containing one of these, so "No valid rules left."
#       is ambiguous for them: it cannot distinguish bad syntax from "every
#       candidate was filtered out". With no usable oracle we stay silent.
#       (`%` is a further trap: hashcat's `%NX` takes *two* args while the
#       arity table above lists it as one-arg, so our own walk would go out
#       of step on it.)
#   ~   the class-based prefix (`~s?dX`, `~@?C`, ...). Its arity depends on
#       the opcode that follows, which we do not model.
#
# Hitting one of these stops validation for the rest of the rule: without
# reliable arity we cannot keep the walk aligned, and a misaligned walk is
# exactly how false "invalid rule" verdicts happen.
UNVALIDATABLE_OPCODES: set[str] = set("!/()=%<>_Q~")

# Argument kinds per opcode, one character per argument:
#   "N" - numeric ("position") arg, parsed by hashcat's conv_ctoi
#   "X" - character arg, any byte accepted
# Derived from the NEXT_RPTOI (numeric) vs bare NEXT_RULEPOS (character)
# calls in _old_apply_rule. Reject-class opcodes are intentionally absent.
OPCODE_ARG_KINDS: dict[str, str] = {
    # one-arg, numeric
    "T": "N",
    "D": "N",
    "p": "N",
    "y": "N",
    "Y": "N",
    "z": "N",
    "Z": "N",
    "'": "N",
    "+": "N",
    "-": "N",
    ".": "N",
    ",": "N",
    "L": "N",
    "R": "N",
    # one-arg, character
    "$": "X",
    "^": "X",
    "@": "X",
    "e": "X",
    # two-arg
    "x": "NN",
    "O": "NN",
    "*": "NN",
    "i": "NX",
    "o": "NX",
    "v": "NX",
    "B": "NX",
    "3": "NX",
    "s": "XX",
    # three-arg
    "X": "NNN",
}

# hashcat's conv_ctoi accepts only these for a numeric arg: '0'-'9' -> 0-9,
# 'A'-'Z' -> 10-35. Anything else is a syntax error and the rule is skipped.
NUMERIC_ARG_CHARS: str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# RULE_LAST_REJECTED_SAVED_POS. In a numeric-arg slot, 'p' means "the position
# saved by the last class-based reject" (rp_cpu.c::conv_pos). It is only legal
# when a preceding rule set that position, which we do not track — so we
# accept it unconditionally rather than risk a false "invalid" verdict.
SAVED_POS_ARG_CHAR: str = "p"
