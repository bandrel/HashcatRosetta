"""Private verification harness library.

Diffs `explain_rule` output against the actual hashcat binary across a baseword
corpus. Public surface: `verify_rule`, `verify_corpus`, `load_baseword_corpus`.

Underscore prefix: this module is internal. Do not import from outside the
package or expose its names from `__init__.py`.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from hashcat_rosetta.cli import explain_rule
from hashcat_rosetta.parser import RuleParser

VerifyStatus = Literal[
    "match",
    "mismatch",
    "skipped_unimpl",
    "skipped_hashcat",
    "skipped_hashcat_unsupported",
    "skipped_nonascii",
]


@dataclass
class VerifyResult:
    status: VerifyStatus
    rule: str
    baseword: str
    ours: str | None = None
    hashcat: str | None = None
    unimpl_opcodes: list[str] = field(default_factory=list)


@dataclass
class CorpusReport:
    rounds: list[dict] = field(default_factory=list)
    total_tested: int = 0
    total_matched: int = 0
    total_mismatches: int = 0


def load_baseword_corpus(path: Path) -> list[str]:
    """Load corpus JSON; return just the value field for each entry."""
    data = json.loads(Path(path).read_text())
    values: list[str] = []
    for idx, entry in enumerate(data):
        if "value" not in entry:
            raise ValueError(f"corpus entry {idx} missing 'value' field")
        values.append(entry["value"])
    return values


def decide_rejection_status(
    ours_rejected: bool, hashcat_rejected: bool
) -> Literal["match", "mismatch", "needs_string_compare"]:
    """Compare rejection outcomes; spec phase 1 rejection-semantics fix.

    Both rejected -> match. One rejected -> mismatch. Neither rejected ->
    caller still needs to compare strings.
    """
    if ours_rejected and hashcat_rejected:
        return "match"
    if ours_rejected != hashcat_rejected:
        return "mismatch"
    return "needs_string_compare"


# Mirrors verify_rules.py - keep in sync if hashcat adds opcodes.
_THREE_ARG_OPCODES: set[str] = set("X")
_TWO_ARG_OPCODES: set[str] = set("soix*=vOB")
_ONE_ARG_OPCODES: set[str] = set("TDpyYezZ^$@!><'+-.,%LR()e")
_ZERO_ARG_OPCODES: set[str] = set(":culdrt[]{}fkKqCEMa")
_ALL_KNOWN_OPCODES = _THREE_ARG_OPCODES | _TWO_ARG_OPCODES | _ONE_ARG_OPCODES | _ZERO_ARG_OPCODES

# Opcodes that hashcat's --stdout pipeline refuses to compile (rule rejected
# with exit 255 "No valid rules left"). Verified empirically against 6.2.6 and
# 7.1.2.
#   M, X: CPU-only rule operations not in OpenCL/Metal kernels.
#   !, <, >, %, (, ), =: filter/reject opcodes. --stdout only emits *modified*
#     candidates; pure-filter rules (those whose only effect is to accept or
#     reject the unchanged baseword) produce no --stdout output at all, even
#     when the filter logically passes. Filters exist for the hashing flow,
#     not the candidate-emission flow.
# Rules whose leading opcode is in this set are skipped by the harness because
# hashcat cannot serve as an oracle for them.
_HASHCAT_STDOUT_UNSUPPORTED: set[str] = set("MX!<>%()=")

# Default implemented-opcodes set for the harness. Mirrors
# scripts/verify_rules.py:IMPLEMENTED_OPCODES; the script wraps this module
# and may pass its own set.
_DEFAULT_IMPLEMENTED: set[str] = {
    ":",
    "c",
    "u",
    "l",
    "d",
    "r",
    "t",
    "[",
    "]",
    "{",
    "}",
    "f",
    "k",
    "K",
    "q",
    "C",
    "E",
    "$",
    "^",
    "i",
    "s",
    "p",
    "D",
    "T",
    "O",
    "y",
    "Y",
    "z",
    "Z",
    "@",
    "!",
    ">",
    "<",
    "'",
    "+",
    "-",
    ".",
    ",",
    "%",
    "R",
    "L",
    "o",
    "x",
    "*",
    "M",
    "X",
    "=",
    "B",
    "(",
    ")",
    "v",
    "e",
}


def _extract_opcodes(rule_str: str) -> list[str]:
    opcodes: list[str] = []
    i = 0
    while i < len(rule_str):
        char = rule_str[i]
        if char == " ":
            i += 1
            continue
        opcodes.append(char)
        if char in _THREE_ARG_OPCODES and i + 3 < len(rule_str):
            i += 4
        elif char in _TWO_ARG_OPCODES and i + 2 < len(rule_str):
            i += 3
        elif char in _ONE_ARG_OPCODES and i + 1 < len(rule_str):
            i += 2
        else:
            i += 1
    return opcodes


# Opcodes whose first argument is a 0-indexed position into the current word.
# Hashcat rejects the entire rule when the position exceeds the word length;
# our parser silently no-ops most of them. Detecting OOB here keeps us in
# sync with hashcat's stricter validation.
_POS_1ARG_FIRST: set[str] = set("TD'+-.,RL")
_POS_2ARG_FIRST: set[str] = set("io=*xOvB")
# Opcodes whose second argument is ALSO a position (in addition to the first).
_POS_2ARG_SECOND: set[str] = set("*")


def _hex_value(c: str) -> int | None:
    """Hashcat positional encoding: '0'-'9' -> 0-9, 'A'-'Z' -> 10-35."""
    if len(c) != 1:
        return None
    if c.isdigit():
        return int(c)
    if "A" <= c <= "Z":
        return ord(c) - ord("A") + 10
    return None


def _has_oob_position(rule_str: str, baseword: str) -> bool:
    """True if any positional opcode references a position past the current
    word length at that step. Tracks word length through the rule so a prior
    length-doubling op (d, f, q, p) opens room for later positions."""
    cur_len = len(baseword)
    i = 0
    n = len(rule_str)
    while i < n:
        c = rule_str[i]
        if c == " ":
            i += 1
            continue
        if c in _THREE_ARG_OPCODES:
            arity = 3
        elif c in _TWO_ARG_OPCODES:
            arity = 2
        elif c in _ONE_ARG_OPCODES:
            arity = 1
        else:
            arity = 0
        if i + arity >= n:
            # Truncated rule — handled by _has_truncated_opcode; bail.
            return False
        args = rule_str[i + 1 : i + 1 + arity]

        if c in _POS_1ARG_FIRST and arity >= 1:
            pos = _hex_value(args[0])
            if pos is not None and pos >= cur_len:
                return True
        if c in _POS_2ARG_FIRST and arity >= 2:
            pos = _hex_value(args[0])
            if pos is not None and pos >= cur_len:
                return True
        if c in _POS_2ARG_SECOND and arity >= 2:
            pos2 = _hex_value(args[1])
            if pos2 is not None and pos2 >= cur_len:
                return True

        # Update simulated length for the next iteration.
        if c in "dfq":
            cur_len *= 2
        elif c in "[]":
            cur_len = max(0, cur_len - 1)
        elif c in "$^":
            cur_len += 1
        elif c == "i":
            cur_len += 1
        elif c == "p" and arity >= 1:
            count = _hex_value(args[0])
            if count is not None:
                cur_len *= count + 1
        elif c in "yY" and arity >= 1:
            n_val = _hex_value(args[0])
            if n_val is not None:
                cur_len += min(n_val, cur_len)
        elif c in "zZ" and arity >= 1:
            n_val = _hex_value(args[0])
            if n_val is not None:
                cur_len += n_val
        elif c == "'" and arity >= 1:
            n_val = _hex_value(args[0])
            if n_val is not None:
                cur_len = min(cur_len, n_val)
        elif c == "x" and arity >= 2:
            len_arg = _hex_value(args[1])
            if len_arg is not None:
                cur_len = len_arg
        elif c == "O" and arity >= 2:
            len_arg = _hex_value(args[1])
            if len_arg is not None:
                cur_len = max(0, cur_len - len_arg)
        # Length-neutral opcodes (s, o, =, *, v, B, T, D, +, -, ., ,, R, L,
        # !, %, <, >, c, u, l, t, r, {, }, k, K, C, E, :, M, e, (, )) fall
        # through without adjusting cur_len.

        i += 1 + arity
    return False


def _has_invalid_position_arg(rule_str: str) -> bool:
    """True if any positional opcode arg uses an encoding hashcat rejects.

    Hashcat accepts only '0'-'9' (positions 0-9) and 'A'-'Z' (positions 10-35)
    for position args. Anything else — lowercase letters, symbols, spaces —
    causes hashcat to reject the rule with 'No valid rules left'. Our parser
    is more permissive (lowercase-as-hex), so we'd compute a position and
    produce a candidate that hashcat won't.
    """
    i = 0
    n = len(rule_str)
    while i < n:
        c = rule_str[i]
        if c == " ":
            i += 1
            continue
        if c in _THREE_ARG_OPCODES:
            arity = 3
        elif c in _TWO_ARG_OPCODES:
            arity = 2
        elif c in _ONE_ARG_OPCODES:
            arity = 1
        else:
            i += 1
            continue
        if i + arity >= n:
            return False  # truncated; handled by _has_truncated_opcode
        args = rule_str[i + 1 : i + 1 + arity]
        if c in _POS_1ARG_FIRST and arity >= 1 and _hex_value(args[0]) is None:
            return True
        if c in _POS_2ARG_FIRST and arity >= 2 and _hex_value(args[0]) is None:
            return True
        if c in _POS_2ARG_SECOND and arity >= 2 and _hex_value(args[1]) is None:
            return True
        i += arity + 1
    return False


def _has_truncated_opcode(rule_str: str) -> bool:
    """True if the rule contains an opcode with missing argument bytes.

    Our RuleParser silently drops such tokens; hashcat rejects the whole rule.
    Detecting this lets the harness skip rather than report a spurious mismatch.
    """
    i = 0
    n = len(rule_str)
    while i < n:
        char = rule_str[i]
        if char == " ":
            i += 1
            continue
        if char in _THREE_ARG_OPCODES:
            args_needed = 3
        elif char in _TWO_ARG_OPCODES:
            args_needed = 2
        elif char in _ONE_ARG_OPCODES:
            args_needed = 1
        else:
            i += 1
            continue
        for k in range(1, args_needed + 1):
            if i + k >= n or rule_str[i + k] == " ":
                return True
        i += args_needed + 1
    return False


def _unimplemented_opcodes(rule_str: str, implemented: set[str]) -> list[str]:
    return sorted(
        {
            op
            for op in _extract_opcodes(rule_str)
            if op not in implemented and op in _ALL_KNOWN_OPCODES
        }
    )


def _hashcat_output(rule: str, baseword: str) -> tuple[str | None, bool]:
    """Run a rule through hashcat. Returns (stdout-or-None, hashcat_failed).

    hashcat_failed=True only for actual failures (timeout, binary missing, or
    unexpected non-zero exit). Exit code 255 ("No valid rules left") means
    hashcat ran successfully but the filter rule rejected all candidates —
    that is returned as ("", False) to signal a clean rejection.
    """
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rule", delete=False) as f:
            f.write(rule)
            tmp = f.name
        # hashcat 6.2.x refuses to start when another instance holds the
        # default session lock — fatal under ThreadPoolExecutor parallelism.
        # Pass a unique --session per call so each worker gets its own
        # session/restore-file namespace.
        session = f"rosetta-{os.getpid()}-{os.path.basename(tmp)}"
        try:
            result = subprocess.run(
                [
                    "hashcat",
                    "-a0",
                    "-r",
                    tmp,
                    "--stdout",
                    "-d1",
                    "--session",
                    session,
                    "--potfile-disable",
                    "--restore-disable",
                ],
                input=baseword.encode(),
                capture_output=True,
                # POCL on Ubuntu rebuilds the OpenCL kernel on every
                # hashcat invocation; under ThreadPoolExecutor contention
                # the first calls per worker can take >10s. 30s leaves
                # headroom without making genuine failures slow to detect.
                timeout=30,
            )
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, True
    # Exit 255 means "No valid rules left" — hashcat ran but all candidates
    # were filtered by a reject opcode (!, %, =, <, >, etc.).  Treat as a
    # clean empty result, not a binary failure.
    if result.returncode == 255:
        return "", False
    if result.returncode != 0:
        return None, True
    out = result.stdout.decode(errors="replace").rstrip("\n")
    return out, False


def _extract_final(explanation: list[str] | None) -> str:
    if not explanation:
        return ""
    last = explanation[-1]
    # explain_rule formats each step as "<op>: <desc> → <prev> → <current>".
    # rsplit on the exact " → " separator (with surrounding spaces) extracts
    # <current> verbatim, including any leading/trailing whitespace that's
    # part of the candidate itself. .strip() here used to mask whitespace
    # bugs by silently trimming the baseword's own padding.
    if " \u2192 " in last:
        return last.rsplit(" \u2192 ", 1)[-1]
    return last


def verify_rule(rule: str, baseword: str, implemented: set[str] | None = None) -> VerifyResult:
    """Diff `explain_rule(rule, baseword)` against hashcat. Single check."""
    implemented = implemented if implemented is not None else _DEFAULT_IMPLEMENTED

    # An empty baseword isn't a candidate hashcat will process — it gets
    # filtered before rule application — so the harness can't use hashcat as
    # an oracle for it regardless of what rule produces.
    if baseword == "":
        return VerifyResult(
            status="skipped_hashcat_unsupported",
            rule=rule,
            baseword=baseword,
        )

    unimpl = _unimplemented_opcodes(rule, implemented)
    if unimpl:
        return VerifyResult(
            status="skipped_unimpl",
            rule=rule,
            baseword=baseword,
            unimpl_opcodes=unimpl,
        )

    extracted_opcodes = _extract_opcodes(rule)
    unsupported = any(
        op in _HASHCAT_STDOUT_UNSUPPORTED or op not in _ALL_KNOWN_OPCODES
        for op in extracted_opcodes
    )
    if (
        unsupported
        or _has_truncated_opcode(rule)
        or _has_oob_position(rule, baseword)
        or _has_invalid_position_arg(rule)
    ):
        return VerifyResult(
            status="skipped_hashcat_unsupported",
            rule=rule,
            baseword=baseword,
        )

    explanation = explain_rule(rule, baseword)
    our_final = _extract_final(explanation)
    # An empty result is functionally a rejection: hashcat's --stdout pipeline
    # filters empty candidates and exits 255, so treat our empty output as a
    # rejection to keep parity with hashcat's filtering semantics.
    ours_rejected = explanation is None or len(explanation) == 0 or our_final == ""

    hashcat_out, hashcat_failed = _hashcat_output(rule, baseword)
    if hashcat_failed:
        return VerifyResult(status="skipped_hashcat", rule=rule, baseword=baseword)

    hashcat_rejected = hashcat_out is None or hashcat_out == ""

    decision = decide_rejection_status(ours_rejected, hashcat_rejected)
    if decision == "match":
        return VerifyResult(status="match", rule=rule, baseword=baseword)
    if decision == "mismatch":
        return VerifyResult(
            status="mismatch",
            rule=rule,
            baseword=baseword,
            ours=None if ours_rejected else our_final,
            hashcat=None if hashcat_rejected else hashcat_out,
        )

    # decision == "needs_string_compare"
    if hashcat_out is not None and not hashcat_out.isascii():
        return VerifyResult(status="skipped_nonascii", rule=rule, baseword=baseword)

    if our_final == hashcat_out:
        return VerifyResult(status="match", rule=rule, baseword=baseword)
    return VerifyResult(
        status="mismatch",
        rule=rule,
        baseword=baseword,
        ours=our_final,
        hashcat=hashcat_out,
    )


def _prewarm_hashcat() -> None:
    """Force POCL/OpenCL kernel build on a single serial hashcat call so the
    parallel pool doesn't race during cold-start. Without this, the first
    16+ workers each trigger an independent kernel compile, some timing out
    and getting classified as skipped_hashcat (or worse, exit-255 ->
    spurious mismatch). One blocking call here populates the kernel cache."""
    _hashcat_output(":", "warmup")


def verify_corpus(
    rules: list[str],
    basewords: list[str],
    workers: int = 4,
    implemented: set[str] | None = None,
) -> CorpusReport:
    """Run `rules × basewords` matrix; aggregate into a CorpusReport.

    One round per baseword. Each round runs all rules in parallel and is
    appended to `report.rounds` in a dict shape compatible with the existing
    `scripts/verify_rules.py` JSON report format, so the CLI rendering code
    can stay unchanged.
    """
    _prewarm_hashcat()
    report = CorpusReport()
    for baseword in basewords:
        round_result = _run_round(rules, baseword, workers, implemented)
        report.rounds.append(round_result)
        report.total_tested += round_result["tested"]
        report.total_matched += round_result["matched"]
        report.total_mismatches += len(round_result["mismatches"])
    return report


def _run_round(
    rules: list[str],
    baseword: str,
    workers: int,
    implemented: set[str] | None,
) -> dict[str, Any]:
    parser = RuleParser()
    counts: dict[str, Any] = {
        "baseword": baseword,
        "total_rules": len(rules),
        "skipped_unimplemented": 0,
        "skipped_invalid": 0,
        "skipped_hashcat": 0,
        "skipped_hashcat_unsupported": 0,
        "skipped_nonascii": 0,
        "skipped_rule_strings": {
            "skipped_hashcat": [],
            "skipped_hashcat_unsupported": [],
            "skipped_nonascii": [],
        },
        "tested": 0,
        "matched": 0,
        "mismatches": [],
        "skipped_rules": [],
    }

    def _one(idx_rule: tuple[int, str]) -> tuple[int, str, VerifyResult]:
        idx, rule = idx_rule
        return idx, rule, verify_rule(rule, baseword, implemented)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, item) for item in enumerate(rules)]
        for future in as_completed(futures):
            idx, rule, vr = future.result()
            if vr.status == "skipped_unimpl":
                counts["skipped_unimplemented"] += 1
                counts["skipped_rules"].append(
                    {
                        "rule": rule,
                        "index": idx,
                        "unimplemented_opcodes": vr.unimpl_opcodes,
                    }
                )
            elif vr.status == "skipped_hashcat":
                counts["skipped_hashcat"] += 1
                counts["skipped_rule_strings"]["skipped_hashcat"].append(rule)
            elif vr.status == "skipped_hashcat_unsupported":
                counts["skipped_hashcat_unsupported"] += 1
                counts["skipped_rule_strings"]["skipped_hashcat_unsupported"].append(rule)
            elif vr.status == "skipped_nonascii":
                counts["skipped_nonascii"] += 1
                counts["skipped_rule_strings"]["skipped_nonascii"].append(rule)
            elif vr.status == "match":
                counts["tested"] += 1
                counts["matched"] += 1
            elif vr.status == "mismatch":
                counts["tested"] += 1
                parsed = parser.parse_rule(rule)
                tokens = parsed["components"] if parsed else []
                counts["mismatches"].append(
                    {
                        "rule": rule,
                        "baseword": baseword,
                        "index": idx,
                        "ours": vr.ours,
                        "hashcat": vr.hashcat,
                        "components": [
                            {
                                "opcode": t[0] if t else "?",
                                "description": t,
                            }
                            for t in tokens
                        ],
                    }
                )
    return counts
