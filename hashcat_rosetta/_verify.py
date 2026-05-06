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

VerifyStatus = Literal["match", "mismatch", "skipped_unimpl", "skipped_hashcat", "skipped_nonascii"]


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
_ONE_ARG_OPCODES: set[str] = set("TDpyYezZ^$@!><'+-.,%LRa()")
_ZERO_ARG_OPCODES: set[str] = set(":culdrt[]{}fkKqCEM")
_ALL_KNOWN_OPCODES = _THREE_ARG_OPCODES | _TWO_ARG_OPCODES | _ONE_ARG_OPCODES | _ZERO_ARG_OPCODES

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
        try:
            result = subprocess.run(
                ["hashcat", "-a0", "-r", tmp, "--stdout", "-d1"],
                input=baseword.encode(),
                capture_output=True,
                timeout=5,
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
    out = result.stdout.decode().rstrip("\n")
    return out, False


def _extract_final(explanation: list[str] | None) -> str:
    if not explanation:
        return ""
    last = explanation[-1]
    if "\u2192" in last:
        return last.split("\u2192")[-1].strip()
    return last


def verify_rule(rule: str, baseword: str, implemented: set[str] | None = None) -> VerifyResult:
    """Diff `explain_rule(rule, baseword)` against hashcat. Single check."""
    implemented = implemented if implemented is not None else _DEFAULT_IMPLEMENTED

    unimpl = _unimplemented_opcodes(rule, implemented)
    if unimpl:
        return VerifyResult(
            status="skipped_unimpl",
            rule=rule,
            baseword=baseword,
            unimpl_opcodes=unimpl,
        )

    explanation = explain_rule(rule, baseword)
    ours_rejected = explanation is None or len(explanation) == 0

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
            ours=None if ours_rejected else _extract_final(explanation),
            hashcat=None if hashcat_rejected else hashcat_out,
        )

    # decision == "needs_string_compare"
    if hashcat_out is not None and not hashcat_out.isascii():
        return VerifyResult(status="skipped_nonascii", rule=rule, baseword=baseword)

    our_final = _extract_final(explanation)
    if our_final == hashcat_out:
        return VerifyResult(status="match", rule=rule, baseword=baseword)
    return VerifyResult(
        status="mismatch",
        rule=rule,
        baseword=baseword,
        ours=our_final,
        hashcat=hashcat_out,
    )


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
        "skipped_nonascii": 0,
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
            elif vr.status == "skipped_nonascii":
                counts["skipped_nonascii"] += 1
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
