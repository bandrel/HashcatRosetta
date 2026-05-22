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

from hashcat_rosetta._verify import (  # noqa: E402
    _DEFAULT_IMPLEMENTED,
    _ONE_ARG_OPCODES,
    _THREE_ARG_OPCODES,
    _TWO_ARG_OPCODES,
    _ZERO_ARG_OPCODES,
)

# Split _ONE_ARG_OPCODES into "position" (N) vs "char" (X) buckets. Hashcat's
# rule grammar doesn't distinguish them syntactically; the split is semantic
# and informs the arg grid (POSITION_ARGS vs CHAR_ARGS). Source: opcode
# semantics in OPCODE_DESCRIPTIONS (scripts/verify_rules.py).
ONE_ARG_POSITION_OPCODES: frozenset[str] = frozenset("pDTyYzZ'+-.,LR")
ONE_ARG_CHAR_OPCODES: frozenset[str] = frozenset("$^@!><%()e")

# Sanity check: these two sets must partition (_ONE_ARG_OPCODES & implemented).
_one_arg_impl = _ONE_ARG_OPCODES & _DEFAULT_IMPLEMENTED
assert (ONE_ARG_POSITION_OPCODES | ONE_ARG_CHAR_OPCODES) >= _one_arg_impl, (
    f"1-arg buckets miss implemented opcodes: "
    f"{_one_arg_impl - (ONE_ARG_POSITION_OPCODES | ONE_ARG_CHAR_OPCODES)!r}"
)
assert not (ONE_ARG_POSITION_OPCODES & ONE_ARG_CHAR_OPCODES), "1-arg bucket overlap"

# Implemented opcodes by arity (intersect with what hashcat actually supports
# via --stdout — both M and X stay in the list; their rules will skip).
ZERO_ARG_OPCODES_IMPL: frozenset[str] = frozenset(_ZERO_ARG_OPCODES & _DEFAULT_IMPLEMENTED)
TWO_ARG_OPCODES_IMPL: frozenset[str] = frozenset(_TWO_ARG_OPCODES & _DEFAULT_IMPLEMENTED)
THREE_ARG_OPCODES_IMPL: frozenset[str] = frozenset(_THREE_ARG_OPCODES & _DEFAULT_IMPLEMENTED)


def generate_rules() -> list[str]:
    """Generate the full sweep rule set.

    Deterministic: opcodes iterated in sorted order, arg-grid order preserved.
    Each rule starts with its opcode at position 0; aggregation relies on this.
    """
    rules: list[str] = []
    for op in sorted(ZERO_ARG_OPCODES_IMPL):
        rules.append(op)
    for op in sorted(ONE_ARG_POSITION_OPCODES & _DEFAULT_IMPLEMENTED):
        for arg in POSITION_ARGS:
            rules.append(op + arg)
    for op in sorted(ONE_ARG_CHAR_OPCODES & _DEFAULT_IMPLEMENTED):
        for arg in CHAR_ARGS:
            rules.append(op + arg)
    for op in sorted(TWO_ARG_OPCODES_IMPL):
        for args in TWO_ARG_GRID:
            rules.append(op + args)
    for op in sorted(THREE_ARG_OPCODES_IMPL):
        for args in THREE_ARG_GRID:
            rules.append(op + args)
    return rules


from typing import TypedDict  # noqa: E402

from hashcat_rosetta._verify import (  # noqa: E402
    CorpusReport,
    _ALL_KNOWN_OPCODES,
    _HASHCAT_STDOUT_UNSUPPORTED,
)


class OpcodeStat(TypedDict):
    opcode: str
    tested: int
    matched: int
    mismatches: int
    unverifiable: int  # rules skipped because hashcat --stdout doesn't support
    first_failing_example: dict | None  # subset of the verify mismatch record


def aggregate_by_opcode(
    report: CorpusReport,
    rules: list[str],
) -> dict[str, OpcodeStat]:
    """Group verify results by the leading char of each rule (the opcode).

    Always includes a zero-row for every opcode in _ALL_KNOWN_OPCODES so the
    matrix surfaces UNTRACKED drift.
    """
    stats: dict[str, OpcodeStat] = {
        op: {
            "opcode": op,
            "tested": 0,
            "matched": 0,
            "mismatches": 0,
            "unverifiable": 0,
            "first_failing_example": None,
        }
        for op in _ALL_KNOWN_OPCODES
    }

    # Build rule -> opcode lookup. The generator guarantees rule[0] is the
    # opcode under test; an empty rule would be a generator bug.
    rule_to_opcode: dict[str, str] = {r: r[0] for r in rules if r}

    for round_result in report.rounds:
        # Mismatches: attribute directly.
        for mm in round_result["mismatches"]:
            op = mm["rule"][0] if mm.get("rule") else "?"
            if op not in stats:
                continue
            stats[op]["mismatches"] += 1
            stats[op]["tested"] += 1
            if stats[op]["first_failing_example"] is None:
                stats[op]["first_failing_example"] = {
                    "rule": mm["rule"],
                    "baseword": mm["baseword"],
                    "ours": mm.get("ours"),
                    "hashcat": mm.get("hashcat"),
                }
        # Matched + unverifiable: walk the rule list and classify by opcode.
        # A rule whose leading opcode is in _HASHCAT_STDOUT_UNSUPPORTED counts
        # toward `unverifiable`; otherwise — and only if it didn't appear as
        # a mismatch in this round — it counts as matched. The verify harness
        # classifies M/X deterministically; we replicate that here so we can
        # attribute per-rule outcomes (the round-level counters don't tell us
        # WHICH rules produced WHICH skips).
        mismatched_rules_this_round = {mm["rule"] for mm in round_result["mismatches"]}
        for rule, op in rule_to_opcode.items():
            if op not in stats:
                continue
            if op in _HASHCAT_STDOUT_UNSUPPORTED:
                stats[op]["unverifiable"] += 1
            elif rule not in mismatched_rules_this_round:
                stats[op]["tested"] += 1
                stats[op]["matched"] += 1

    return stats


STATUS_PASS = "PASS"
STATUS_REGRESSION = "REGRESSION"
STATUS_LATENT = "LATENT"
STATUS_UNVERIFIABLE = "UNVERIFIABLE"
STATUS_UNTRACKED = "UNTRACKED"


def derive_status(
    stats: dict[str, OpcodeStat],
    known_latent: dict[str, str],
) -> dict[str, dict]:
    """Return a per-opcode dict with `status` added. Input stats are not mutated.

    Priority order (first match wins):
      1. UNTRACKED — opcode is in _ALL_KNOWN_OPCODES but not _DEFAULT_IMPLEMENTED
      2. UNVERIFIABLE — opcode implemented but hashcat --stdout can't oracle it
      3. REGRESSION — mismatches > 0 and not in known_latent
      4. LATENT — mismatches > 0 and in known_latent
      5. PASS — everything else
    """
    rows: dict[str, dict] = {}
    for op, stat in stats.items():
        if op not in _DEFAULT_IMPLEMENTED:
            status = STATUS_UNTRACKED
        elif stat["unverifiable"] > 0 and stat["tested"] == 0:
            status = STATUS_UNVERIFIABLE
        elif stat["mismatches"] > 0:
            status = STATUS_LATENT if op in known_latent else STATUS_REGRESSION
        else:
            status = STATUS_PASS
        rows[op] = {**stat, "status": status}
    return rows


def compute_exit_code(rows: dict[str, dict]) -> int:
    """1 if any row has status REGRESSION, else 0."""
    return 1 if any(r["status"] == STATUS_REGRESSION for r in rows.values()) else 0


# Status sort priority: regressions first (most actionable), then latent
# (tracked tech debt), then everything else.
_STATUS_SORT: dict[str, int] = {
    STATUS_REGRESSION: 0,
    STATUS_LATENT: 1,
    STATUS_UNVERIFIABLE: 2,
    STATUS_PASS: 3,
    STATUS_UNTRACKED: 4,
}


def _format_example(row: dict) -> str:
    if row["status"] == "UNTRACKED":
        return "(not in _DEFAULT_IMPLEMENTED)"
    if row["status"] == "UNVERIFIABLE":
        return "(unsupported by hashcat --stdout)"
    ex = row.get("first_failing_example")
    if not ex:
        return "—"
    # Escape pipe chars for markdown cell.
    rule = (ex.get("rule") or "").replace("|", "\\|")
    bw = (ex.get("baseword") or "").replace("|", "\\|")
    ours = (ex.get("ours") or "").replace("|", "\\|")
    hc = (ex.get("hashcat") or "").replace("|", "\\|")
    return f"`{rule}` on `{bw}` → ours=`{ours}` vs hashcat=`{hc}`"


def render_markdown(rows: dict[str, dict]) -> str:
    sorted_rows = sorted(
        rows.values(),
        key=lambda r: (_STATUS_SORT.get(r["status"], 99), r["opcode"]),
    )
    lines = [
        "# Opcode Sweep Matrix",
        "",
        "| Opcode | Tested | Matched | Mismatches | Unverifiable | First Failing Example | Status |",
        "|--------|--------|---------|------------|--------------|----------------------|--------|",
    ]
    for r in sorted_rows:
        lines.append(
            f"| `{r['opcode']}` | {r['tested']} | {r['matched']} | "
            f"{r['mismatches']} | {r['unverifiable']} | "
            f"{_format_example(r)} | {r['status']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    """Wire-up filled in subsequent tasks."""
    raise NotImplementedError
