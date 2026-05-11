#!/usr/bin/env python3
"""Verify explain_rule() against hashcat using random generated rules.

Usage:
    uv run python scripts/verify_rules.py [OPTIONS]

Requires:
    - hashcat binary in PATH
    - generate-rules.bin at ~/hashcat-utils/bin/generate-rules.bin
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from hashcat_rosetta._verify import (
    _DEFAULT_IMPLEMENTED,
    _ONE_ARG_OPCODES,
    _TWO_ARG_OPCODES,
    load_baseword_corpus,
    verify_corpus,
)

GENERATE_RULES_BIN = Path.home() / "hashcat-utils" / "bin" / "generate-rules.bin"
DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / "tests" / "data" / "basewords.json"

OPCODE_DESCRIPTIONS: dict[str, str] = {
    ":": "No-op (do nothing)",
    "c": "Capitalize first letter, lowercase rest",
    "C": "Lowercase first letter, uppercase rest",
    "u": "Uppercase all letters",
    "l": "Lowercase all letters",
    "d": "Duplicate entire word",
    "r": "Reverse the entire word",
    "t": "Toggle case of all characters",
    "f": "Reflect (duplicate word reversed)",
    "k": "Swap first two characters",
    "K": "Swap last two characters",
    "q": "Duplicate every character",
    "E": "Title case (uppercase first letter of each word)",
    "[": "Delete first character",
    "]": "Delete last character",
    "{": "Rotate word left",
    "}": "Rotate word right",
    "$": "Append character X",
    "^": "Prepend character X",
    "i": "Insert character Y at position X",
    "s": "Replace all instances of X with Y",
    "o": "Overwrite character at position X with Y",
    "p": "Append duplicated word N times",
    "D": "Delete character at position N",
    "T": "Toggle case at position N",
    "O": "Omit M characters starting at position N",
    "y": "Duplicate first N characters (prepend)",
    "Y": "Duplicate last N characters (append)",
    "z": "Duplicate first character N times",
    "Z": "Duplicate last character N times",
    "@": "Purge all instances of character X",
    "!": "Reject if word contains character X",
    ">": "Reject if word length is greater than N",
    "<": "Reject if word length is less than N",
    "'": "Truncate word at position N",
    "+": "Increment ASCII value of character at position N",
    "-": "Decrement ASCII value of character at position N",
    ".": "Replace character at position N with character at N+1",
    ",": "Replace character at position N with character at N-1",
    "%": "Reject unless word contains character X",
    "R": "Bitwise shift right character at position N",
    "L": "Bitwise shift left character at position N",
    "x": "Extract M characters starting at position N",
    "*": "Swap characters at positions X and Y",
    "X": "Insert substring from memory at position N, length M (requires memory)",
    "=": "Reject unless character at position N is X",
    "v": "Toggle case of character at position N every M characters",
    "B": "Bitwise operation B(N,X) - apply bitwise op at position",
    "a": "Append memorized word",
    "e": "Title case with separator (uppercase first letter and after each separator)",
    "(": "Reject unless first character equals X",
    ")": "Reject unless last character equals X",
    "M": "Memorize current word",
}


def check_prerequisites() -> None:
    if not GENERATE_RULES_BIN.exists():
        print(f"ERROR: generate-rules.bin not found at {GENERATE_RULES_BIN}", file=sys.stderr)
        sys.exit(2)
    try:
        subprocess.run(["hashcat", "--version"], capture_output=True, timeout=5).check_returncode()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("ERROR: hashcat binary not available or not working", file=sys.stderr)
        sys.exit(2)


def generate_rules(count: int, seed: int) -> list[str]:
    result = subprocess.run(
        [str(GENERATE_RULES_BIN), str(count), str(seed)],
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"ERROR: generate-rules.bin failed: {result.stderr.decode()}", file=sys.stderr)
        sys.exit(2)
    return [stripped for line in result.stdout.decode().splitlines() if (stripped := line.strip())]


def print_round_summary(round_result: dict) -> None:
    n_mm = len(round_result["mismatches"])
    print(f"\n--- baseword={round_result['baseword']!r} ---")
    print(f"  Total rules:          {round_result['total_rules']}")
    print(f"  Skipped (unimpl):     {round_result['skipped_unimplemented']}")
    print(f"  Skipped (hashcat):    {round_result['skipped_hashcat']}")
    print(f"  Skipped (non-ASCII):  {round_result['skipped_nonascii']}")
    print(f"  Tested:               {round_result['tested']}")
    print(f"  Matched:              {round_result['matched']}")
    print(f"  Mismatches:           {n_mm}")
    if n_mm > 0:
        print(f"\n  First {min(n_mm, 10)} mismatches:")
        for mm in round_result["mismatches"][:10]:
            opcodes = " ".join(c["opcode"] for c in mm["components"])
            print(
                f"    rule={mm['rule']!r:30s} ours={mm['ours']!r:20s} "
                f"hashcat={mm['hashcat']!r:20s} opcodes=[{opcodes}]"
            )


def write_skipped_opcodes_report(rounds: list[dict], output_dir: str) -> None:
    """Aggregate skipped opcodes across all rounds and write markdown reports."""
    opcode_stats: dict[str, dict] = defaultdict(lambda: {"count": 0, "examples": []})
    for round_result in rounds:
        for skipped in round_result["skipped_rules"]:
            for op in skipped["unimplemented_opcodes"]:
                stats = opcode_stats[op]
                stats["count"] += 1
                if len(stats["examples"]) < 5:
                    stats["examples"].append(
                        {
                            "rule": skipped["rule"],
                            "baseword": round_result["baseword"],
                            "index": skipped["index"],
                        }
                    )
    if not opcode_stats:
        return
    sorted_opcodes = sorted(opcode_stats.items(), key=lambda x: x[1]["count"], reverse=True)
    total_skipped = sum(r["skipped_unimplemented"] for r in rounds)
    os.makedirs(output_dir, exist_ok=True)
    summary_path = os.path.join(output_dir, "skipped-opcodes.md")
    lines = [
        "# Skipped Opcodes Summary",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total rule-runs skipped (unimplemented): **{total_skipped}**",
        "",
        f"Distinct unimplemented opcodes found: **{len(sorted_opcodes)}**",
        "",
        "| Opcode | Description | Rule-runs Affected | Arity |",
        "|--------|-------------|---------------------|-------|",
    ]
    for op, stats in sorted_opcodes:
        desc = OPCODE_DESCRIPTIONS.get(op, "Unknown")
        if op in _TWO_ARG_OPCODES:
            arity = "2-arg"
        elif op in _ONE_ARG_OPCODES:
            arity = "1-arg"
        else:
            arity = "0-arg"
        lines.append(f"| `{op}` | {desc} | {stats['count']} | {arity} |")
    Path(summary_path).write_text("\n".join(lines) + "\n")
    print(f"\nSkipped opcodes report written to {summary_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify explain_rule() against hashcat.")
    parser.add_argument("--count", type=int, default=200, help="Rules per round (default: 200)")
    parser.add_argument("--seed", type=int, default=None, help="Starting seed (default: random)")
    parser.add_argument("--rounds", type=int, default=1, help="Number of rule-generation rounds")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Parallel workers")
    parser.add_argument("--report", type=str, default=None, help="Write JSON report to file")
    parser.add_argument(
        "--skipped-dir",
        type=str,
        default="reports/skipped-opcodes",
        help="Directory for skipped opcode markdown report",
    )
    bw_group = parser.add_mutually_exclusive_group()
    bw_group.add_argument(
        "--baseword",
        type=str,
        default=None,
        help="Single ad-hoc baseword (mutually exclusive with --basewords)",
    )
    bw_group.add_argument(
        "--basewords",
        type=str,
        default=None,
        help=f"Path to corpus JSON (default: {DEFAULT_CORPUS})",
    )
    args = parser.parse_args()

    if args.seed is None:
        args.seed = int(time.time()) % 100000

    if args.baseword is not None:
        basewords = [args.baseword]
    else:
        corpus_path = Path(args.basewords) if args.basewords else DEFAULT_CORPUS
        basewords = load_baseword_corpus(corpus_path)

    check_prerequisites()

    print(
        f"Verify rules: count={args.count} seed={args.seed} rounds={args.rounds} "
        f"basewords={len(basewords)}"
    )

    all_rounds: list[dict] = []
    any_mismatches = False

    for round_num in range(1, args.rounds + 1):
        seed = args.seed + round_num - 1
        print(f"\nGenerating {args.count} rules (seed={seed})...")
        rules = generate_rules(args.count, seed)
        print(
            f"Running verification ({len(rules)} rules x {len(basewords)} basewords, "
            f"{args.workers} workers)..."
        )

        report = verify_corpus(rules, basewords, args.workers, _DEFAULT_IMPLEMENTED)
        for round_result in report.rounds:
            round_result["seed"] = seed
            print_round_summary(round_result)
        all_rounds.extend(report.rounds)
        if report.total_mismatches > 0:
            any_mismatches = True

    if sum(r["skipped_unimplemented"] for r in all_rounds) > 0:
        write_skipped_opcodes_report(all_rounds, args.skipped_dir)

    if args.report:
        report_doc = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "config": {
                "count": args.count,
                "seed": args.seed,
                "rounds": args.rounds,
                "baseword_count": len(basewords),
            },
            "rounds": all_rounds,
            "summary": {
                "total_tested": sum(r["tested"] for r in all_rounds),
                "total_matched": sum(r["matched"] for r in all_rounds),
                "total_mismatches": sum(len(r["mismatches"]) for r in all_rounds),
            },
        }
        Path(args.report).write_text(json.dumps(report_doc, indent=2))
        print(f"\nReport written to {args.report}")

    total_tested = sum(r["tested"] for r in all_rounds)
    total_mm = sum(len(r["mismatches"]) for r in all_rounds)
    print(f"\n{'=' * 50}")
    print(f"TOTAL: {total_tested} tested, {total_mm} mismatches across {len(all_rounds)} round(s)")
    if any_mismatches:
        print("RESULT: FAIL")
        sys.exit(1)
    print("RESULT: PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
