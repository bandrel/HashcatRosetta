#!/usr/bin/env python3
"""Verify explain_rule() against actual hashcat output using random generated rules.

Usage:
    uv run python scripts/verify_rules.py [OPTIONS]

Requires:
    - hashcat binary in PATH
    - generate-rules.bin at ~/hashcat-utils/src/generate-rules.bin
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hashcat_rosetta.cli import REJECT_SENTINEL_PREFIX, explain_rule
from hashcat_rosetta.parser import RuleParser

GENERATE_RULES_BIN = Path.home() / "hashcat-utils" / "src" / "generate-rules.bin"

# Opcodes that explain_rule() currently implements (transforms the word)
IMPLEMENTED_OPCODES: set[str] = {
    # From rule_map (zero-arg)
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
    # Explicit handlers (with args)
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
    # Memory and filter opcodes
    "M",
    "X",
    "=",
    "B",
}

# All known hashcat opcodes and their arities (from RuleParser)
THREE_ARG_OPCODES: set[str] = set("X")
TWO_ARG_OPCODES: set[str] = set("soix*=vOB")
ONE_ARG_OPCODES: set[str] = set("TDpyYezZ^$@!><'+-.,%LRa()")
ZERO_ARG_OPCODES: set[str] = set(":culdrt[]{}fkKqCEM")

ALL_KNOWN_OPCODES = THREE_ARG_OPCODES | TWO_ARG_OPCODES | ONE_ARG_OPCODES | ZERO_ARG_OPCODES

# Opcode descriptions for documentation
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
    "v": "Swap case of character at position N (lowercase <-> uppercase)",
    "B": "Bitwise operation B(N,X) - apply bitwise op at position",
    "a": "Append string from memory",
    "e": "Title case with separator (uppercase first letter after each separator)",
    "(": "Character class check - reject unless char at pos N is in class",
    ")": "Character class check - reject if char at pos N is in class",
}


def check_prerequisites() -> None:
    """Verify that hashcat and generate-rules.bin are available."""
    if not GENERATE_RULES_BIN.exists():
        print(f"ERROR: generate-rules.bin not found at {GENERATE_RULES_BIN}", file=sys.stderr)
        sys.exit(2)
    try:
        subprocess.run(["hashcat", "--version"], capture_output=True, timeout=5).check_returncode()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("ERROR: hashcat binary not available or not working", file=sys.stderr)
        sys.exit(2)


def generate_rules(count: int, seed: int) -> list[str]:
    """Generate random rules using hashcat-utils generate-rules.bin."""
    result = subprocess.run(
        [str(GENERATE_RULES_BIN), str(count), str(seed)],
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(f"ERROR: generate-rules.bin failed: {result.stderr.decode()}", file=sys.stderr)
        sys.exit(2)
    return [line for line in result.stdout.decode().splitlines() if line.strip()]


def get_hashcat_output(rule: str, baseword: str) -> str | None:
    """Run a single rule through hashcat and return the result."""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rule", delete=False) as f:
            f.write(rule)
            temp_rule_file = f.name
        try:
            result = subprocess.run(
                ["hashcat", "-a0", "-r", temp_rule_file, "--stdout", "-d1"],
                input=baseword.encode(),
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.decode().strip()
                return output if output else None
            return None
        finally:
            if os.path.exists(temp_rule_file):
                os.unlink(temp_rule_file)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


def extract_opcodes_from_rule(rule_str: str) -> list[str]:
    """Parse a rule string and return a list of opcode characters."""
    opcodes = []
    i = 0
    while i < len(rule_str):
        char = rule_str[i]
        if char == " ":
            i += 1
            continue
        opcodes.append(char)
        if char in THREE_ARG_OPCODES and i + 3 < len(rule_str):
            i += 4
        elif char in TWO_ARG_OPCODES and i + 2 < len(rule_str):
            i += 3
        elif char in ONE_ARG_OPCODES and i + 1 < len(rule_str):
            i += 2
        else:
            i += 1
    return opcodes


def find_unimplemented_opcodes(rule_str: str) -> set[str]:
    """Return the set of opcodes in a rule that explain_rule does not implement."""
    opcodes = extract_opcodes_from_rule(rule_str)
    return {op for op in opcodes if op not in IMPLEMENTED_OPCODES and op in ALL_KNOWN_OPCODES}


def run_round(
    rules: list[str],
    seed: int,
    baseword: str,
    workers: int,
    verbose: bool,
) -> dict:
    """Run one verification round. Returns a results dict."""
    parser = RuleParser()

    # Pre-compute explain_rule results, tracking skipped opcodes
    testable = []
    skipped_unimplemented = 0
    skipped_invalid = 0
    skipped_rules: list[dict] = []
    for idx, rule in enumerate(rules):
        explanation = explain_rule(rule, baseword)
        if explanation is None or len(explanation) == 0:
            unimpl = find_unimplemented_opcodes(rule)
            if unimpl:
                skipped_unimplemented += 1
                skipped_rules.append(
                    {
                        "rule": rule,
                        "index": idx,
                        "unimplemented_opcodes": sorted(unimpl),
                    }
                )
            else:
                skipped_invalid += 1
            continue
        testable.append((idx, rule, explanation))

    # Check each rule against hashcat in parallel
    def _check(item: tuple[int, str, list[str]]) -> dict | None:
        idx, rule, explanation = item
        hashcat_result = get_hashcat_output(rule, baseword)

        # Handle rejection sentinel: explain_rule() signals rejection by appending a
        # step that starts with REJECT_SENTINEL_PREFIX.  hashcat signals rejection by
        # producing no output (None from get_hashcat_output).
        last_step = explanation[-1]
        if last_step.startswith(REJECT_SENTINEL_PREFIX):
            if hashcat_result is None:
                # Both sides agree: the word was rejected.
                return {"status": "match", "rule": rule, "idx": idx}
            # We predicted rejection but hashcat produced output → mismatch.
            parsed = parser.parse_rule(rule)
            components = parsed["components"] if parsed else []
            return {
                "status": "mismatch",
                "rule": rule,
                "idx": idx,
                "ours": last_step,
                "hashcat": hashcat_result,
                "components": [
                    {"opcode": c.get("opcode", "?"), "description": c.get("description", "?")}
                    for c in components
                ],
            }

        if hashcat_result is None:
            return {"status": "skipped_hashcat", "rule": rule, "idx": idx}
        if not hashcat_result.isascii():
            return {"status": "skipped_nonascii", "rule": rule, "idx": idx}
        our_result = last_step.split("\u2192")[-1].strip()
        if our_result == hashcat_result:
            return {"status": "match", "rule": rule, "idx": idx}
        # Mismatch - gather details
        parsed = parser.parse_rule(rule)
        components = parsed["components"] if parsed else []
        return {
            "status": "mismatch",
            "rule": rule,
            "idx": idx,
            "ours": our_result,
            "hashcat": hashcat_result,
            "components": [
                {"opcode": c.get("opcode", "?"), "description": c.get("description", "?")}
                for c in components
            ],
        }

    results: dict[str, Any] = {
        "seed": seed,
        "total_rules": len(rules),
        "skipped_unimplemented": skipped_unimplemented,
        "skipped_invalid": skipped_invalid,
        "skipped_hashcat": 0,
        "skipped_nonascii": 0,
        "tested": 0,
        "matched": 0,
        "mismatches": [],
        "skipped_rules": skipped_rules,
    }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check, item): item for item in testable}
        for future in as_completed(futures):
            r = future.result()
            if r is None:
                continue
            if r["status"] == "skipped_hashcat":
                results["skipped_hashcat"] += 1
            elif r["status"] == "skipped_nonascii":
                results["skipped_nonascii"] += 1
            elif r["status"] == "match":
                results["tested"] += 1
                results["matched"] += 1
            elif r["status"] == "mismatch":
                results["tested"] += 1
                mismatch = {
                    "rule": r["rule"],
                    "seed": seed,
                    "index": r["idx"],
                    "ours": r["ours"],
                    "hashcat": r["hashcat"],
                    "components": r["components"],
                }
                results["mismatches"].append(mismatch)
                if verbose:
                    print(
                        f"  MISMATCH rule={r['rule']!r} ours={r['ours']!r} hashcat={r['hashcat']!r}"
                    )

    return results


def print_round_summary(results: dict, round_num: int) -> None:
    """Print a summary for one round."""
    n_mm = len(results["mismatches"])
    print(f"\n--- Round {round_num} (seed={results['seed']}) ---")
    print(f"  Total rules:       {results['total_rules']}")
    print(f"  Skipped (unimpl):  {results['skipped_unimplemented']}")
    print(f"  Skipped (invalid): {results['skipped_invalid']}")
    print(f"  Skipped (hashcat): {results['skipped_hashcat']}")
    print(f"  Skipped (non-ASCII): {results['skipped_nonascii']}")
    print(f"  Tested:            {results['tested']}")
    print(f"  Matched:           {results['matched']}")
    print(f"  Mismatches:        {n_mm}")

    if n_mm > 0:
        print(f"\n  First {min(n_mm, 20)} mismatches:")
        for mm in results["mismatches"][:20]:
            opcodes = " ".join(c["opcode"] for c in mm["components"])
            print(
                f"    rule={mm['rule']!r:30s} ours={mm['ours']!r:20s} hashcat={mm['hashcat']!r:20s} opcodes=[{opcodes}]"
            )
        if n_mm > 20:
            print(f"    ... and {n_mm - 20} more")


def write_skipped_opcodes_report(all_results: list[dict], output_dir: str) -> str:
    """Write a markdown report of skipped (unimplemented) opcodes.

    Returns the path to the written file.
    """
    # Aggregate: for each unimplemented opcode, collect example rules and counts
    opcode_stats: dict[str, dict] = defaultdict(lambda: {"count": 0, "examples": []})

    for round_results in all_results:
        for skipped in round_results["skipped_rules"]:
            for op in skipped["unimplemented_opcodes"]:
                stats = opcode_stats[op]
                stats["count"] += 1
                if len(stats["examples"]) < 5:
                    stats["examples"].append(
                        {
                            "rule": skipped["rule"],
                            "seed": round_results["seed"],
                            "index": skipped["index"],
                        }
                    )

    if not opcode_stats:
        return ""

    # Sort by frequency (most common first)
    sorted_opcodes = sorted(opcode_stats.items(), key=lambda x: x[1]["count"], reverse=True)

    total_skipped = sum(r["skipped_unimplemented"] for r in all_results)

    os.makedirs(output_dir, exist_ok=True)

    # -- Summary report --
    summary_path = os.path.join(output_dir, "skipped-opcodes.md")
    lines = [
        "# Skipped Opcodes Summary",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"Total rules skipped (unimplemented): **{total_skipped}**",
        "",
        f"Distinct unimplemented opcodes found: **{len(sorted_opcodes)}**",
        "",
        "| Opcode | Description | Rules Affected | Arity |",
        "|--------|-------------|---------------|-------|",
    ]

    for op, stats in sorted_opcodes:
        desc = OPCODE_DESCRIPTIONS.get(op, "Unknown")
        if op in TWO_ARG_OPCODES:
            arity = "2-arg"
        elif op in ONE_ARG_OPCODES:
            arity = "1-arg"
        else:
            arity = "0-arg"
        lines.append(f"| `{op}` | {desc} | {stats['count']} | {arity} |")

    lines += [
        "",
        "## Per-opcode details",
        "",
        "Each opcode below has a dedicated file with example rules for testing.",
        "",
    ]

    for op, _stats in sorted_opcodes:
        safe_name = _opcode_filename(op)
        lines.append(
            f"- [`{op}`](opcode-{safe_name}.md) - {OPCODE_DESCRIPTIONS.get(op, 'Unknown')}"
        )

    lines.append("")

    with open(summary_path, "w") as f:
        f.write("\n".join(lines))

    # -- Per-opcode detail files --
    for op, stats in sorted_opcodes:
        safe_name = _opcode_filename(op)
        detail_path = os.path.join(output_dir, f"opcode-{safe_name}.md")
        desc = OPCODE_DESCRIPTIONS.get(op, "Unknown")

        if op in TWO_ARG_OPCODES:
            arity = "2-arg (opcode + 2 parameter characters)"
        elif op in ONE_ARG_OPCODES:
            arity = "1-arg (opcode + 1 parameter character)"
        else:
            arity = "0-arg (opcode only)"

        detail_lines = [
            f"# Opcode `{op}` - {desc}",
            "",
            f"- **Arity**: {arity}",
            f"- **Rules affected**: {stats['count']}",
            "- **Status**: Not implemented in `explain_rule()`",
            "",
            "## Example rules containing this opcode",
            "",
            "Use these to test your implementation:",
            "",
            "```",
        ]

        for ex in stats["examples"]:
            detail_lines.append(f"{ex['rule']}  # seed={ex['seed']} index={ex['index']}")

        detail_lines += [
            "```",
            "",
            "## Reproduce",
            "",
            "```bash",
            f"# Generate rules from a specific seed and grep for opcode '{op}'",
        ]

        if stats["examples"]:
            ex_seed = stats["examples"][0]["seed"]
            detail_lines.append(
                f"~/hashcat-utils/src/generate-rules.bin 1000 {ex_seed} | grep -F '{op}'"
            )

        detail_lines += [
            "",
            "# Test a specific rule against hashcat",
            f'echo "password" | hashcat -a0 -r <(echo "{stats["examples"][0]["rule"]}") --stdout -d1',
            "```",
            "",
            "## Implementation notes",
            "",
            f"Add handling for `{op}` in `explain_rule()` in `hashcat_rosetta/cli.py`.",
            "",
            "Reference: https://hashcat.net/wiki/doku.php?id=rule_based_attack",
            "",
        ]

        with open(detail_path, "w") as f:
            f.write("\n".join(detail_lines))

    print(f"\nSkipped opcodes report written to {output_dir}/")
    print(f"  Summary: {summary_path}")
    print(f"  Detail files: {len(sorted_opcodes)} opcode-*.md files")

    return summary_path


def _opcode_filename(op: str) -> str:
    """Convert an opcode character to a safe filename component."""
    # Map special characters to readable names
    special: dict[str, str] = {
        "*": "star",
        "$": "dollar",
        "^": "caret",
        "[": "lbracket",
        "]": "rbracket",
        "{": "lbrace",
        "}": "rbrace",
        "<": "lt",
        ">": "gt",
        "'": "apostrophe",
        "+": "plus",
        "-": "minus",
        ".": "dot",
        ",": "comma",
        "%": "percent",
        "!": "bang",
        "@": "at",
        ":": "colon",
        "=": "equals",
        "(": "lparen",
        ")": "rparen",
    }
    return special.get(op, op)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify explain_rule() against hashcat for random generated rules."
    )
    parser.add_argument("--count", type=int, default=1000, help="Rules per round (default: 1000)")
    parser.add_argument("--seed", type=int, default=None, help="Starting seed (default: random)")
    parser.add_argument("--rounds", type=int, default=1, help="Number of rounds (default: 1)")
    parser.add_argument(
        "--baseword", type=str, default="password", help="Baseword (default: password)"
    )
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Parallel workers")
    parser.add_argument(
        "--stop-early", action="store_true", help="Stop after first round with mismatches"
    )
    parser.add_argument("--verbose", action="store_true", help="Print each mismatch as found")
    parser.add_argument("--report", type=str, default=None, help="Write JSON report to file")
    parser.add_argument(
        "--skipped-dir",
        type=str,
        default="reports/skipped-opcodes",
        help="Directory for skipped opcode markdown reports (default: reports/skipped-opcodes)",
    )
    args = parser.parse_args()

    if args.seed is None:
        args.seed = int(time.time()) % 100000

    check_prerequisites()

    print(
        f"Verify rules: count={args.count} seed={args.seed} rounds={args.rounds} baseword={args.baseword!r}"
    )

    all_results = []
    any_mismatches = False

    for round_num in range(1, args.rounds + 1):
        seed = args.seed + round_num - 1
        print(f"\nGenerating {args.count} rules (seed={seed})...")
        rules = generate_rules(args.count, seed)
        print(f"Running verification ({len(rules)} rules, {args.workers} workers)...")

        results = run_round(rules, seed, args.baseword, args.workers, args.verbose)
        all_results.append(results)
        print_round_summary(results, round_num)

        if len(results["mismatches"]) > 0:
            any_mismatches = True
            if args.stop_early:
                print("\n--stop-early: stopping after first round with mismatches")
                break

    # Write skipped opcodes markdown reports
    total_skipped = sum(r["skipped_unimplemented"] for r in all_results)
    if total_skipped > 0:
        write_skipped_opcodes_report(all_results, args.skipped_dir)

    # Write JSON report if requested
    if args.report:
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "config": {
                "count": args.count,
                "seed": args.seed,
                "rounds": args.rounds,
                "baseword": args.baseword,
            },
            "rounds": all_results,
            "summary": {
                "total_tested": sum(r["tested"] for r in all_results),
                "total_matched": sum(r["matched"] for r in all_results),
                "total_mismatches": sum(len(r["mismatches"]) for r in all_results),
            },
        }
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport written to {args.report}")

    # Final summary
    total_tested = sum(r["tested"] for r in all_results)
    total_mm = sum(len(r["mismatches"]) for r in all_results)
    print(f"\n{'=' * 50}")
    print(f"TOTAL: {total_tested} tested, {total_mm} mismatches across {len(all_results)} round(s)")

    if any_mismatches:
        print("RESULT: FAIL")
        sys.exit(1)
    else:
        print("RESULT: PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
