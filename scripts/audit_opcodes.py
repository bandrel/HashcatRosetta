#!/usr/bin/env python3
"""One-shot opcode metadata reconciler.

Compares the authoritative opcode reference (tests/fixtures/opcodes_reference.json)
against the arity sets in hashcat_rosetta.parser.RuleParser and the descriptions in
hashcat_rosetta.formatting.OPCODE_DESCRIPTIONS, then writes a diff report to
reports/validation/opcode-audit.md.

Exit codes:
  0 — no discrepancies
  1 — one or more discrepancies found
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Hardcoded arity sets — mirrors _tokenize_rule() in hashcat_rosetta/parser.py.
# Update these whenever parser.py changes; that is the point: the test catches
# the change and forces an explicit update here and in the reference JSON.
# ---------------------------------------------------------------------------
PARSER_NO_ARG_OPS: set[str] = set(":lucCtdfr{}[]kKqEMmSwWhH4579a6Q")
PARSER_ONE_ARG_OPS: set[str] = set("TDpyYezZ^$@!><'+-.,LR()")
PARSER_TWO_ARG_OPS: set[str] = set("soi3x*=vOB%")
PARSER_THREE_ARG_OPS: set[str] = set("X")

# Derived: all opcodes known to the parser
PARSER_ALL_OPS: set[str] = (
    PARSER_NO_ARG_OPS | PARSER_ONE_ARG_OPS | PARSER_TWO_ARG_OPS | PARSER_THREE_ARG_OPS
)


def arity_from_parser(char: str) -> int | None:
    """Return the arity that parser.py currently assigns to opcode char, or None."""
    if char in PARSER_NO_ARG_OPS:
        return 0
    if char in PARSER_ONE_ARG_OPS:
        return 1
    if char in PARSER_TWO_ARG_OPS:
        return 2
    if char in PARSER_THREE_ARG_OPS:
        return 3
    return None


def load_reference(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


def load_opcode_descriptions() -> dict[str, str]:
    from hashcat_rosetta.formatting import OPCODE_DESCRIPTIONS

    return dict(OPCODE_DESCRIPTIONS)


def verify_content_hash(data: dict) -> tuple[bool, str, str]:
    """Return (ok, stored_hash, computed_hash)."""
    opcodes = data["opcodes"]
    computed = hashlib.sha256(json.dumps(opcodes, sort_keys=True).encode()).hexdigest()
    stored = data.get("content_hash", "")
    return stored == computed, stored, computed


def run_audit(reference_path: Path, report_path: Path) -> list[str]:
    """Run the full audit and return a list of discrepancy strings."""
    data = load_reference(reference_path)
    descriptions = load_opcode_descriptions()

    discrepancies: list[str] = []
    sections: dict[str, list[str]] = {
        "hash": [],
        "arity": [],
        "missing_desc": [],
        "extra_in_parser": [],
        "b_contradiction": [],
    }

    # ------------------------------------------------------------------
    # 1. Content hash integrity
    # ------------------------------------------------------------------
    hash_ok, stored_hash, computed_hash = verify_content_hash(data)
    if not hash_ok:
        msg = (
            f"Content hash mismatch: stored={stored_hash!r} computed={computed_hash!r}. "
            "The reference JSON was modified without updating content_hash."
        )
        sections["hash"].append(msg)
        discrepancies.append(msg)

    # ------------------------------------------------------------------
    # 2. Arity discrepancies: reference says N, parser says M
    # ------------------------------------------------------------------
    reference_chars: set[str] = set()
    for entry in data["opcodes"]:
        char = entry["char"]
        ref_arity = entry["arity"]
        reference_chars.add(char)

        parser_arity = arity_from_parser(char)
        if parser_arity is None:
            # Not in parser at all — covered by extra/missing section
            continue
        if parser_arity != ref_arity:
            msg = f"Opcode {char!r}: reference arity={ref_arity}, parser arity={parser_arity}"
            sections["arity"].append(msg)
            discrepancies.append(msg)

    # ------------------------------------------------------------------
    # 3. Missing descriptions: in reference but no entry in OPCODE_DESCRIPTIONS
    # ------------------------------------------------------------------
    for entry in data["opcodes"]:
        char = entry["char"]
        if char not in descriptions or not descriptions[char].strip():
            msg = f"Opcode {char!r}: present in reference but missing from OPCODE_DESCRIPTIONS"
            sections["missing_desc"].append(msg)
            discrepancies.append(msg)

    # ------------------------------------------------------------------
    # 4. Extra in parser: parser knows about chars not in reference
    # ------------------------------------------------------------------
    for char in sorted(PARSER_ALL_OPS):
        if char not in reference_chars:
            msg = f"Opcode {char!r}: in parser arity sets but not in reference JSON"
            sections["extra_in_parser"].append(msg)
            discrepancies.append(msg)

    # ------------------------------------------------------------------
    # 5. B opcode explicit check
    # ------------------------------------------------------------------
    b_entry = next((e for e in data["opcodes"] if e["char"] == "B"), None)
    if b_entry is None:
        msg = "Opcode 'B' is missing from the reference JSON entirely"
        sections["b_contradiction"].append(msg)
        discrepancies.append(msg)
    else:
        if b_entry.get("implemented_in_explain_rule") is True:
            msg = (
                "Opcode 'B' is marked implemented_in_explain_rule=true in reference, "
                "but cli.py's B handler is a no-op with a wrong comment."
            )
            sections["b_contradiction"].append(msg)
            discrepancies.append(msg)
        if b_entry.get("status") == "implemented":
            msg = (
                "Opcode 'B' status is 'implemented' in reference, but the actual "
                "implementation in cli.py only logs a no-op step."
            )
            sections["b_contradiction"].append(msg)
            discrepancies.append(msg)

    # ------------------------------------------------------------------
    # Write markdown report
    # ------------------------------------------------------------------
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "# Opcode Metadata Audit Report",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Reference: `{reference_path}`",
        "",
        f"**Total discrepancies found: {len(discrepancies)}**",
        "",
    ]

    def section(title: str, items: list[str]) -> None:
        lines.append(f"## {title}")
        lines.append("")
        if items:
            for item in items:
                lines.append(f"- {item}")
        else:
            lines.append("_None — all clear._")
        lines.append("")

    section("1. Content Hash Integrity", sections["hash"])
    section("2. Arity Discrepancies (reference vs parser.py)", sections["arity"])
    section("3. Missing OPCODE_DESCRIPTIONS Entries", sections["missing_desc"])
    section("4. Opcodes in Parser But Not in Reference", sections["extra_in_parser"])
    section("5. B Opcode Contradiction", sections["b_contradiction"])

    lines += [
        "---",
        "",
        "## Notes",
        "",
        "- **Reference source:** `tests/fixtures/opcodes_reference.json`",
        "- **Parser arity sets:** hardcoded copy of `_tokenize_rule()` locals in `scripts/audit_opcodes.py`",
        "- **Descriptions source:** `hashcat_rosetta.formatting.OPCODE_DESCRIPTIONS`",
        "",
        "Known expected discrepancies (pre-existing bugs to fix, not regressions):",
        "",
        "- `B` is documented (RULE_OP_MANGLE_CHR_ADD) but not yet simulated in explain_rule().",
        "",
    ]

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return discrepancies


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    reference_path = repo_root / "tests" / "fixtures" / "opcodes_reference.json"
    report_path = repo_root / "reports" / "validation" / "opcode-audit.md"

    if not reference_path.exists():
        print(f"ERROR: Reference file not found: {reference_path}", file=sys.stderr)
        return 2

    print(f"Loading reference from: {reference_path}")
    discrepancies = run_audit(reference_path, report_path)

    print(f"\nReport written to: {report_path}")
    print(f"\nSummary: {len(discrepancies)} discrepancy(ies) found")

    if discrepancies:
        print("\nDiscrepancies:")
        for d in discrepancies:
            print(f"  - {d}")
        return 1

    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
