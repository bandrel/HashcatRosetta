"""Gating tests for opcode metadata consistency.

These tests compare the authoritative opcode reference
(tests/fixtures/opcodes_reference.json) against:
  1. The arity sets hardcoded in parser.py (via the audit script's mirror).
  2. OPCODE_DESCRIPTIONS in hashcat_rosetta.formatting.
  3. The content_hash field in the reference JSON (drift protection).
  4. The B opcode not being falsely marked as implemented.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from hashcat_rosetta.formatting import OPCODE_DESCRIPTIONS

# ---------------------------------------------------------------------------
# Load reference once
# ---------------------------------------------------------------------------
_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "opcodes_reference.json"


@pytest.fixture(scope="module")
def reference() -> dict[str, Any]:
    with open(_FIXTURE_PATH, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
        return data


@pytest.fixture(scope="module")
def opcodes(reference: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = reference["opcodes"]
    return result


# ---------------------------------------------------------------------------
# Hardcoded parser arity sets — mirrors _tokenize_rule() in parser.py.
# If parser.py changes, update this block AND the reference JSON.
# ---------------------------------------------------------------------------
PARSER_NO_ARG_OPS: set[str] = set(":lucCtdfr{}[]kKqEMmSwWhH4579a6Q")
PARSER_ONE_ARG_OPS: set[str] = set("TDpyYezZ^$@!><'+-.,LR()")
PARSER_TWO_ARG_OPS: set[str] = set("soi3x*=vOB%")
PARSER_THREE_ARG_OPS: set[str] = set("X")
PARSER_ALL_OPS: set[str] = (
    PARSER_NO_ARG_OPS | PARSER_ONE_ARG_OPS | PARSER_TWO_ARG_OPS | PARSER_THREE_ARG_OPS
)


def parser_arity(char: str) -> int | None:
    """Return the arity parser.py currently assigns, or None if unknown."""
    if char in PARSER_NO_ARG_OPS:
        return 0
    if char in PARSER_ONE_ARG_OPS:
        return 1
    if char in PARSER_TWO_ARG_OPS:
        return 2
    if char in PARSER_THREE_ARG_OPS:
        return 3
    return None


# ---------------------------------------------------------------------------
# Test 1: content_hash integrity (anti-drift gate)
# ---------------------------------------------------------------------------
class TestContentHash:
    def test_content_hash_present(self, reference: dict[str, Any]) -> None:
        """Reference JSON must have a non-empty content_hash field."""
        assert "content_hash" in reference, "content_hash field missing from reference JSON"
        assert reference["content_hash"], "content_hash is empty"

    def test_content_hash_matches(
        self, reference: dict[str, Any], opcodes: list[dict[str, Any]]
    ) -> None:
        """Recomputing hash from the opcodes array must match stored content_hash.

        This prevents silent drift: any edit to the opcodes array must be
        accompanied by an update to content_hash (which audit_opcodes.py can compute).
        """
        computed = hashlib.sha256(json.dumps(opcodes, sort_keys=True).encode()).hexdigest()
        stored = reference["content_hash"]
        assert computed == stored, (
            f"content_hash mismatch!\n"
            f"  stored:   {stored}\n"
            f"  computed: {computed}\n"
            "Run scripts/audit_opcodes.py and update content_hash in the reference JSON."
        )


# ---------------------------------------------------------------------------
# Test 2: Every reference opcode appears in exactly one parser arity set
# ---------------------------------------------------------------------------
# Opcodes that are documented in the reference but intentionally absent from
# parser.py (they are not tokenised because parser.py doesn't know them).
# Currently empty: parser.py now recognizes every opcode in the reference
# (6 and Q were added to no_arg_ops). Kept as a mechanism for future gaps.
KNOWN_ABSENT_FROM_PARSER: set[str] = set()

# Known arity bugs: parser.py assigns the wrong arity for these opcodes.
# When any of these bugs is fixed, the corresponding test will XPASS → FAIL
# (strict=True), forcing an explicit update here and in the reference JSON.
KNOWN_ARITY_BUGS: dict[str, str] = {}

_ALL_OPCODES = json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))["opcodes"]


def _make_param_arity(entry: dict[str, Any]) -> Any:
    """Wrap a reference entry in pytest.param, adding strict xfail for known arity bugs."""
    char = entry["char"]
    if char in KNOWN_ARITY_BUGS:
        return pytest.param(
            entry,
            id=char,
            marks=pytest.mark.xfail(strict=True, reason=KNOWN_ARITY_BUGS[char]),
        )
    return pytest.param(entry, id=char)


class TestParserArityConsistency:
    def test_no_opcode_in_multiple_arity_sets(self) -> None:
        """No opcode character should appear in more than one parser arity set."""
        overlap_01 = PARSER_NO_ARG_OPS & PARSER_ONE_ARG_OPS
        overlap_02 = PARSER_NO_ARG_OPS & PARSER_TWO_ARG_OPS
        overlap_12 = PARSER_ONE_ARG_OPS & PARSER_TWO_ARG_OPS
        assert not overlap_01, f"Opcodes in both no-arg and one-arg sets: {overlap_01}"
        assert not overlap_02, f"Opcodes in both no-arg and two-arg sets: {overlap_02}"
        assert not overlap_12, f"Opcodes in both one-arg and two-arg sets: {overlap_12}"

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(e, id=e["char"])
            for e in _ALL_OPCODES
            if e["char"] not in KNOWN_ABSENT_FROM_PARSER
        ],
    )
    def test_reference_opcode_in_parser(self, entry: dict[str, Any]) -> None:
        """Every reference opcode (except known-absent) must be in a parser arity set."""
        char = entry["char"]
        assert char in PARSER_ALL_OPS, (
            f"Opcode {char!r} is in the reference but not in any parser arity set. "
            "Add it to KNOWN_ABSENT_FROM_PARSER if intentionally unrecognised."
        )

    @pytest.mark.parametrize(
        "entry",
        [_make_param_arity(e) for e in _ALL_OPCODES if e["char"] not in KNOWN_ABSENT_FROM_PARSER],
    )
    def test_arity_matches_parser(self, entry: dict[str, Any]) -> None:
        """For opcodes in parser, reference arity must match parser arity.

        Known arity discrepancies are decorated with strict xfail via KNOWN_ARITY_BUGS
        so that fixing a bug causes XPASS → FAIL, forcing an explicit update.
        """
        char: str = entry["char"]
        ref_arity: int = entry["arity"]
        p_arity = parser_arity(char)

        if p_arity is None:
            # Covered by test_reference_opcode_in_parser; skip here.
            pytest.skip(f"Opcode {char!r} not in parser sets (covered by other test)")
            return  # unreachable but narrows type for mypy

        assert p_arity == ref_arity, (
            f"Opcode {char!r}: reference arity={ref_arity}, parser arity={p_arity}. "
            "Either fix parser.py or add this to KNOWN_ARITY_BUGS."
        )


# ---------------------------------------------------------------------------
# Test 3: Every reference opcode has a non-empty OPCODE_DESCRIPTIONS entry
# ---------------------------------------------------------------------------
class TestOpcodeDescriptions:
    @pytest.mark.parametrize(
        "entry",
        [pytest.param(e, id=e["char"]) for e in _ALL_OPCODES],
    )
    def test_has_description(self, entry: dict[str, Any]) -> None:
        """Every opcode in the reference must have a non-empty OPCODE_DESCRIPTIONS entry."""
        char = entry["char"]
        desc = OPCODE_DESCRIPTIONS.get(char, "")
        assert desc and desc.strip(), (
            f"Opcode {char!r} is in the reference but missing from OPCODE_DESCRIPTIONS "
            f"(or has an empty description)."
        )


# ---------------------------------------------------------------------------
# Test 4: B opcode is not falsely marked as fully implemented
# ---------------------------------------------------------------------------
class TestBOpcodeStatus:
    def test_b_in_reference(self, opcodes: list[dict[str, Any]]) -> None:
        """B opcode must be present in the reference JSON."""
        chars = {e["char"] for e in opcodes}
        assert "B" in chars, "Opcode 'B' is missing from the reference JSON"

    def test_b_not_implemented_in_explain_rule(self, opcodes: list[dict[str, Any]]) -> None:
        """B opcode must NOT be marked implemented_in_explain_rule=True.

        cli.py's B handler is a no-op (logs a step but does not apply the
        byte-add transformation). The old comment 'B is not a documented hashcat
        opcode' was wrong — B is RULE_OP_MANGLE_CHR_ADD — but the implementation
        is still absent, so implemented_in_explain_rule must remain False.
        """
        b_entry = next(e for e in opcodes if e["char"] == "B")
        assert b_entry["implemented_in_explain_rule"] is False, (
            "Opcode 'B' is marked implemented_in_explain_rule=True, but "
            "cli.py's B handler is a no-op. Fix the implementation first."
        )

    def test_b_status_is_unimplemented(self, opcodes: list[dict[str, Any]]) -> None:
        """B opcode status should be 'unimplemented', not 'implemented'."""
        b_entry = next(e for e in opcodes if e["char"] == "B")
        assert b_entry["status"] == "unimplemented", (
            f"Opcode 'B' status is {b_entry['status']!r}; expected 'unimplemented'. "
            "B is documented (RULE_OP_MANGLE_CHR_ADD) but not yet simulated in explain_rule()."
        )
