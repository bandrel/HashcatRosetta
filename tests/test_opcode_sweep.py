"""Unit tests for scripts/sweep_opcodes.py — pure-logic pieces only.

The sweep script lives in scripts/ (not in the package), so we import it via
importlib to keep it test-discoverable without polluting the public API.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest  # noqa: F401

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "sweep_opcodes.py"
_spec = importlib.util.spec_from_file_location("sweep_opcodes", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
sweep_opcodes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep_opcodes)


class TestArgGridConstants:
    def test_position_args_are_hashcat_position_chars(self):
        # Hashcat encodes positions 0-9 as '0'-'9' and 10-35 as 'A'-'Z'.
        for arg in sweep_opcodes.POSITION_ARGS:
            assert len(arg) == 1
            assert arg in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def test_char_args_are_single_chars(self):
        for arg in sweep_opcodes.CHAR_ARGS:
            assert len(arg) == 1

    def test_two_arg_grid_is_3x3_pairs(self):
        assert len(sweep_opcodes.TWO_ARG_GRID) == 9
        for pair in sweep_opcodes.TWO_ARG_GRID:
            assert len(pair) == 2
            assert all(len(c) == 1 for c in pair)

    def test_three_arg_grid_is_triples(self):
        assert len(sweep_opcodes.THREE_ARG_GRID) > 0
        for triple in sweep_opcodes.THREE_ARG_GRID:
            assert len(triple) == 3

    def test_known_latent_is_dict_str_str(self):
        assert isinstance(sweep_opcodes.KNOWN_LATENT, dict)
        for k, v in sweep_opcodes.KNOWN_LATENT.items():
            assert isinstance(k, str) and len(k) == 1
            assert isinstance(v, str) and len(v) > 0


class TestGenerateRules:
    def test_returns_nonempty_deterministic_list(self):
        a = sweep_opcodes.generate_rules()
        b = sweep_opcodes.generate_rules()
        assert a == b  # deterministic
        assert len(a) > 0

    def test_all_rules_are_unique(self):
        rules = sweep_opcodes.generate_rules()
        assert len(rules) == len(set(rules))

    def test_zero_arg_rule_per_zero_arg_opcode(self):
        # Every 0-arg opcode in _DEFAULT_IMPLEMENTED must appear as a 1-char rule.
        from hashcat_rosetta._verify import _DEFAULT_IMPLEMENTED, _ZERO_ARG_OPCODES

        rules = sweep_opcodes.generate_rules()
        zero_arg_impl = _DEFAULT_IMPLEMENTED & _ZERO_ARG_OPCODES
        for op in zero_arg_impl:
            assert op in rules, f"missing 0-arg rule for opcode {op!r}"

    def test_one_arg_position_rules(self):
        # Each 1-arg position opcode in _DEFAULT_IMPLEMENTED appears with every
        # POSITION_ARGS value as a 2-char rule.
        from hashcat_rosetta._verify import _DEFAULT_IMPLEMENTED

        rules = set(sweep_opcodes.generate_rules())
        for op in sweep_opcodes.ONE_ARG_POSITION_OPCODES & _DEFAULT_IMPLEMENTED:
            for arg in sweep_opcodes.POSITION_ARGS:
                assert (op + arg) in rules, f"missing {op + arg!r}"

    def test_one_arg_char_rules(self):
        from hashcat_rosetta._verify import _DEFAULT_IMPLEMENTED

        rules = set(sweep_opcodes.generate_rules())
        for op in sweep_opcodes.ONE_ARG_CHAR_OPCODES & _DEFAULT_IMPLEMENTED:
            for arg in sweep_opcodes.CHAR_ARGS:
                assert (op + arg) in rules, f"missing {op + arg!r}"

    def test_two_arg_rules(self):
        rules = set(sweep_opcodes.generate_rules())
        from hashcat_rosetta._verify import _DEFAULT_IMPLEMENTED, _TWO_ARG_OPCODES

        for op in _DEFAULT_IMPLEMENTED & _TWO_ARG_OPCODES:
            for args in sweep_opcodes.TWO_ARG_GRID:
                assert (op + args) in rules, f"missing {op + args!r}"

    def test_three_arg_rules(self):
        rules = set(sweep_opcodes.generate_rules())
        from hashcat_rosetta._verify import _DEFAULT_IMPLEMENTED, _THREE_ARG_OPCODES

        for op in _DEFAULT_IMPLEMENTED & _THREE_ARG_OPCODES:
            for args in sweep_opcodes.THREE_ARG_GRID:
                assert (op + args) in rules, f"missing {op + args!r}"

    def test_total_count_matches_spec(self):
        # Spec rule count: 18·1 + 14·5 + 10·5 + 9·9 + 9 = 228
        # (THREE_ARG_GRID has 9 entries, not the spec's '~10').
        rules = sweep_opcodes.generate_rules()
        n_zero = len(sweep_opcodes.ZERO_ARG_OPCODES_IMPL)
        n_pos = len(sweep_opcodes.ONE_ARG_POSITION_OPCODES) * len(sweep_opcodes.POSITION_ARGS)
        n_char = len(sweep_opcodes.ONE_ARG_CHAR_OPCODES) * len(sweep_opcodes.CHAR_ARGS)
        n_two = len(sweep_opcodes.TWO_ARG_OPCODES_IMPL) * len(sweep_opcodes.TWO_ARG_GRID)
        n_three = len(sweep_opcodes.THREE_ARG_OPCODES_IMPL) * len(sweep_opcodes.THREE_ARG_GRID)
        assert len(rules) == n_zero + n_pos + n_char + n_two + n_three


class TestAggregateByOpcode:
    def _synth_round(
        self,
        baseword,
        *,
        tested=0,
        matched=0,
        mismatches=None,
        hc_unsupported=0,
        hc_unsupported_rules=None,
        hashcat_skipped_rules=None,
        nonascii_skipped_rules=None,
    ):
        return {
            "baseword": baseword,
            "total_rules": tested + (len(mismatches) if mismatches else 0) + hc_unsupported,
            "skipped_unimplemented": 0,
            "skipped_invalid": 0,
            "skipped_hashcat": len(hashcat_skipped_rules or []),
            "skipped_hashcat_unsupported": hc_unsupported,
            "skipped_nonascii": len(nonascii_skipped_rules or []),
            "tested": tested,
            "matched": matched,
            "mismatches": mismatches or [],
            "skipped_rules": [],
            "skipped_rule_strings": {
                "skipped_hashcat": hashcat_skipped_rules or [],
                "skipped_hashcat_unsupported": hc_unsupported_rules or [],
                "skipped_nonascii": nonascii_skipped_rules or [],
            },
        }

    def test_groups_by_leading_char_of_rule(self):
        # Synthetic: 2 rounds, 3 distinct opcodes ('c', 'v', '$').
        from hashcat_rosetta._verify import CorpusReport

        report = CorpusReport()
        report.rounds = [
            self._synth_round("password", tested=3, matched=3),
            self._synth_round(
                "admin",
                tested=2,
                matched=1,
                mismatches=[
                    {
                        "rule": "v23",
                        "baseword": "admin",
                        "index": 0,
                        "ours": "AdMiN",
                        "hashcat": "aDmIn",
                        "components": [{"opcode": "v"}],
                    },
                ],
            ),
        ]
        rules = ["c", "v23", "$a"]
        stats = sweep_opcodes.aggregate_by_opcode(report, rules)
        assert set(stats.keys()) >= {"c", "v", "$"}
        assert stats["v"]["mismatches"] == 1
        assert stats["v"]["first_failing_example"] is not None
        assert stats["v"]["first_failing_example"]["rule"] == "v23"

    def test_opcode_identity_no_longer_forces_unverifiable(self):
        # Previously M/X were hardcoded into an "always unverifiable" bucket
        # by opcode identity alone, regardless of what the round actually
        # reported. Task 2 routes them through the CPU oracle instead, so a
        # rule with no matching skip record is counted as tested/matched like
        # any other opcode, and the unverifiable counter stays 0.
        from hashcat_rosetta._verify import CorpusReport

        report = CorpusReport()
        report.rounds = [
            self._synth_round("password", tested=0, matched=0, hc_unsupported=0),
        ]
        rules = ["M"]
        stats = sweep_opcodes.aggregate_by_opcode(report, rules)
        assert stats["M"]["unverifiable"] == 0
        assert stats["M"]["tested"] == 1
        assert stats["M"]["matched"] == 1

    def test_skipped_rules_not_counted_as_matched(self):
        # Rules that the verify harness skipped (hashcat exec failure, OOB
        # position triggering hashcat_unsupported, or non-ASCII output) must
        # NOT inflate the matched count — otherwise an opcode-level bug that
        # only triggers a skip could masquerade as PASS.
        from hashcat_rosetta._verify import CorpusReport

        report = CorpusReport()
        report.rounds = [
            self._synth_round(
                "longword",
                tested=0,
                matched=0,
                hc_unsupported=1,
                hc_unsupported_rules=[">9"],
            ),
        ]
        rules = [">9"]
        stats = sweep_opcodes.aggregate_by_opcode(report, rules)
        assert stats[">"]["tested"] == 0
        assert stats[">"]["matched"] == 0
        assert stats[">"]["mismatches"] == 0

    def test_includes_zero_rows_for_untracked_opcodes(self):
        # Opcodes in _ALL_KNOWN_OPCODES but not _DEFAULT_IMPLEMENTED get a
        # zero-everything row so they show up as UNTRACKED in the matrix.
        from hashcat_rosetta._verify import (
            CorpusReport,
            _ALL_KNOWN_OPCODES,
            _DEFAULT_IMPLEMENTED,
        )

        report = CorpusReport()
        report.rounds = []
        stats = sweep_opcodes.aggregate_by_opcode(report, [])
        for op in _ALL_KNOWN_OPCODES - _DEFAULT_IMPLEMENTED:
            assert op in stats
            assert stats[op]["tested"] == 0
            assert stats[op]["mismatches"] == 0


class TestDeriveStatus:
    def _stat(self, op, **kwargs):
        base = {
            "opcode": op,
            "tested": 0,
            "matched": 0,
            "mismatches": 0,
            "unverifiable": 0,
            "first_failing_example": None,
        }
        base.update(kwargs)
        return base

    def test_pass_when_all_matched(self):
        stats = {"c": self._stat("c", tested=24, matched=24)}
        rows = sweep_opcodes.derive_status(stats, known_latent={})
        assert rows["c"]["status"] == "PASS"

    def test_regression_when_mismatch_and_not_in_known_latent(self):
        stats = {"v": self._stat("v", tested=216, matched=198, mismatches=18)}
        rows = sweep_opcodes.derive_status(stats, known_latent={})
        assert rows["v"]["status"] == "REGRESSION"

    def test_latent_when_mismatch_and_in_known_latent(self):
        stats = {"v": self._stat("v", tested=216, matched=198, mismatches=18)}
        rows = sweep_opcodes.derive_status(stats, known_latent={"v": "issue 42"})
        assert rows["v"]["status"] == "LATENT"

    def test_unverifiable_for_M_X_implemented(self):
        # M and X are in _DEFAULT_IMPLEMENTED but _HASHCAT_STDOUT_UNSUPPORTED.
        stats = {"M": self._stat("M", tested=0, matched=0, unverifiable=24)}
        rows = sweep_opcodes.derive_status(stats, known_latent={})
        assert rows["M"]["status"] == "UNVERIFIABLE"

    def test_untracked_when_known_opcode_not_implemented(self):
        # 'a' is in _ALL_KNOWN_OPCODES but not _DEFAULT_IMPLEMENTED.
        stats = {"a": self._stat("a")}  # all zeros
        rows = sweep_opcodes.derive_status(stats, known_latent={})
        assert rows["a"]["status"] == "UNTRACKED"

    def test_exit_code_zero_when_no_regression(self):
        rows = {
            "c": {**self._stat("c", tested=24, matched=24), "status": "PASS"},
            "v": {**self._stat("v", mismatches=1), "status": "LATENT"},
            "M": {**self._stat("M", unverifiable=24), "status": "UNVERIFIABLE"},
            "a": {**self._stat("a"), "status": "UNTRACKED"},
        }
        assert sweep_opcodes.compute_exit_code(rows) == 0

    def test_exit_code_one_on_regression(self):
        rows = {
            "v": {**self._stat("v", mismatches=1), "status": "REGRESSION"},
        }
        assert sweep_opcodes.compute_exit_code(rows) == 1


class TestRenderMarkdown:
    def test_has_header_row_and_data_rows(self):
        rows = {
            "c": {
                "opcode": "c",
                "tested": 24,
                "matched": 24,
                "mismatches": 0,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "PASS",
            },
            "v": {
                "opcode": "v",
                "tested": 216,
                "matched": 198,
                "mismatches": 18,
                "unverifiable": 0,
                "first_failing_example": {
                    "rule": "v23",
                    "baseword": "admin",
                    "ours": "AdMiN",
                    "hashcat": "aDmIn",
                },
                "status": "LATENT",
            },
        }
        md = sweep_opcodes.render_markdown(rows)
        # Header
        assert "| Opcode |" in md
        assert "| Status" in md
        # Data
        assert "| `c` |" in md
        assert "| `v` |" in md
        assert "PASS" in md
        assert "LATENT" in md
        # First failing example escaped for table cell
        assert "v23" in md

    def test_rows_are_sorted_by_status_then_opcode(self):
        # Regressions appear at the top so the punch list is unmissable.
        rows = {
            "c": {
                "opcode": "c",
                "tested": 1,
                "matched": 1,
                "mismatches": 0,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "PASS",
            },
            "v": {
                "opcode": "v",
                "tested": 1,
                "matched": 0,
                "mismatches": 1,
                "unverifiable": 0,
                "first_failing_example": {
                    "rule": "v0",
                    "baseword": "x",
                    "ours": "a",
                    "hashcat": "b",
                },
                "status": "REGRESSION",
            },
        }
        md = sweep_opcodes.render_markdown(rows)
        assert md.index("| `v` |") < md.index("| `c` |")

    def test_untracked_row_shows_zeros_and_note(self):
        rows = {
            "a": {
                "opcode": "a",
                "tested": 0,
                "matched": 0,
                "mismatches": 0,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "UNTRACKED",
            },
        }
        md = sweep_opcodes.render_markdown(rows)
        assert "| `a` |" in md
        assert "not in _DEFAULT_IMPLEMENTED" in md


class TestRenderJson:
    def test_includes_rows_and_metadata(self):
        rows = {
            "c": {
                "opcode": "c",
                "tested": 24,
                "matched": 24,
                "mismatches": 0,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "PASS",
            },
        }
        out = sweep_opcodes.render_json(rows, meta={"timestamp": "2026-05-22T10:00:00"})
        doc = json.loads(out)
        assert doc["meta"]["timestamp"] == "2026-05-22T10:00:00"
        assert "c" in doc["rows"]
        assert doc["rows"]["c"]["status"] == "PASS"
        assert "summary" in doc
        assert doc["summary"]["pass"] == 1

    def test_summary_counts_by_status(self):
        rows = {
            "a": {
                "opcode": "a",
                "tested": 0,
                "matched": 0,
                "mismatches": 0,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "PASS",
            },
            "b": {
                "opcode": "b",
                "tested": 0,
                "matched": 0,
                "mismatches": 1,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "REGRESSION",
            },
            "c": {
                "opcode": "c",
                "tested": 0,
                "matched": 0,
                "mismatches": 1,
                "unverifiable": 0,
                "first_failing_example": None,
                "status": "LATENT",
            },
        }
        doc = json.loads(sweep_opcodes.render_json(rows, meta={}))
        assert doc["summary"] == {
            "pass": 1,
            "regression": 1,
            "latent": 1,
            "unverifiable": 0,
            "untracked": 0,
        }
