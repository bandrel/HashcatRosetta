"""Tests for rule-syntax validation (``find_rule_issues``) and its CLI wiring.

Ground truth for every assertion here is the hashcat rule engine itself
(``src/rp_cpu.c::_old_apply_rule``, confirmed with ``hashcat --stdout``):

- an unknown opcode invalidates the whole rule
- numeric ("position") args go through ``conv_ctoi``: only ``0-9`` and ``A-Z``
  are legal (plus ``p``, the saved-position sentinel)
- character args accept any byte
- reject-class opcodes cannot be validated through ``--stdout`` at all, so the
  validator stays silent on them

A false "invalid rule" verdict is worse than the bug this guards against, so
the false-positive tests below are the important ones.
"""

from __future__ import annotations

import importlib.util
import logging
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from hashcat_rosetta import _opcodes
from hashcat_rosetta.cli import explain_rule, main
from hashcat_rosetta.parser import DebugLogParser, find_rule_issues

_REPO_ROOT = Path(__file__).resolve().parent.parent


class TestReproducers:
    """The two rules from the bug report; hashcat rejects both outright."""

    def test_unknown_opcode_is_reported(self):
        issues = find_rule_issues("$1 R32")
        assert issues, "'$1 R32' has a stray '2' opcode; hashcat rejects the rule"

    def test_bad_numeric_arg_is_reported(self):
        issues = find_rule_issues("$1 Zq")
        assert issues, "'Zq' has a non-[0-9A-Z] position arg; hashcat rejects the rule"


class TestValidRulesAreNotFlagged:
    @pytest.mark.parametrize(
        "rule",
        [
            ":",
            "$1 R3",
            "$1 Z2",
            "c sa@ ss$ $2 $0 $2 $5 i8- +0 ]",
            "DA",
            "TA",
            "$z",
            "$!",
            "^z",
            "@z",
            "e-",
            "sa@",
            "s\\x20_",
            "$\\x41",
            "X012",
            "M",
            "i8-",
            "o0A",
            "*01",
            "xA5",
            "O19",
            "v1a",
            "B0a",
            "30s",
            "u",
            "} } } } t",
            "$: ",
            "$ ",
            "T0",
            "Dp",
            "z9",
            "'A",
            "h",
            "H",
            "S",
        ],
    )
    def test_no_issues(self, rule):
        assert find_rule_issues(rule) == []

    def test_empty_rule(self):
        assert find_rule_issues("") == []


class TestNumericArgMatrix:
    """Oracle-verified: numeric args accept only 0-9 and A-Z."""

    @pytest.mark.parametrize("rule", ["Dz", "D!", "Ta", "Zq", "'z", "y!", "iaX", "*a0", "X0z1"])
    def test_bad_numeric_arg_flagged(self, rule):
        assert find_rule_issues(rule), f"{rule!r} has an illegal position arg"

    @pytest.mark.parametrize("rule", ["D1", "DA", "TA", "Z2", "y1", "i0a", "*10", "X019"])
    def test_good_numeric_arg_clean(self, rule):
        assert find_rule_issues(rule) == []


class TestRejectClassIsNeverFlagged:
    """hashcat's --stdout discards reject rules, so the oracle cannot judge
    their args. The validator must stay silent rather than risk a false
    'invalid' verdict."""

    @pytest.mark.parametrize(
        "rule",
        [">5", "<z", "_5", "!a", "/a", "(p", ")d", "=0p", "%1a", "%ab", "Q", "~s?da", ">z", "<5"],
    )
    def test_not_flagged(self, rule):
        assert find_rule_issues(rule) == []


class TestTruncatedOpcodes:
    @pytest.mark.parametrize("rule", ["$", "^", "Z", "i1", "X01", "s", "sa", "3"])
    def test_missing_args_flagged(self, rule):
        assert find_rule_issues(rule), f"{rule!r} is truncated; hashcat rejects it"


def _fixture_rules() -> list[str]:
    parser = DebugLogParser()
    rules: list[str] = []
    log_paths = sorted((_REPO_ROOT / "tests" / "fixtures" / "debug_logs").glob("*.log"))
    log_paths += sorted((_REPO_ROOT / "examples").glob("sample_debug*.txt"))
    assert log_paths, "no fixture debug logs found"
    for path in log_paths:
        for entry in parser.parse_debug_file(str(path)):
            rule = entry.get("rule")
            if rule:
                rules.append(rule)
    assert rules, "no rules extracted from fixtures"
    return rules


# Fixture "rules" that hashcat itself rejects, so flagging them is correct, not
# a false positive. Each was checked with
#   printf '<rule>\n' > r; hashcat --stdout -r r wordlist
# on v7.1.2, which answers "No valid rules left." for all four while accepting
# their truncated prefixes (`sss`, `$$`):
#   sss3ss  -> `3ss`: 's' is not a legal position arg
#   seiim   -> trailing `im`: `i` is missing its second argument
#   sso@    -> trailing `@`: missing its argument
#   $$1     -> trailing `1` is not an opcode
_FIXTURE_RULES_HASHCAT_REJECTS = frozenset({"sss3ss", "seiim", "sso@", "$$1"})


class TestNoFalsePositivesOnFixtures:
    """The most important test in the change: every rule in the repo's
    verified fixtures must come back clean, apart from the handful hashcat
    rejects too."""

    def test_fixture_rules_are_clean(self):
        offenders = {
            rule: issues
            for rule in _fixture_rules()
            if rule not in _FIXTURE_RULES_HASHCAT_REJECTS and (issues := find_rule_issues(rule))
        }
        assert offenders == {}

    @pytest.mark.parametrize("rule", sorted(_FIXTURE_RULES_HASHCAT_REJECTS))
    def test_known_bad_fixture_rules_are_flagged(self, rule):
        assert find_rule_issues(rule)


class TestArityTablesDoNotDrift:
    """``OPCODE_ARG_KINDS`` must agree with the arity sets it is derived from."""

    def test_arg_kind_lengths_match_arity(self):
        for op, kinds in _opcodes.OPCODE_ARG_KINDS.items():
            if op in _opcodes.THREE_ARG_OPCODES:
                assert len(kinds) == 3, op
            elif op in _opcodes.TWO_ARG_OPCODES:
                assert len(kinds) == 2, op
            elif op in _opcodes.ONE_ARG_OPCODES:
                assert len(kinds) == 1, op
            else:
                raise AssertionError(f"{op!r} has arg kinds but no known arity")

    def test_every_arg_taking_opcode_is_classified(self):
        arg_taking = (
            _opcodes.ONE_ARG_OPCODES | _opcodes.TWO_ARG_OPCODES | _opcodes.THREE_ARG_OPCODES
        )
        unclassified = arg_taking - set(_opcodes.OPCODE_ARG_KINDS) - _opcodes.UNVALIDATABLE_OPCODES
        assert unclassified == set()

    def test_arg_kinds_only_use_n_and_x(self):
        for kinds in _opcodes.OPCODE_ARG_KINDS.values():
            assert set(kinds) <= {"N", "X"}

    def test_verify_module_shares_the_same_tables(self):
        from hashcat_rosetta import _verify

        assert _verify._THREE_ARG_OPCODES == _opcodes.THREE_ARG_OPCODES
        assert _verify._TWO_ARG_OPCODES == _opcodes.TWO_ARG_OPCODES
        assert _verify._ONE_ARG_OPCODES == _opcodes.ONE_ARG_OPCODES
        assert _verify._ZERO_ARG_OPCODES == _opcodes.ZERO_ARG_OPCODES
        assert _verify._ALL_KNOWN_OPCODES == _opcodes.ALL_KNOWN_OPCODES


class TestExplainRuleArgumentSkipping:
    """A failed argument parse must never leave the argument to be re-read as
    an opcode (the '$1 Zq' -> bogus 'q: Duplicate every char' bug)."""

    def test_bad_numeric_arg_does_not_leak_a_step(self):
        steps = explain_rule("$1 Zq", "password")
        assert steps is not None
        assert not any("Duplicate every char" in step for step in steps)
        assert not any(step.startswith("q") for step in steps)

    @pytest.mark.parametrize(
        "rule,leaked",
        [
            ("Dq", "q"),
            ("Tq", "q"),
            ("pq", "q"),
            ("yq", "q"),
            ("Yq", "q"),
            ("zq", "q"),
            ("'q", "q"),
            ("+q", "q"),
            ("-q", "q"),
            (".q", "q"),
            (",q", "q"),
            ("Rq", "q"),
            ("Lq", "q"),
            ("iqa", "q"),
            ("oqa", "q"),
            ("xqa", "q"),
            ("*qa", "q"),
            ("Oqa", "q"),
            ("Bqa", "q"),
            ("3qa", "q"),
            ("vqa", "q"),
            (">q", "q"),
            ("<q", "q"),
            ("=qa", "q"),
            ("Xq12", "q"),
        ],
    )
    def test_no_argument_is_reparsed_as_an_opcode(self, rule, leaked):
        steps = explain_rule(rule, "password") or []
        assert not any(step.startswith(leaked) for step in steps), steps

    @pytest.mark.parametrize(
        "rule,expected",
        [
            ("$1 R3", "pas9word1"),
            ("$1 Z2", "password111"),
            ("c", "Password"),
            ("i8-", "password-"),
        ],
    )
    def test_valid_rules_still_explained(self, rule, expected):
        steps = explain_rule(rule, "password")
        assert steps is not None
        assert expected in steps[-1]


class TestParserUnknownOpcodeWarning:
    def test_unknown_opcode_logs_warning(self, caplog):
        from hashcat_rosetta.parser import RuleParser

        with caplog.at_level(logging.WARNING, logger="hashcat_rosetta.parser"):
            RuleParser().parse_rule("$1 R32")
        assert any("Unknown opcode" in record.message for record in caplog.records), caplog.text


class TestCliRejectsInvalidRules:
    def test_single_rule_invalid_exits_nonzero(self):
        result = CliRunner().invoke(main, ["--explain", "$1 R32"])
        assert result.exit_code != 0
        assert "invalid" in result.output.lower()

    def test_single_rule_invalid_does_not_fabricate_steps(self):
        result = CliRunner().invoke(main, ["--explain", "$1 Zq"])
        assert result.exit_code != 0
        assert "Duplicate every char" not in result.output

    def test_single_valid_rule_still_explained(self):
        result = CliRunner().invoke(main, ["--explain", "$1 R3", "--baseword", "password"])
        assert result.exit_code == 0
        assert "pas9word1" in result.output

    def test_rule_file_reports_bad_line_and_continues(self, tmp_path):
        rule_file = tmp_path / "rules.rule"
        rule_file.write_text("$1 R32\n$1 R3\n$1 Zq\n$1 Z2\n")
        result = CliRunner().invoke(main, ["--explain", str(rule_file), "--baseword", "password"])
        assert result.exit_code == 0
        assert "pas9word1" in result.output
        assert "password111" in result.output
        assert "Duplicate every char" not in result.output
        assert result.output.lower().count("invalid") >= 2


def _load_sweep_rules() -> list[str]:
    spec = importlib.util.spec_from_file_location(
        "sweep_opcodes", _REPO_ROOT / "scripts" / "sweep_opcodes.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rules: list[str] = module.generate_rules()
    assert rules
    return rules


class TestAgainstHashcatOracle:
    """Cross-check the validator against the binary: anything we call invalid
    must be something hashcat refuses to compile."""

    @pytest.mark.integration
    def test_flagged_rules_are_rejected_by_hashcat(self, tmp_path):
        if shutil.which("hashcat") is None:
            pytest.skip("hashcat binary not available")

        candidates = _load_sweep_rules() + _fixture_rules()
        flagged = sorted({rule for rule in candidates if find_rule_issues(rule)})
        assert flagged, "expected the sweep grid to contain some invalid rules"

        rule_file = tmp_path / "flagged.rule"
        rule_file.write_text("\n".join(flagged) + "\n")
        word_file = tmp_path / "words.txt"
        word_file.write_text("password\n")

        proc = subprocess.run(
            ["hashcat", "--stdout", "-r", str(rule_file), str(word_file)],
            capture_output=True,
            timeout=120,
        )
        # Every rule in the file is one we flagged; if hashcat compiled any of
        # them it would emit a candidate line. It must emit none.
        assert proc.stdout.strip() == b"", (
            f"hashcat accepted at least one rule we flagged as invalid: "
            f"{proc.stdout[:400]!r} (rules: {flagged[:20]})"
        )
