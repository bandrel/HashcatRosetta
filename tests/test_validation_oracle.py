"""Validation oracle: verify explain_rule() against hashcat for accuracy gating."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

GENERATE_RULES_BIN = Path.home() / "hashcat-utils" / "src" / "generate-rules.bin"
REGRESSION_RULES = Path(__file__).parent / "fixtures" / "rules" / "regression.rule"


def _hashcat_available() -> bool:
    try:
        subprocess.run(["hashcat", "--version"], capture_output=True, timeout=5).check_returncode()
        return True
    except Exception:
        return False


def _generate_rules_available() -> bool:
    return GENERATE_RULES_BIN.exists()


class TestRegressionRules:
    """Run every regression rule against hashcat and our simulator."""

    @pytest.mark.integration
    def test_regression_corpus_against_hashcat(self) -> None:
        """Every rule in regression.rule must produce the same result as hashcat."""
        if not _hashcat_available():
            pytest.skip("hashcat not available")

        from hashcat_rosetta._verify import _hashcat_output, _select_engine
        from hashcat_rosetta.cli import REJECT_SENTINEL_PREFIX, explain_rule

        def get_hashcat_output(rule: str, baseword: str) -> str | None:
            # "" is a real rejection answer from the CPU engine (-j), same as
            # None -- normalize both to None so callers only need one check.
            output, failed = _hashcat_output(rule, baseword, engine=_select_engine(rule))
            return None if failed or not output else output

        rules = [
            r.strip()
            for r in REGRESSION_RULES.read_text().splitlines()
            if r.strip() and not r.strip().startswith("#")
        ]
        baseword = "password"
        mismatches = []

        for rule in rules:
            explanation = explain_rule(rule, baseword)
            if explanation is None or not explanation:
                continue
            last_step = explanation[-1]
            is_rejected = last_step.startswith(REJECT_SENTINEL_PREFIX)
            hashcat_result = get_hashcat_output(rule, baseword)

            if is_rejected:
                if hashcat_result is not None:
                    mismatches.append(
                        f"Rule {rule!r}: we rejected but hashcat produced {hashcat_result!r}"
                    )
            else:
                our_result = last_step.split("\u2192")[-1].strip()
                if hashcat_result is None:
                    # hashcat rejected, we didn't — potential mismatch but skip for now
                    pass
                elif not hashcat_result.isascii():
                    # hashcat stdout is decoded utf-8-with-replace, which cannot
                    # losslessly round-trip a raw high byte; a non-ASCII byte here
                    # is a comparison-fidelity artifact, not a simulation mismatch
                    # (see hashcat_rosetta._verify.verify_rule for the same skip).
                    pass
                elif our_result != hashcat_result:
                    mismatches.append(
                        f"Rule {rule!r}: ours={our_result!r}, hashcat={hashcat_result!r}"
                    )

        assert not mismatches, f"{len(mismatches)} regression rules differ:\n" + "\n".join(
            mismatches[:20]
        )


@pytest.mark.validation
class TestOraclePassRate:
    """Gating test: explain_rule() must achieve >=95% pass rate across corpus and basewords."""

    def test_oracle_pass_rate(self) -> None:
        """Run 200 generated rules over 3 seeds and all basewords, assert >=95% pass rate."""
        if not _hashcat_available():
            pytest.skip("hashcat not available")
        if not _generate_rules_available():
            pytest.skip("generate-rules.bin not available")

        from hashcat_rosetta._verify import load_baseword_corpus, verify_corpus

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from verify_rules import DEFAULT_CORPUS, generate_rules  # noqa: PLC0415

        COUNT = 200
        SEEDS = [42, 43, 44]
        WORKERS = os.cpu_count() or 4
        basewords = load_baseword_corpus(DEFAULT_CORPUS)

        total_tested = 0
        total_matched = 0

        for seed in SEEDS:
            rules = generate_rules(COUNT, seed)
            report = verify_corpus(rules, basewords, WORKERS)
            total_tested += report.total_tested
            total_matched += report.total_matched

        if total_tested == 0:
            pytest.skip("No rules were testable against hashcat")

        pass_rate = total_matched / total_tested
        assert pass_rate >= 0.95, (
            f"Pass rate {pass_rate:.1%} ({total_matched}/{total_tested}) is below 95% threshold"
        )
