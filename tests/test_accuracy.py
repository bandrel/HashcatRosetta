"""Accuracy smoke test: drives the verify harness over a small rule sample
crossed with the full baseword corpus. Marked integration; skipped without
hashcat. Failures point at the (rule, baseword) pair that disagreed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hashcat_rosetta._verify import (
    _DEFAULT_IMPLEMENTED,
    load_baseword_corpus,
    verify_rule,
)

GENERATE_RULES_BIN = Path.home() / "hashcat-utils" / "src" / "generate-rules.bin"
CORPUS_PATH = Path(__file__).resolve().parent / "data" / "basewords.json"
SMOKE_SEED = 42
SMOKE_COUNT = 10  # 10 rules x 24 basewords = 240 cases per pytest run


def _have_hashcat() -> bool:
    try:
        subprocess.run(["hashcat", "--version"], capture_output=True, timeout=5).check_returncode()
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="module")
def smoke_rules() -> list[str]:
    if not GENERATE_RULES_BIN.exists():
        pytest.skip(f"generate-rules.bin not found at {GENERATE_RULES_BIN}")
    result = subprocess.run(
        [str(GENERATE_RULES_BIN), str(SMOKE_COUNT), str(SMOKE_SEED)],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    return [line for line in result.stdout.decode().splitlines() if line.strip()]


@pytest.fixture(scope="module")
def corpus() -> list[str]:
    return load_baseword_corpus(CORPUS_PATH)


@pytest.mark.integration
def test_accuracy_smoke(smoke_rules: list[str], corpus: list[str]) -> None:
    if not _have_hashcat():
        pytest.skip("hashcat binary not available")

    failures: list[str] = []
    for rule in smoke_rules:
        for baseword in corpus:
            result = verify_rule(rule, baseword, _DEFAULT_IMPLEMENTED)
            if result.status == "mismatch":
                failures.append(
                    f"  rule={rule!r} baseword={baseword!r} "
                    f"ours={result.ours!r} hashcat={result.hashcat!r}"
                )
    if failures:
        pytest.fail(
            f"{len(failures)} accuracy mismatch(es) in smoke test:\n" + "\n".join(failures[:30])
        )
