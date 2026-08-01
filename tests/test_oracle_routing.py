import sys
from pathlib import Path

import pytest
from hashcat_rosetta._verify import _CPU_ONLY_OPCODES, _hashcat_output, _select_engine, verify_rule

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

pytestmark = pytest.mark.integration


def test_cpu_engine_runs_filter_rule_that_gpu_rejects():
    """-j accepts '>4', which -r refuses to compile at all."""
    gpu_out, gpu_failed = _hashcat_output(">4", "abcdefgh", engine="gpu")
    cpu_out, cpu_failed = _hashcat_output(">4", "abcdefgh", engine="cpu")
    assert gpu_out is None or gpu_out == "", "GPU cannot compile filter rules"
    assert cpu_failed is False
    assert cpu_out == "abcdefgh", "len 8 >= 4 passes, word emitted unmodified"


def test_cpu_engine_reports_rejection_as_empty_string():
    cpu_out, cpu_failed = _hashcat_output(">4", "ab", engine="cpu")
    assert cpu_failed is False
    assert cpu_out == "", "len 2 < 4 is rejected by hashcat"


def test_invalid_rule_is_a_failure_not_a_clean_rejection():
    """Exit 255 is 'No valid rules left', a compile error, not a rejection."""
    out, failed = _hashcat_output(">4", "abcdefgh", engine="gpu")
    assert failed is True, "an uncompilable rule must not read as empty output"


def test_cpu_only_set_is_exactly_the_thirteen():
    assert _CPU_ONLY_OPCODES == set("MX!<>%()=46Qa")


def test_select_engine_routes_by_opcode():
    assert _select_engine("$1") == "gpu"
    assert _select_engine(">4") == "cpu"
    assert _select_engine("M4") == "cpu"
    # A rule mixing a filter with a transform still needs the CPU engine,
    # because -r refuses the whole rule: '>4 $1' fails exactly like '>4'.
    assert _select_engine(">4 $1") == "cpu"


def test_filter_opcodes_are_now_compared_not_skipped():
    r = verify_rule(">4", "abcdefgh")
    assert r.status != "skipped_hashcat_unsupported"
    assert r.status == "match", (
        "our simulator should agree with hashcat that len(word)=8 >= N=4 "
        "means '>4' keeps 'abcdefgh' unchanged"
    )


def test_3nx_still_uses_the_gpu_oracle():
    """CPU and GPU disagree on 3NX; rule-file semantics are GPU.

    verify_rule only populates `.hashcat` on a mismatch (see VerifyResult),
    so a match against the correct GPU oracle leaves it None. Assert on
    `.status` for the routing behavior, and confirm the GPU oracle's actual
    output directly via `_hashcat_output` to pin down the expected value.
    """
    assert _select_engine("30s") == "gpu"
    r = verify_rule("30s", "Password1")
    assert r.status == "match"
    gpu_out, gpu_failed = _hashcat_output("30s", "Password1", engine="gpu")
    assert gpu_failed is False
    assert gpu_out == "PasSword1"


def test_every_known_opcode_is_either_oracled_or_explicitly_excused():
    from sweep_opcodes import KNOWN_LATENT, unoracled_opcodes

    gaps = unoracled_opcodes()
    unexcused = {op: why for op, why in gaps.items() if op not in KNOWN_LATENT}
    assert unexcused == {}, f"opcodes with no oracle and no excuse: {unexcused}"


def test_the_previously_unoracled_thirteen_are_now_covered():
    from sweep_opcodes import unoracled_opcodes

    gaps = unoracled_opcodes()
    for op in "MX!<>%()=46Qa":
        assert op not in gaps, f"{op} should now be oracled via the CPU engine"


def test_only_the_oracle_environment_exemptions_remain():
    """B and v are excused because CI's POCL backend emits nothing for them,
    not because we are unsure what they do. Nothing else may be excused.
    'a' is NOT here: it is oracled via -j and its expected value is
    'unchanged'.
    """
    from sweep_opcodes import KNOWN_LATENT

    assert set(KNOWN_LATENT) == {"B", "v"}
