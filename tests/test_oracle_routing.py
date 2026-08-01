import pytest
from hashcat_rosetta._verify import _hashcat_output

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
