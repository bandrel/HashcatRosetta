import pytest
from hashcat_rosetta.cli import REJECT_SENTINEL_PREFIX, explain_rule
from hashcat_rosetta.parser import RuleParser


def _final(rule, word):
    """Return the final candidate, or None if the rule rejected the word."""
    steps = explain_rule(rule, word)
    if not steps or steps[-1].startswith(REJECT_SENTINEL_PREFIX):
        return None
    return steps[-1].rsplit(" → ", 1)[-1]


class TestLengthFilters:
    """hashcat: >N rejects shorter than N; <N rejects longer than N.
    Both are inclusive at N. Verified against v7.1.2.
    """

    @pytest.mark.parametrize(
        "rule,word,kept",
        [
            (">4", "ab", False),  # len 2 < 4 -> reject
            (">4", "abcd", True),  # len 4 -> keep
            (">4", "abcdefgh", True),  # len 8 -> keep
            ("<4", "ab", True),  # len 2 -> keep
            ("<4", "abcd", True),  # len 4 -> keep
            ("<4", "abcdefgh", False),  # len 8 > 4 -> reject
        ],
    )
    def test_length_filter_matches_hashcat(self, rule, word, kept):
        result = _final(rule, word)
        if kept:
            assert result == word
        else:
            assert result is None


class TestContainsCountFilter:
    """hashcat's % is %NX: reject unless word contains char X at least N times.
    Ground truth on 'password' (two s's): %1s keep, %2s keep, %3s reject.
    """

    @pytest.mark.parametrize(
        "rule,word,kept",
        [
            ("%1s", "password", True),
            ("%2s", "password", True),
            ("%3s", "password", False),
            ("%1z", "password", False),
        ],
    )
    def test_percent_matches_hashcat(self, rule, word, kept):
        result = _final(rule, word)
        assert (result == word) if kept else (result is None)

    def test_percent_consumes_two_argument_bytes(self):
        """Wrong arity shifts every later opcode by one byte, which corrupts
        --analyze-rules statistics for any file containing a %."""
        tokens = RuleParser()._tokenize_rule("%2s$1")
        assert len(tokens) == 2, f"expected ['%2s', '$1'], got {tokens}"
