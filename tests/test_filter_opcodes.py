import pytest
from hashcat_rosetta.cli import explain_rule


def _final(rule, word):
    """Return the final candidate, or None if the rule rejected the word."""
    steps = explain_rule(rule, word)
    return None if not steps else steps[-1].rsplit(" → ", 1)[-1]


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
