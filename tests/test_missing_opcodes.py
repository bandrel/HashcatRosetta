from hashcat_rosetta.cli import explain_rule


def _final(rule, word):
    steps = explain_rule(rule, word)
    return None if not steps else steps[-1].rsplit(" → ", 1)[-1]


class TestHexEncoding:
    """Verified against hashcat v7.1.2."""

    def test_h_is_lowercase_hex(self):
        assert _final("h", "password") == "70617373776f7264"

    def test_H_is_uppercase_hex(self):
        assert _final("H", "password") == "70617373776F7264"

    def test_h_operates_on_the_current_word_not_the_baseword(self):
        # hashcat: `uh` on password -> 50415353574f5244
        assert _final("uh", "password") == "50415353574f5244"

    def test_hex_respects_the_256_byte_cap(self):
        """hashcat no-ops a growing op when the result would reach 256."""
        long_word = "a" * 200
        assert _final("h", long_word) == long_word
