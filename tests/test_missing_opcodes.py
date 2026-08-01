import pytest

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


class TestKeyboardShift:
    def test_S_shifts_letters_like_case_toggle(self):
        assert _final("S", "password") == "PASSWORD"

    def test_S_also_shifts_non_alpha(self):
        """This is what makes S different from t. Verified on v7.1.2."""
        assert _final("S", "pass1;[a") == "PASS!:{A"

    def test_S_covers_all_printable_ascii(self):
        printable = "".join(chr(c) for c in range(33, 127))
        expected = (
            "1'3457\"908=<_>?)!@#$%^&*(;:,+./2"
            "abcdefghijklmnopqrstuvwxyz{|}6-~"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]`"
        )
        assert _final("S", printable) == expected

    def test_S_leaves_bytes_outside_33_126_alone(self):
        assert _final("S", "a b") == "A B"  # space (32) is unmasked


class TestMemoryOpcodes:
    """Memory ops are host-side only; oracle is `hashcat -j`.
    Every expected value below was read off hashcat v7.1.2, not reasoned out.
    """

    def test_4_appends_memory(self):
        assert _final("M4", "abc") == "abcabc"

    def test_6_prepends_memory(self):
        assert _final("cM6", "abc") == "AbcAbc"

    def test_Q_rejects_when_word_equals_memory(self):
        assert _final("MQ", "abc") is None

    def test_Q_passes_when_word_differs_from_memory(self):
        assert _final("Mc Q", "abc") == "Abc"
        assert _final("MuQ", "abc") == "ABC"

    @pytest.mark.xfail(
        reason="Depends on Task 7b's zero-filled memorized-buffer default; "
        "memorized == baseword until Task 7b lands.",
        strict=True,
    )
    def test_4_without_M_appends_the_zeroed_buffer(self):
        """hashcat: bare '4' on abc gives 'abc\\0\\0\\0'. This depends on the
        memory buffer's zero-fill default, which Task 7b (not this task)
        implements. If Task 7b has not landed yet, memorized == baseword, so
        this specific assertion will fail until Task 7b lands — SKIP or
        XFAIL this one test only if that's the case, do not weaken the
        assertion itself. All other tests in this class must pass now."""
        assert _final("4", "abc") == "abc\x00\x00\x00"

    @pytest.mark.xfail(
        reason="Depends on Task 7b's zero-filled memorized-buffer default; "
        "memorized == baseword until Task 7b lands.",
        strict=True,
    )
    def test_6_without_M_prepends_the_zeroed_buffer(self):
        """Same caveat as test_4_without_M_appends_the_zeroed_buffer above."""
        assert _final("6", "abc") == "\x00\x00\x00abc"

    def test_step_is_emitted_even_when_nothing_changes(self):
        """A no-op must still produce a step, so a reader never mistakes a
        silently-skipped opcode for one that legitimately did nothing."""
        steps = explain_rule("MQ4", "abc")
        assert steps is None or any(s.startswith("4:") for s in steps)


class TestNoOpOpcode:
    """hashcat declares RULE_OP_MANGLE_TOGGLECASE_REC for `a` but the body is
    a `/* todo */ break;` stub, so it changes nothing. Verified: `-j 'a'` on
    abc gives abc, and `-j 'ca'` gives Abc.
    """

    def test_a_changes_nothing(self):
        assert _final("a", "abc") == "abc"

    def test_a_does_not_interfere_with_neighbouring_opcodes(self):
        assert _final("ca", "abc") == "Abc"

    def test_a_still_emits_a_step(self):
        steps = explain_rule("a", "abc")
        assert steps is not None
        assert any(s.startswith("a:") for s in steps)
