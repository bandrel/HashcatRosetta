from hashcat_rosetta.cli import REJECT_SENTINEL_PREFIX, explain_rule


def _final(rule, word):
    steps = explain_rule(rule, word)
    if not steps or steps[-1].startswith(REJECT_SENTINEL_PREFIX):
        return None
    return steps[-1].rsplit(" → ", 1)[-1]


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

    def test_4_without_M_rejects_the_word(self):
        """A memory op with no preceding `M` rejects, it does not append a
        zero-filled buffer.

        Ground truth is hashcat's own source: ``src/rp_cpu.c:1168`` declares
        ``int mem_len = 0``, and ``RULE_OP_MANGLE_APPEND_MEMORY``
        (``rp_cpu.c:1474``) opens with
        ``if (mem_len < 1) return (RULE_RC_REJECT_ERROR)``. Confirmed against
        the binary (v7.1.2-484-g64e1bff93): ``hashcat --stdout -j '4'`` on
        ``abcdef`` emits zero bytes, not ``abcdef`` + six NULs.

        This replaces an assertion that expected the NUL-fill. ``mem`` is
        uninitialized stack memory, so reading it can look zero-filled, but
        ``mem_len == 0`` means the reject fires before any read.
        """
        assert _final("4", "abc") is None

    def test_6_without_M_rejects_the_word(self):
        """Same as test_4_without_M_rejects_the_word; the prepend case rejects
        at ``rp_cpu.c:1481``."""
        assert _final("6", "abc") is None

    def test_step_is_emitted_even_when_nothing_changes(self):
        """A no-op must still produce a step, so a reader never mistakes a
        silently-skipped opcode for one that legitimately did nothing."""
        steps = explain_rule("MQ4", "abc")
        assert (
            steps is None
            or steps[-1].startswith(REJECT_SENTINEL_PREFIX)
            or any(s.startswith("4:") for s in steps)
        )


class TestMemoryInitialization:
    """The memory buffer starts empty (length 0), not seeded with the plain and
    not zero-filled to the plain's length.

    ``src/rp_cpu.c:1168``: ``int mem_len = 0``. Every memory-consuming opcode
    guards on ``mem_len < 1`` and returns ``RULE_RC_REJECT_ERROR`` — ``X`` at
    rp_cpu.c:1463, ``4`` at 1474, ``6`` at 1481 — so before any ``M`` they all
    reject rather than reading the buffer. Only ``M`` sets a length
    (``mem_len = out_len``, rp_cpu.c:1490).

    Confirmed against v7.1.2-484-g64e1bff93: ``-j '4'`` on ``abcdef``,
    ``-j '6'``, and ``-j 'X012'`` on ``abc`` each emit zero bytes.
    """

    def test_X_without_M_rejects(self):
        assert _final("X012", "abc") is None

    def test_X_after_M_reads_the_memorized_word(self):
        assert _final("MX012", "abc") == "abac"

    def test_no_memory_op_reads_a_phantom_buffer(self):
        assert _final("4", "abcdef") is None
        assert _final("6", "abcdef") is None
        assert _final("X012", "abcdef") is None


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


class TestChainedXMemoryMutation:
    """X mutates the memory buffer as a side effect (src/rp_cpu.c's
    mangle_insert_multi).

    Every case is prefixed with `M` because a bare `X` has nothing to read:
    `mem_len` starts at 0 and rp_cpu.c:1463 rejects on `mem_len < 1` (see
    TestMemoryInitialization). These previously asserted NUL-filled results for
    bare `X`, which the binary does not produce — it emits nothing.

    Values re-verified against v7.1.2-484-g64e1bff93 via
    `hashcat --stdout -j '<rule>' <(echo '<baseword>')`; the spaced and
    unspaced spellings (`MX011 X011` / `MX011X011`) agree.
    """

    def test_single_X_after_M_inserts_from_memory(self):
        assert _final("MX011", "abcdefgh") == "aabcdefgh"

    def test_chained_X011_X011_reads_the_mutated_buffer(self):
        assert _final("MX011 X011", "abcdefgh") == "aaabcdefgh"

    def test_chained_X011_X021_reads_the_mutated_buffer(self):
        assert _final("MX011 X021", "abcdefgh") == "aababcdefgh"

    def test_chained_X334_X444_reads_the_mutated_buffer(self):
        assert _final("MX334 X444", "password") == "passorddswoword"


class TestMFormatAndXBounds:
    """Both confirmed against hashcat v7.1.2 during Task 2's review."""

    def test_bare_M_final_candidate_is_the_word_not_the_description(self):
        assert _final("M", "abc") == "abc"

    def test_M_followed_by_another_opcode_still_works(self):
        assert _final("Mc", "abc") == "Abc"

    def test_X_rejects_when_insert_position_exceeds_current_length(self):
        # hashcat: X013 on 'a' (memorized == 'a' pre-Task-7b) -> empty output
        assert _final("X013", "a") is None

    def test_X_still_succeeds_within_bounds(self):
        assert _final("MX012", "abc") == "abac"

    def test_X_rejects_when_extracted_length_is_zero(self):
        # hashcat: X201 on 'cat' (m=0) is rejected, independent of n/l_pos validity
        assert _final("X201", "cat") is None


class TestMemoryOverflowRejection:
    """hashcat's RULE_OP_MANGLE_APPEND_MEMORY / RULE_OP_MANGLE_PREPEND_MEMORY
    (src/rp_cpu.c) reject the rule outright — not a silent no-op — when the
    memory buffer is empty (mem_len < 1) or when appending/prepending would
    reach the 256-byte RP_PASSWORD_SIZE cap.
    """

    def test_4_rejects_when_result_would_reach_256_bytes(self):
        assert explain_rule("4", "a" * 130) is None

    def test_6_rejects_when_result_would_reach_256_bytes(self):
        assert explain_rule("6", "a" * 130) is None

    def test_4_still_appends_when_within_bounds(self):
        assert _final("M4", "abc") == "abcabc"

    def test_6_still_prepends_when_within_bounds(self):
        assert _final("cM6", "abc") == "AbcAbc"
