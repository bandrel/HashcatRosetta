"""Tests for hashcat mask parsing, validation, and keyspace computation."""

import subprocess
from types import SimpleNamespace

import pytest

import hashcat_rosetta.mask as mask_module
from hashcat_rosetta.mask import (
    BUILTIN_CHARSETS,
    HcmaskLine,
    MaskError,
    describe,
    expand_custom_charsets,
    format_hcmask_line,
    keyspace,
    parse_hcmask_line,
    tokens,
    validate_mask,
    verify_keyspace_with_maskprocessor,
)
from hashcat_rosetta.mask import _maskprocessor_keyspace, _short_scientific


class TestBuiltinCharsets:
    """Test that builtin charsets have correct sizes."""

    def test_lowercase_size(self):
        assert len(BUILTIN_CHARSETS["?l"]) == 26

    def test_uppercase_size(self):
        assert len(BUILTIN_CHARSETS["?u"]) == 26

    def test_digit_size(self):
        assert len(BUILTIN_CHARSETS["?d"]) == 10

    def test_hex_lowercase_size(self):
        assert len(BUILTIN_CHARSETS["?h"]) == 16

    def test_hex_uppercase_size(self):
        assert len(BUILTIN_CHARSETS["?H"]) == 16

    def test_special_size(self):
        assert len(BUILTIN_CHARSETS["?s"]) == 33

    def test_alphanumeric_special_size(self):
        assert len(BUILTIN_CHARSETS["?a"]) == 95

    def test_byte_size(self):
        assert len(BUILTIN_CHARSETS["?b"]) == 256

    def test_special_charset_content(self):
        # Verify the special charset matches the expected set
        expected = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        assert BUILTIN_CHARSETS["?s"] == expected


class TestParseSimpleMasks:
    """Test parsing masks without custom charsets."""

    def test_parse_digits_only(self):
        line = parse_hcmask_line("?d?d?d?d")
        assert line.custom == []
        assert line.mask == "?d?d?d?d"
        assert line.raw == "?d?d?d?d"

    def test_parse_literal_only(self):
        line = parse_hcmask_line("Summer")
        assert line.custom == []
        assert line.mask == "Summer"

    def test_parse_mixed_literal_and_token(self):
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        assert line.custom == []
        assert line.mask == "Summer?d?d?d?d?d?d"


class TestParseCustomCharsets:
    """Test parsing with custom charsets."""

    def test_one_custom_charset(self):
        line = parse_hcmask_line("abcdef,?1?1?1?1")
        assert line.custom == ["abcdef"]
        assert line.mask == "?1?1?1?1"

    def test_two_custom_charsets(self):
        line = parse_hcmask_line("abc,def,?1?2?1?2")
        assert line.custom == ["abc", "def"]
        assert line.mask == "?1?2?1?2"

    def test_three_custom_charsets(self):
        line = parse_hcmask_line("a,b,c,?1?2?3?1")
        assert line.custom == ["a", "b", "c"]
        assert line.mask == "?1?2?3?1"

    def test_four_custom_charsets(self):
        line = parse_hcmask_line("a,b,c,d,?1?2?3?4")
        assert line.custom == ["a", "b", "c", "d"]
        assert line.mask == "?1?2?3?4"


class TestEscapedCommas:
    """Test handling of escaped commas in custom charsets."""

    def test_escaped_comma_in_custom_charset(self):
        line = parse_hcmask_line("a\\,b,?1?1?1")
        assert line.custom == ["a,b"]
        assert line.mask == "?1?1?1"

    def test_multiple_escaped_commas(self):
        line = parse_hcmask_line("a\\,b\\,c,?1?1")
        assert line.custom == ["a,b,c"]
        assert line.mask == "?1?1"

    def test_escaped_comma_followed_by_unescaped(self):
        line = parse_hcmask_line("a\\,b,c,?1?2")
        assert line.custom == ["a,b", "c"]
        assert line.mask == "?1?2"

    def test_escaped_comma_in_mask_not_separates(self):
        # Escaped comma in mask field — should be treated as literal comma,
        # not as a field separator. The comma should be unescaped during parse.
        line = parse_hcmask_line("?d?d\\,test")
        # Mask field contains a literal comma (after unescaping)
        assert line.mask == "?d?d,test"
        assert line.custom == []

    def test_escaped_comma_in_mask_roundtrip(self):
        # Comma in mask must be escaped on output for round-trip property
        original = "?d?d\\,test"
        line = parse_hcmask_line(original)
        # Mask should have unescaped comma
        assert line.mask == "?d?d,test"
        # Re-format should re-escape it
        formatted = format_hcmask_line(line.custom, line.mask)
        assert formatted == original


class TestEscapedQuestion:
    """Test handling of escaped question marks (literal ?)."""

    def test_escaped_question_mark(self):
        line = parse_hcmask_line("Password??2024")
        assert line.mask == "Password??2024"
        assert line.custom == []

    def test_multiple_escaped_questions(self):
        line = parse_hcmask_line("??hello??")
        assert line.mask == "??hello??"


class TestValidationErrors:
    """Test validation of invalid masks."""

    def test_dangling_trailing_question(self):
        with pytest.raises(MaskError, match="dangling trailing"):
            parse_hcmask_line("?d?d?")

    def test_unknown_token(self):
        with pytest.raises(MaskError, match="unknown token"):
            parse_hcmask_line("?z?d?d")

    def test_reference_to_nonexistent_custom_charset(self):
        with pytest.raises(MaskError, match="referenced \\?1"):
            parse_hcmask_line("?1?1?1")  # No custom charset provided

    def test_reference_to_custom_charset_higher_than_provided(self):
        with pytest.raises(MaskError, match="referenced \\?3"):
            # Only ?1 and ?2 are provided
            parse_hcmask_line("a,b,?1?2?3")

    def test_too_many_custom_charsets(self):
        with pytest.raises(MaskError, match="at most 8 custom charsets"):
            parse_hcmask_line("a,b,c,d,e,f,g,h,i,?1")

    def test_eight_custom_charsets_allowed(self):
        line = parse_hcmask_line("a,b,c,d,e,f,g,h,?1?2?3?4?5?6?7?8")
        assert line.custom == ["a", "b", "c", "d", "e", "f", "g", "h"]
        assert tokens(line) == [(f"?{n}", 1) for n in range(1, 9)]

    def test_validate_mask_directly_unknown_token(self):
        with pytest.raises(MaskError, match="unknown token"):
            validate_mask("?z", [])

    def test_validate_mask_directly_dangling_question(self):
        with pytest.raises(MaskError, match="dangling trailing"):
            validate_mask("test?", [])

    def test_validate_mask_directly_bad_reference(self):
        with pytest.raises(MaskError, match="referenced \\?2"):
            validate_mask("?1?2", ["abc"])

    def test_mask_at_256_positions_allowed(self):
        # hashcat's own limit (SP_PW_MAX in mpsp.h) is 256 positions.
        validate_mask("a" * 256, [])

    def test_mask_over_256_positions_rejected(self):
        with pytest.raises(MaskError, match="257 positions"):
            validate_mask("a" * 257, [])

    def test_empty_mask_rejected(self):
        # hashcat itself rejects this: "Invalid mask length (0)." (mpsp.c).
        with pytest.raises(MaskError, match="empty"):
            validate_mask("", [])

    def test_parse_hcmask_line_rejects_empty_mask(self):
        with pytest.raises(MaskError, match="empty"):
            parse_hcmask_line("")

    def test_mask_length_counts_positions_not_characters(self):
        # '??' is 2 characters but 1 position — 256 of them must still pass.
        validate_mask("??" * 256, [])
        with pytest.raises(MaskError, match="257 positions"):
            validate_mask("??" * 257, [])


class TestTokens:
    """Test the tokens() function."""

    def test_tokens_literal_only(self):
        line = parse_hcmask_line("abc")
        tok_list = tokens(line)
        assert tok_list == [("a", 1), ("b", 1), ("c", 1)]

    def test_tokens_single_digit(self):
        line = parse_hcmask_line("?d")
        tok_list = tokens(line)
        assert tok_list == [("?d", 10)]

    def test_tokens_mixed(self):
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        tok_list = tokens(line)
        expected = [
            ("S", 1),
            ("u", 1),
            ("m", 1),
            ("m", 1),
            ("e", 1),
            ("r", 1),
            ("?d", 10),
            ("?d", 10),
            ("?d", 10),
            ("?d", 10),
            ("?d", 10),
            ("?d", 10),
        ]
        assert tok_list == expected

    def test_tokens_escaped_question(self):
        line = parse_hcmask_line("Pass??2024")
        tok_list = tokens(line)
        # ?? is a single token with size 1
        expected = [
            ("P", 1),
            ("a", 1),
            ("s", 1),
            ("s", 1),
            ("??", 1),
            ("2", 1),
            ("0", 1),
            ("2", 1),
            ("4", 1),
        ]
        assert tok_list == expected

    def test_tokens_custom_charset(self):
        line = parse_hcmask_line("abc,?1?1?d")
        tok_list = tokens(line)
        # ?1 has size 3 (length of "abc"), ?d has size 10
        assert tok_list == [("?1", 3), ("?1", 3), ("?d", 10)]

    def test_tokens_empty_mask(self):
        # Edge case: empty mask — technically valid but unusual
        line = HcmaskLine(custom=[], mask="", raw="")
        tok_list = tokens(line)
        assert tok_list == []


class TestKeyspace:
    """Test keyspace calculation."""

    def test_keyspace_single_digit(self):
        line = parse_hcmask_line("?d")
        assert keyspace(line) == 10

    def test_keyspace_summer_six_digits(self):
        # Summer?d?d?d?d?d?d
        # Summer is 6 literals (size 1 each), then 6 digits (size 10 each)
        # Total: 1 * 10^6 = 1,000,000
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        assert keyspace(line) == 1_000_000

    def test_keyspace_byte_only(self):
        # ?b is 256 bytes
        line = parse_hcmask_line("?b")
        assert keyspace(line) == 256

    def test_keyspace_custom_charset(self):
        # abc (size 3) followed by ?d (size 10) three times
        # 3 * 10 * 10 * 10 = 3000
        line = parse_hcmask_line("abc,?1?d?d?d")
        assert keyspace(line) == 3 * 10 * 10 * 10

    def test_keyspace_all_builtin_charsets(self):
        # Check each builtin charset produces correct keyspace
        cases = [
            ("?l", 26),
            ("?u", 26),
            ("?d", 10),
            ("?h", 16),
            ("?H", 16),
            ("?s", 33),
            ("?a", 95),
            ("?b", 256),
        ]
        for mask_str, expected_size in cases:
            line = parse_hcmask_line(mask_str)
            assert keyspace(line) == expected_size, f"Failed for {mask_str}"


class TestDescribe:
    """Test the describe() function."""

    def test_describe_digits(self):
        line = parse_hcmask_line("?d?d?d?d")
        desc = describe(line)
        assert "digit" in desc
        assert "4 ×" in desc
        assert "10,000" in desc

    def test_describe_summer_six_digits(self):
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        desc = describe(line)
        assert "Summer" in desc
        assert "digit" in desc
        assert "1,000,000" in desc

    def test_describe_empty_mask(self):
        line = HcmaskLine(custom=[], mask="", raw="")
        desc = describe(line)
        assert "empty mask" in desc or desc == "empty mask → 1 candidate"

    def test_describe_includes_thousands_separator(self):
        line = parse_hcmask_line("?d?d?d?d?d?d?d?d")  # 10^8 = 100,000,000
        desc = describe(line)
        assert "100,000,000" in desc

    def test_describe_scientific_notation_for_large_keyspace(self):
        # Use ?b (256) repeated to get >10^9
        # ?b is 256, so ?b^6 = 256^6 = 281,474,976,710,656 > 10^9
        line = parse_hcmask_line("?b?b?b?b?b?b")
        desc = describe(line)
        # Should contain the full number with thousands separators
        assert "281,474,976,710,656" in desc
        # Should contain scientific notation in the exact format
        assert "(~2.8e+14)" in desc

    def test_describe_custom_charset(self):
        line = parse_hcmask_line("abc,?1?1?1")
        desc = describe(line)
        # Should mention custom charset 1
        assert "custom charset 1" in desc
        # Keyspace is 3^3 = 27
        assert "27" in desc


class TestFormatHcmaskLine:
    """Test the format_hcmask_line() function."""

    def test_format_no_custom_charsets(self):
        result = format_hcmask_line([], "?d?d?d?d")
        assert result == "?d?d?d?d"

    def test_format_one_custom_charset(self):
        result = format_hcmask_line(["abcdef"], "?1?1?1?1")
        assert result == "abcdef,?1?1?1?1"

    def test_format_multiple_custom_charsets(self):
        result = format_hcmask_line(["abc", "def"], "?1?2?1?2")
        assert result == "abc,def,?1?2?1?2"

    def test_format_custom_charset_with_comma(self):
        # Custom charset containing a literal comma
        result = format_hcmask_line(["a,b"], "?1?1")
        assert result == "a\\,b,?1?1"

    def test_format_multiple_custom_with_commas(self):
        result = format_hcmask_line(["a,b", "c,d"], "?1?2")
        assert result == "a\\,b,c\\,d,?1?2"


class TestRoundTrip:
    """Test that parse_hcmask_line and format_hcmask_line round-trip correctly."""

    def test_roundtrip_no_custom(self):
        original = "?d?d?d?d"
        line = parse_hcmask_line(original)
        formatted = format_hcmask_line(line.custom, line.mask)
        assert formatted == original

    def test_roundtrip_one_custom(self):
        original = "abcdef,?1?1?1"
        line = parse_hcmask_line(original)
        formatted = format_hcmask_line(line.custom, line.mask)
        assert formatted == original

    def test_roundtrip_with_escaped_comma(self):
        original = "a\\,b,?1?1"
        line = parse_hcmask_line(original)
        # After parsing, the custom charset should be unescaped
        assert line.custom == ["a,b"]
        # When formatting, it should be re-escaped
        formatted = format_hcmask_line(line.custom, line.mask)
        assert formatted == original

    def test_roundtrip_multiple_with_commas(self):
        original = "a\\,b,c\\,d,?1?2"
        line = parse_hcmask_line(original)
        formatted = format_hcmask_line(line.custom, line.mask)
        assert formatted == original


class TestEdgeCases:
    """Test edge cases and corner cases."""

    def test_empty_custom_charset(self):
        # Empty custom charsets are invalid — they cannot generate any candidates.
        # validate_mask should reject them with a clear error.
        with pytest.raises(MaskError, match="custom charset \\?1 is empty"):
            validate_mask("?1", [""])

    def test_all_escapes_in_custom_charset(self):
        # Custom charset with only escaped commas. hashcat deduplicates the
        # characters of a custom charset, so "a,,b" is the 3-char set {a , b}.
        # Verified: `hashcat --stdout -a 3` on "a\,\,b,?1" emits b, a, ",".
        line = parse_hcmask_line("a\\,\\,b,?1")
        assert line.custom == ["a,,b"]
        assert keyspace(line) == 3

    def test_question_mark_in_middle_of_custom(self):
        # hashcat expands ?X tokens INSIDE a custom charset definition too, so
        # "a?b" is 'a' plus all 256 byte values, deduplicated => 256 chars.
        # Verified: `hashcat --stdout -a 3` on "a?b,?1?1" emits 65536 candidates.
        line = parse_hcmask_line("a?b,?1?1")
        assert line.custom == ["a?b"]
        assert keyspace(line) == 256 * 256

    def test_mask_with_special_literals(self):
        # Mask can contain any literal characters (including special ones)
        line = parse_hcmask_line("!@#$%?d?d")
        tok_list = tokens(line)
        assert tok_list[0] == ("!", 1)
        assert tok_list[1] == ("@", 1)
        assert tok_list[2] == ("#", 1)
        assert tok_list[3] == ("$", 1)
        assert tok_list[4] == ("%", 1)
        assert tok_list[5] == ("?d", 10)
        assert tok_list[6] == ("?d", 10)

    def test_large_custom_charset(self):
        # Custom charset with many characters
        large_charset = "abcdefghijklmnopqrstuvwxyz"
        line = parse_hcmask_line(f"{large_charset},?1?1")
        assert len(line.custom[0]) == 26
        assert keyspace(line) == 26 * 26


class TestMaskErrorMessages:
    """Test that error messages are precise and helpful."""

    def test_error_message_dangling_question(self):
        with pytest.raises(MaskError) as exc_info:
            parse_hcmask_line("?d?")
        assert "dangling" in str(exc_info.value).lower()

    def test_error_message_unknown_token(self):
        with pytest.raises(MaskError) as exc_info:
            parse_hcmask_line("?z")
        assert "unknown" in str(exc_info.value).lower()
        assert "?z" in str(exc_info.value)

    def test_error_message_missing_charset(self):
        with pytest.raises(MaskError) as exc_info:
            parse_hcmask_line("?2?2")
        assert "?2" in str(exc_info.value)
        assert "referenced" in str(exc_info.value).lower()

    def test_error_message_too_many_charsets(self):
        with pytest.raises(MaskError) as exc_info:
            parse_hcmask_line("a,b,c,d,e,f,g,h,i,?1")
        assert "8" in str(exc_info.value)
        assert "9" in str(exc_info.value)


class TestHcmaskLineDataclass:
    """Test the HcmaskLine dataclass."""

    def test_hcmask_line_creation(self):
        line = HcmaskLine(custom=["abc"], mask="?1?d", raw="abc,?1?d")
        assert line.custom == ["abc"]
        assert line.mask == "?1?d"
        assert line.raw == "abc,?1?d"

    def test_hcmask_line_from_parse(self):
        parsed = parse_hcmask_line("abc,?1?1")
        assert isinstance(parsed, HcmaskLine)
        assert parsed.custom == ["abc"]
        assert parsed.mask == "?1?1"
        assert parsed.raw == "abc,?1?1"


class TestCustomCharsetExpansion:
    """hashcat expands ?X tokens inside custom charset *definitions* too.

    Every expected value in this class was cross-checked against the real
    hashcat binary (v7.1.2) with `hashcat --stdout -a 3 <file.hcmask>`.
    """

    def test_builtin_tokens_expand_inside_custom_charset(self):
        # "?l?d" is 26 + 10 = 36 characters, not the 4-character literal
        # string. hashcat --stdout emits 36^4 = 1,679,616 candidates.
        line = parse_hcmask_line("?l?d,?1?1?1?1")
        assert keyspace(line) == 1_679_616
        assert keyspace(line) == 36**4

    def test_expand_charset_returns_deduplicated_set(self):
        # hashcat deduplicates: "ab?l" is just the 26 lowercase letters.
        assert expand_custom_charsets(["ab?l"]) == [BUILTIN_CHARSETS["?l"]]
        assert expand_custom_charsets(["aa"]) == ["a"]
        assert expand_custom_charsets(["?l?d"]) == [BUILTIN_CHARSETS["?l"] + BUILTIN_CHARSETS["?d"]]

    def test_byte_token_inside_custom_charset(self):
        # "a?b" => 'a' plus 256 byte values, deduplicated => 256.
        line = parse_hcmask_line("a?b,?1?1")
        assert keyspace(line) == 65_536

    def test_double_question_is_literal_inside_custom_charset(self):
        # "a??b" is the 3-char set {a, ?, b}: hashcat emits 3 candidates.
        line = parse_hcmask_line("a??b,?1")
        assert keyspace(line) == 3
        assert expand_custom_charsets(["a??b"]) == ["a?b"]

    def test_tokens_reports_expanded_custom_size(self):
        line = parse_hcmask_line("?d?d,?1?1")
        # "?d?d" deduplicates back down to the 10 digits.
        assert tokens(line) == [("?1", 10), ("?1", 10)]

    def test_custom_charset_may_reference_an_earlier_one(self):
        # Verified: "abc,?1?d,?2?2" emits 169 candidates (13^2).
        line = parse_hcmask_line("abc,?1?d,?2?2")
        assert keyspace(line) == 169

    def test_custom_charset_cannot_reference_itself_or_a_later_one(self):
        with pytest.raises(MaskError, match="not defined yet"):
            parse_hcmask_line("ab?1,?1")
        with pytest.raises(MaskError, match="not defined yet"):
            parse_hcmask_line("abc,?2,?1")

    def test_dangling_question_in_custom_charset_raises(self):
        # hashcat: "Syntax error in mask: abc?"
        with pytest.raises(MaskError, match="dangling trailing"):
            parse_hcmask_line("abc?,?1")

    def test_unknown_token_in_custom_charset_raises(self):
        # hashcat: "Syntax error in mask: ab?z"
        with pytest.raises(MaskError, match=r"unknown token '\?z'"):
            parse_hcmask_line("ab?z,?1")

    def test_uppercase_hex_token_inside_custom_charset(self):
        line = parse_hcmask_line("?H,?1?1")
        assert keyspace(line) == 16 * 16

    def test_empty_custom_charset_still_rejected(self):
        with pytest.raises(MaskError, match=r"custom charset \?1 is empty"):
            parse_hcmask_line(",?1")


class TestVeryLargeKeyspaceDescribe:
    """describe() must not overflow on keyspaces beyond float range."""

    def test_describe_does_not_overflow_on_huge_keyspace(self):
        # ?b * 200 => 256^200 ~= 10^481, far beyond float's ~1.8e308.
        line = parse_hcmask_line("?b" * 200)
        ks = keyspace(line)
        assert ks == 256**200
        desc = describe(line)
        assert "200 × byte" in desc
        # digits - 1 == the exponent; 256^200 has 482 digits.
        assert f"e+{len(str(ks)) - 1}" in desc
        assert "(~4.4e+481)" in desc

    def test_short_scientific_matches_float_formatting(self):
        # The integer implementation must be byte-identical to the previous
        # float-based f"{ks:.1e}" for everything a float can represent.
        for value in (10**9 + 1, 256**6, 12_345_678_901, 999_999_999_999, 10**300):
            assert _short_scientific(value) == f"{value:.1e}"

    def test_describe_scientific_format_unchanged(self):
        line = parse_hcmask_line("?b?b?b?b?b?b")
        assert "(~2.8e+14)" in describe(line)


class TestMaskprocessorKeyspace:
    """Unit tests with subprocess mocked out — no real mp64 binary needed."""

    def test_returns_none_when_binary_missing(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", None)
        assert _maskprocessor_keyspace([], "?d?d?d") is None

    def test_builds_expected_args_and_parses_output(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            return SimpleNamespace(returncode=0, stdout="1000000\n")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _maskprocessor_keyspace([], "Summer?d?d?d?d?d?d")

        assert result == 1000000
        assert captured["args"] == ["/fake/mp64.bin", "--combinations", "Summer?d?d?d?d?d?d"]

    def test_custom_charsets_become_numbered_slots(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            return SimpleNamespace(returncode=0, stdout="62500\n")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _maskprocessor_keyspace(["aeiou"], "?1?1?1?1?d?d")

        assert result == 62500
        assert captured["args"] == [
            "/fake/mp64.bin",
            "-1",
            "aeiou",
            "--combinations",
            "?1?1?1?1?d?d",
        ]

    def test_hex_tokens_translated_onto_free_slot(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            return SimpleNamespace(returncode=0, stdout="6553600\n")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = _maskprocessor_keyspace([], "?h?h?h?h?d?d")

        assert result == 6553600
        assert captured["args"] == [
            "/fake/mp64.bin",
            "-1",
            "0123456789abcdef",
            "--combinations",
            "?1?1?1?1?d?d",
        ]

    def test_hex_token_with_no_free_slots_returns_none(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")
        # All 4 slots already used by the caller's own custom charsets.
        result = _maskprocessor_keyspace(["a", "b", "c", "d"], "?1?2?3?4?h")
        assert result is None

    def test_more_than_four_custom_charsets_returns_none(self, monkeypatch):
        # mp64 only has 4 slots (-1..-4); this module supports 8 (?1-?8),
        # so a 5th+ custom charset is simply outside what mp64 can verify.
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")

        def fail_if_called(*args, **kwargs):
            raise AssertionError("subprocess.run should not be called with >4 custom charsets")

        monkeypatch.setattr(subprocess, "run", fail_if_called)

        result = _maskprocessor_keyspace(["a", "b", "c", "d", "e"], "?1?2?3?4?5")
        assert result is None

    def test_nonzero_exit_returns_none(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")
        monkeypatch.setattr(
            subprocess, "run", lambda args, **kwargs: SimpleNamespace(returncode=1, stdout="")
        )
        assert _maskprocessor_keyspace([], "?d?d?d") is None

    def test_non_integer_output_returns_none(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda args, **kwargs: SimpleNamespace(returncode=0, stdout="not a number\n"),
        )
        assert _maskprocessor_keyspace([], "?d?d?d") is None

    def test_subprocess_exception_returns_none(self, monkeypatch):
        monkeypatch.setattr(mask_module, "MASKPROCESSOR_BIN", "/fake/mp64.bin")

        def raising_run(args, **kwargs):
            raise FileNotFoundError("no such binary")

        monkeypatch.setattr(subprocess, "run", raising_run)
        assert _maskprocessor_keyspace([], "?d?d?d") is None


class TestVerifyKeyspaceWithMaskprocessor:
    def test_skips_when_maskprocessor_unavailable(self, monkeypatch):
        monkeypatch.setattr(mask_module, "_maskprocessor_keyspace", lambda custom, mask: None)
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        assert verify_keyspace_with_maskprocessor(line) is None

    def test_matching_keyspace_passes(self, monkeypatch):
        monkeypatch.setattr(mask_module, "_maskprocessor_keyspace", lambda custom, mask: 1_000_000)
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        assert verify_keyspace_with_maskprocessor(line) is None

    def test_mismatched_keyspace_fails(self, monkeypatch):
        monkeypatch.setattr(mask_module, "_maskprocessor_keyspace", lambda custom, mask: 42)
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        result = verify_keyspace_with_maskprocessor(line)
        assert result is not None
        assert "1,000,000" in result
        assert "42" in result


@pytest.mark.integration
class TestMaskprocessorIntegration:
    """Requires the real hashcat-utils mp64 binary on PATH or a known location."""

    def test_binary_was_found(self):
        assert mask_module.MASKPROCESSOR_BIN is not None, (
            "mp64/mp64.bin not found — install hashcat-utils to run this test"
        )

    def test_plain_digits_mask_matches(self):
        line = parse_hcmask_line("Summer?d?d?d?d?d?d")
        assert verify_keyspace_with_maskprocessor(line) is None

    def test_custom_charset_mask_matches(self):
        line = parse_hcmask_line("aeiou,?1?1?1?1?d?d")
        assert verify_keyspace_with_maskprocessor(line) is None

    def test_hex_tokens_match(self):
        line = parse_hcmask_line("?h?h?h?h?d?d")
        assert verify_keyspace_with_maskprocessor(line) is None
