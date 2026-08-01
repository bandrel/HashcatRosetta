"""Tests for hashcat mask parsing, validation, and keyspace computation."""

import pytest

from hashcat_rosetta.mask import (
    BUILTIN_CHARSETS,
    HcmaskLine,
    MaskError,
    describe,
    format_hcmask_line,
    keyspace,
    parse_hcmask_line,
    tokens,
    validate_mask,
)


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
        with pytest.raises(MaskError, match="at most 4 custom charsets"):
            parse_hcmask_line("a,b,c,d,e,?1")

    def test_validate_mask_directly_unknown_token(self):
        with pytest.raises(MaskError, match="unknown token"):
            validate_mask("?z", [])

    def test_validate_mask_directly_dangling_question(self):
        with pytest.raises(MaskError, match="dangling trailing"):
            validate_mask("test?", [])

    def test_validate_mask_directly_bad_reference(self):
        with pytest.raises(MaskError, match="referenced \\?2"):
            validate_mask("?1?2", ["abc"])


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
        # Custom charset with only escaped commas
        line = parse_hcmask_line("a\\,\\,b,?1")
        assert line.custom == ["a,,b"]
        assert keyspace(line) == 4  # length of "a,,b"

    def test_question_mark_in_middle_of_custom(self):
        # Question marks in custom charsets are literal (no unescaping in
        # custom fields)
        line = parse_hcmask_line("a?b,?1?1")
        assert line.custom == ["a?b"]
        assert keyspace(line) == 3 * 3  # custom charset "a?b" has length 3

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
            parse_hcmask_line("a,b,c,d,e,?1")
        assert "4" in str(exc_info.value)
        assert "5" in str(exc_info.value)


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
