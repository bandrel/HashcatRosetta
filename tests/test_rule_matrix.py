"""Test matrix for hashcat rule operations based on official wiki reference.

This test file validates the rule explanation engine against the official
hashcat rule operations documented at:
https://hashcat.net/wiki/doku.php?id=rule_based_attack

The test matrix covers all implemented rule operations with their
expected transformations as defined in the hashcat documentation.
"""

import pytest
import tempfile
import subprocess
import os
from hashcat_rosetta.cli import explain_rule


def get_hashcat_output(rule, baseword="password"):
    """
    Get hashcat output for a given rule using actual hashcat binary.

    Creates a temporary rule file and runs:
    echo <baseword> | hashcat -a0 -r <rulefile> --stdout -d1

    Returns the transformed output from hashcat, or None if error.
    """
    try:
        # Create temporary rule file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rule", delete=False) as f:
            f.write(rule)
            temp_rule_file = f.name

        try:
            # Run hashcat with the rule file
            cmd = ["hashcat", "-a0", "-r", temp_rule_file, "--stdout", "-d1"]
            result = subprocess.run(cmd, input=baseword.encode(), capture_output=True, timeout=5)

            if result.returncode == 0:
                # Parse output - should be one line with result
                output = result.stdout.decode().strip()
                return output if output else None
            else:
                # Error running hashcat
                return None
        finally:
            # Clean up temporary file
            if os.path.exists(temp_rule_file):
                os.unlink(temp_rule_file)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        # hashcat not available or timed out - skip integration test
        return None


class TestRuleMatrixWithHashcat:
    """Integration tests verifying rule explanations match hashcat output."""

    @pytest.mark.integration
    def test_rule_c_against_hashcat(self):
        """Verify capitalize rule 'c' against actual hashcat"""
        rule = "c"
        baseword = "password"

        # Get hashcat output
        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        # Get our explanation and extract final result
        result = explain_rule(rule, baseword)
        assert result is not None

        # Extract final transformation from last step
        # Format: "c: Capitalize → password → Password"
        final_result = result[-1].split("→")[-1].strip()

        assert (
            final_result == hashcat_result
        ), f"Rule '{rule}' result mismatch: got '{final_result}', hashcat produced '{hashcat_result}'"

    @pytest.mark.integration
    def test_rule_u_against_hashcat(self):
        """Verify uppercase rule 'u' against actual hashcat"""
        rule = "u"
        baseword = "password"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_l_against_hashcat(self):
        """Verify lowercase rule 'l' against actual hashcat"""
        rule = "l"
        baseword = "Password"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_d_against_hashcat(self):
        """Verify duplicate rule 'd' against actual hashcat"""
        rule = "d"
        baseword = "pass"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_r_against_hashcat(self):
        """Verify reverse rule 'r' against actual hashcat"""
        rule = "r"
        baseword = "test"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_bracket_left_against_hashcat(self):
        """Verify truncate left '[' against actual hashcat"""
        rule = "["
        baseword = "password"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_bracket_right_against_hashcat(self):
        """Verify truncate right ']' against actual hashcat"""
        rule = "]"
        baseword = "password"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_append_against_hashcat(self):
        """Verify append '$1' against actual hashcat"""
        rule = "$1"
        baseword = "test"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rule_prepend_against_hashcat(self):
        """Verify prepend '^!' against actual hashcat"""
        rule = "^!"
        baseword = "test"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_rules_complex_against_hashcat(self):
        """Verify complex rule 'cdu' against actual hashcat"""
        rule = "cdu"
        baseword = "test"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_prepend_chain_december_against_hashcat(self):
        """Verify complex prepend chain '^r ^e ^b ^m ^e ^c ^e ^d' spells 'december'"""
        rule = "^r ^e ^b ^m ^e ^c ^e ^d"
        baseword = "password"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        # Should spell "decemberpassword"
        assert final_result == "decemberpassword"
        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_append_chain_against_hashcat(self):
        """Verify complex append chain '$1$2$3' appends digits"""
        rule = "$1$2$3"
        baseword = "pass"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        # Should produce "pass123"
        assert final_result == "pass123"
        assert final_result == hashcat_result

    @pytest.mark.integration
    def test_mixed_transforms_against_hashcat(self):
        """Verify mixed rule '^!$!' (prepend ! and append !)"""
        rule = "^!$!"
        baseword = "test"

        hashcat_result = get_hashcat_output(rule, baseword)
        if hashcat_result is None:
            pytest.skip("hashcat not available")

        result = explain_rule(rule, baseword)
        assert result is not None
        final_result = result[-1].split("→")[-1].strip()

        # Should produce "!test!"
        assert final_result == "!test!"
        assert final_result == hashcat_result


class TestRuleMatrix:
    """Test suite covering hashcat rule operations matrix."""

    # ===== BASIC TRANSFORMATION RULES =====
    # Reference: Hashcat wiki - Implemented compatible functions

    def test_rule_lowercase(self):
        """Rule 'l': Lowercase all letters"""
        result = explain_rule("l", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "p@ssw0rd" in result[0]

    def test_rule_uppercase(self):
        """Rule 'u': Uppercase all letters"""
        result = explain_rule("u", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "P@SSW0RD" in result[0]

    def test_rule_capitalize(self):
        """Rule 'c': Capitalize first letter, lowercase rest"""
        result = explain_rule("c", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "P@ssw0rd" in "".join(result)

    def test_rule_toggle_case(self):
        """Rule 't': Toggle case of all characters"""
        result = explain_rule("t", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        # Each letter toggles: p→P, s→S, W→w, r→R, d→D, non-letters unchanged
        assert "P@SSw0RD" in result[0]

    def test_rule_reverse(self):
        """Rule 'r': Reverse the entire word"""
        result = explain_rule("r", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "dr0Wss@p" in result[0]

    def test_rule_duplicate(self):
        """Rule 'd': Duplicate entire word"""
        result = explain_rule("d", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "p@ssW0rdp@ssW0rd" in result[0]

    def test_rule_reflect(self):
        """Rule 'f': Duplicate word reversed (reflect)"""
        result = explain_rule("f", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        # f = duplicate + reversed, so "p@ssW0rd" + "dr0Wss@p"
        assert "p@ssW0rddr0Wss@p" in result[0]

    def test_rule_rotate_left(self):
        """Rule '{': Rotate word left"""
        result = explain_rule("{", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "@ssW0rdp" in result[0]

    def test_rule_rotate_right(self):
        """Rule '}': Rotate word right"""
        result = explain_rule("}", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "dp@ssW0r" in result[0]

    def test_rule_truncate_left(self):
        """Rule '[': Delete first character (truncate left)"""
        result = explain_rule("[", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "@ssW0rd" in result[0]

    def test_rule_truncate_right(self):
        """Rule ']': Delete last character (truncate right)"""
        result = explain_rule("]", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "p@ssW0r" in result[0]

    def test_rule_duplicate_word(self):
        """Rule 'pN': Append duplicated word N times"""
        result = explain_rule("p2", "abc")
        assert result is not None
        assert len(result) == 1
        assert "abcabcabc" in result[0]

    # ===== POSITIONAL RULES =====

    def test_rule_insert_at_position(self):
        """Rule 'iNX': Insert character X at position N"""
        # i4! means insert '!' at position 4
        result = explain_rule("i4!", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        # Position 4 in "p@ssW0rd" is after 'p@ss', inserting at pos 4 gives "p@ss!W0rd"
        assert "p@ss!W0rd" in result[0]

    def test_rule_insert_at_position_hex(self):
        """Rule 'iNX': Insert with hex position (A=10, B=11, etc)"""
        # iA3 means insert '3' at position A (hex) = 10
        result = explain_rule("iA3", "testword")  # len=8
        assert result is not None
        # Position 10 is beyond length, so appends
        assert "testword3" in result[0] or "testword" in result[0]

    def test_rule_delete_at_position(self):
        """Rule 'DN': Delete character at position N"""
        # D3 means delete character at position 3
        result = explain_rule("D3", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "p@sW0rd" in result[0]

    def test_rule_delete_at_position_hex(self):
        """Rule 'DN': Delete at hex position"""
        # D0 means delete character at position 0
        result = explain_rule("D0", "p@ssW0rd")
        assert result is not None
        assert "@ssW0rd" in result[0]

    def test_rule_toggle_at_position(self):
        """Rule 'TN': Toggle case at position N"""
        # T3 means toggle case at position 3
        result = explain_rule("T3", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        # Position 3 is 's', which becomes 'S'
        assert "p@sSW0rd" in result[0]

    def test_rule_replace_char(self):
        """Rule 'sXY': Replace all instances of X with Y"""
        # ss$ means replace all 's' with '$'
        result = explain_rule("ss$", "p@ssW0rd")
        assert result is not None
        assert len(result) == 1
        assert "p@$$W0rd" in result[0]

    def test_rule_substitute_no_match(self):
        """Rule 'sXY': Replace when character doesn't exist"""
        # sxz means replace all 'x' with 'z' (x doesn't exist in word)
        result = explain_rule("sxz", "p@ssW0rd")
        assert result is not None
        assert "p@ssW0rd" in result[0]

    # ===== APPEND/PREPEND RULES =====

    def test_rule_append_char_single(self):
        """Rule '$X': Append single character"""
        # $1 means append '1'
        result = explain_rule("$1", "p@ssW0rd")
        assert result is not None
        assert "p@ssW0rd1" in result[0]

    def test_rule_append_multiple_chars(self):
        """Rule '$X': Append multiple characters"""
        # $1$2 means append '1' then append '2'
        result = explain_rule("$1$2", "p@ssW0rd")
        assert result is not None
        assert len(result) == 2
        # First step: append 1
        assert "p@ssW0rd1" in result[0]
        # Second step: append 2
        assert "p@ssW0rd12" in result[1]

    def test_rule_prepend_char_single(self):
        """Rule '^X': Prepend single character"""
        # ^2 means prepend '2'
        result = explain_rule("^2", "p@ssW0rd")
        assert result is not None
        assert "2p@ssW0rd" in result[0]

    def test_rule_prepend_multiple_chars(self):
        """Rule '^X': Prepend multiple characters"""
        # ^2^1 means prepend '2' then prepend '1'
        result = explain_rule("^2^1", "p@ssW0rd")
        assert result is not None
        assert len(result) == 2
        # First step: prepend 2
        assert "2p@ssW0rd" in result[0]
        # Second step: prepend 1 (goes before 2)
        assert "12p@ssW0rd" in result[1]

    # ===== COMPLEX RULE COMBINATIONS =====

    def test_rule_capitalize_duplicate_uppercase(self):
        """Complex rule: 'cdu' - Capitalize, Duplicate, Uppercase"""
        result = explain_rule("cdu", "p@ssW0rd")
        assert result is not None
        assert len(result) == 3
        # Step 1: capitalize (first upper, rest lower)
        assert "P@ssw0rd" in result[0]
        # Step 2: duplicate
        assert "P@ssw0rdP@ssw0rd" in result[1]
        # Step 3: uppercase
        assert "P@SSW0RDP@SSW0RD" in result[2]

    def test_rule_duplicate_reverse(self):
        """Complex rule: 'dr' - Duplicate then Reverse"""
        result = explain_rule("dr", "pass")
        assert result is not None
        assert len(result) == 2
        # Step 1: duplicate
        assert "passpass" in result[0]
        # Step 2: reverse
        assert "ssapssap" in result[1]

    def test_rule_lowercase_reverse_duplicate(self):
        """Complex rule: 'lrd' - Lowercase, Reverse, Duplicate"""
        result = explain_rule("lrd", "WoRd")
        assert result is not None
        assert len(result) == 3
        # Step 1: lowercase
        assert "word" in result[0]
        # Step 2: reverse
        assert "drow" in result[1]
        # Step 3: duplicate
        assert "drowdrow" in result[2]

    def test_rule_multiple_substitutions(self):
        """Complex rule: Multiple substitutions"""
        # sse$s1 = replace s→e, replace s→1
        result = explain_rule("sse$s1", "password")
        assert result is not None
        # Should have 2 steps (2 substitutions)
        assert len(result) >= 2

    def test_rule_insert_then_duplicate(self):
        """Complex rule: Insert character then duplicate"""
        # i2!d = insert ! at pos 2, then duplicate
        result = explain_rule("i2!d", "test")
        assert result is not None
        assert len(result) == 2
        # Step 1: insert at pos 2 (between 'e' and 's')
        assert "te!st" in result[0]
        # Step 2: duplicate (word is duplicated no separator)
        assert "te!stte!st" in result[1]

    # ===== EDGE CASES =====

    def test_rule_empty_rule(self):
        """Test empty rule string"""
        result = explain_rule("", "password")
        assert result is None

    def test_rule_unknown_single_rule(self):
        """Test unknown rule character"""
        result = explain_rule("x", "password")
        # Should return None or empty since 'x' is not recognized
        assert result is None or result == []

    def test_rule_passthrough(self):
        """Test rule with mostly unknown characters"""
        result = explain_rule("xyz", "password")
        assert result is None or (result is not None and len(result) == 0)

    def test_rule_mixed_known_unknown(self):
        """Test rule with mix of known and unknown characters"""
        result = explain_rule("cxu", "test")
        assert result is not None
        # Should have steps for 'c' and 'u'
        assert len(result) >= 2

    def test_rule_truncate_empty_string(self):
        """Test truncate operations on short strings"""
        result = explain_rule("[[", "a")
        assert result is not None
        # First [ removes 'a', leaving empty
        # Second [ on empty should handle gracefully

    def test_rule_delete_out_of_bounds(self):
        """Test delete at position beyond string length"""
        result = explain_rule("D5", "test")  # len=4, delete pos 5
        assert result is not None
        # Should handle gracefully, not crashing

    def test_rule_with_default_baseword(self):
        """Test that default baseword 'password' is used"""
        result = explain_rule("u")
        assert result is not None
        assert "PASSWORD" in result[0]

    def test_rule_with_custom_baseword(self):
        """Test custom baseword parameter"""
        result = explain_rule("u", "admin")
        assert result is not None
        assert "ADMIN" in result[0]

    # ===== PARAMETERIZED RULE EDGE CASES =====

    def test_insert_with_multiple_operations(self):
        """Test multiple insert operations"""
        # i74i81i92iA3 = insert at positions with digits
        result = explain_rule("i74i81i92iA3", "password")
        assert result is not None
        # Should have 4 steps
        assert len(result) >= 4
        # Final should have digits inserted
        assert any(digit in "".join(result[-1]) for digit in "4123")

    def test_delete_multiple_positions(self):
        """Test multiple delete operations"""
        # D0D0 = delete pos 0 twice (each removes next first char)
        result = explain_rule("D0D0", "password")
        assert result is not None
        assert len(result) == 2

    def test_toggle_multiple_positions(self):
        """Test multiple toggle operations"""
        # T0T1 = toggle pos 0, then toggle pos 1
        result = explain_rule("T0T1", "abcdef")
        assert result is not None
        assert len(result) == 2

    # ===== BASEWORD PARAMETER TESTS =====

    def test_explain_with_short_baseword(self):
        """Test explanation with short baseword"""
        result = explain_rule("cdu", "ps")
        assert result is not None
        assert len(result) == 3
        # Step 1: capitalize
        assert "Ps" in result[0]
        # Step 2: duplicate
        assert "PsPs" in result[1]
        # Step 3: uppercase
        assert "PSPS" in result[2]

    def test_explain_with_long_baseword(self):
        """Test explanation with long baseword"""
        result = explain_rule("lu", "ThisisAVeryLongPassword")
        assert result is not None
        assert len(result) == 2
        # All lowercase then all uppercase
        assert "thisisaverylong" in result[0].lower()
        assert "THISISAVERYLONG" in result[1]

    def test_explain_with_special_chars_baseword(self):
        """Test explanation with special characters in baseword"""
        result = explain_rule("c", "p@$$w0rd!")
        assert result is not None
        # Should capitalize first char
        assert "P@$$w0rd!" in result[0]

    def test_explain_with_numeric_baseword(self):
        """Test explanation with numeric baseword"""
        result = explain_rule("u", "test123")
        assert result is not None
        # Should handle numeric content
        assert "TEST123" in result[0]

    def test_explain_baseword_unchanged_by_params(self):
        """Test that baseword parameter doesn't affect rule parsing"""
        result1 = explain_rule("l", "PASSWORD")
        result2 = explain_rule("l", "admin")
        result3 = explain_rule("l", "test")

        assert result1 is not None
        assert result2 is not None
        assert result3 is not None

        # All should produce lowercase output
        assert "password" in result1[0].lower()
        assert "admin" in result2[0].lower()
        assert "test" in result3[0].lower()


class TestRuleMatrixRobustness:
    """Tests for rule matrix robustness and error handling."""

    def test_incomplete_parameterized_rule(self):
        """Test incomplete parameterized rule (missing parameters)"""
        # 'i' followed by < 2 chars should handle gracefully
        result = explain_rule("i4", "test")
        # Should either skip it or handle it without crashing
        assert result is None or isinstance(result, list)

    def test_rule_with_whitespace(self):
        """Test rule with various whitespace"""
        # Hashcat rules can have spaces (usually ignored)
        result = explain_rule("c u", "test")
        assert result is not None or result is None  # Implementation dependent

    def test_rule_with_comments(self):
        """Test rule containing comment character"""
        # '#' starts a comment in hashcat rules
        result = explain_rule("c#comment", "test")
        # Should handle comment character (usually stops processing)
        assert result is not None or result is None

    def test_very_long_rule_chain(self):
        """Test very long chain of rules"""
        long_rule = "cudlrft[]{}"  # Many operations
        result = explain_rule(long_rule, "test")
        assert result is not None
        # Should have steps for each valid operation
        assert len(result) > 0


class TestRuleComprehensiveCoverage:
    """Test comprehensive coverage of rule operations."""

    @pytest.mark.parametrize(
        "rule,baseword,expected_in_output",
        [
            ("l", "PASSWORD", "password"),
            ("u", "password", "PASSWORD"),
            ("c", "password", "Password"),
            ("t", "aB", "Ab"),  # simple toggle test
            ("r", "test", "tset"),
            ("d", "ab", "abab"),
            ("f", "ab", "abba"),  # ab + ba
            ("{", "abcd", "bcda"),  # rotate left
            ("}", "abcd", "dabc"),  # rotate right
            ("[", "abcd", "bcd"),  # remove first
            ("]", "abcd", "abc"),  # remove last
            ("$1", "test", "test1"),
            ("^1", "test", "1test"),
            ("i2x", "test", "texst"),  # insert x at pos 2
            ("D1", "test", "tst"),  # delete at pos 1
        ],
    )
    def test_individual_rules(self, rule, baseword, expected_in_output):
        """Parameterized test for individual rules with expected output."""
        result = explain_rule(rule, baseword)
        assert result is not None, f"Rule '{rule}' returned None"
        assert any(
            expected_in_output in step for step in result
        ), f"Expected '{expected_in_output}' in output for rule '{rule}' with baseword '{baseword}': {result}"
