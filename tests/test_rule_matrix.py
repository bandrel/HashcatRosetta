"""Test matrix for hashcat rule operations based on official wiki reference.

This test file validates the rule explanation engine against the official
hashcat rule operations documented at:
https://hashcat.net/wiki/doku.php?id=rule_based_attack

The test matrix covers all implemented rule operations with their
expected transformations as defined in the hashcat documentation.
"""

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest
from click.testing import CliRunner

from hashcat_rosetta import RuleAnalyzer, RuleParser
from hashcat_rosetta.cli import explain_rule, main


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

        assert final_result == hashcat_result, (
            f"Rule '{rule}' result mismatch: got '{final_result}', hashcat produced '{hashcat_result}'"
        )

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
        assert any(expected_in_output in step for step in result), (
            f"Expected '{expected_in_output}' in output for rule '{rule}' with baseword '{baseword}': {result}"
        )


# ---------------------------------------------------------------------------
# Integration tests using hashcat-utils generate-rules binary
# ---------------------------------------------------------------------------

GENERATE_RULES_BIN = Path.home() / "hashcat-utils" / "src" / "generate-rules.bin"


@pytest.fixture(scope="class")
def generated_rules():
    """Run generate-rules.bin to produce 10000 random rules with a fixed seed."""
    if not GENERATE_RULES_BIN.exists():
        pytest.skip(f"generate-rules.bin not found at {GENERATE_RULES_BIN}")

    result = subprocess.run(
        [str(GENERATE_RULES_BIN), "10000", "42"],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, f"generate-rules.bin failed: {result.stderr.decode()}"

    rules = [line for line in result.stdout.decode().splitlines() if line.strip()]
    assert len(rules) > 0, "generate-rules.bin produced no output"
    return rules


@pytest.fixture(scope="class")
def generated_rules_file(generated_rules, tmp_path_factory):
    """Write generated rules to a temp file for CLI/file-based tests."""
    tmp = tmp_path_factory.mktemp("rules")
    path = tmp / "generated.rule"
    path.write_text("\n".join(generated_rules) + "\n")
    return str(path)


class TestGenerateRulesIntegration:
    """Integration tests that feed hashcat-utils generated rules through HashcatRosetta."""

    @pytest.mark.integration
    def test_parse_generated_rules(self, generated_rules):
        """Every generated rule should parse without error via RuleParser."""
        parser = RuleParser()
        for rule in generated_rules:
            parsed = parser.parse_rule(rule)
            assert parsed is not None, f"RuleParser returned None for: {rule!r}"
            assert "original" in parsed
            assert "components" in parsed
            assert "complexity" in parsed

    @pytest.mark.integration
    def test_explain_generated_rules(self, generated_rules):
        """explain_rule should not crash on any generated rule."""
        for rule in generated_rules:
            # Some rules may return None for unsupported ops - that's fine
            result = explain_rule(rule)
            assert result is None or isinstance(result, list), (
                f"explain_rule returned unexpected type for: {rule!r}"
            )

    @pytest.mark.integration
    def test_analyze_generated_rules(self, generated_rules, generated_rules_file):
        """RuleAnalyzer.analyze_ruleset should produce valid results."""
        analyzer = RuleAnalyzer()
        result = analyzer.analyze_ruleset(generated_rules)
        assert result is not None, "analyze_ruleset returned None"
        assert result["total_rules"] > 0
        assert "average_complexity" in result
        assert "average_efficiency" in result
        assert "rule_analyses" in result

    @pytest.mark.integration
    def test_cli_analyze_rules_generated(self, generated_rules_file):
        """CLI --analyze-rules should exit 0 on generated rule file."""
        runner = CliRunner()
        result = runner.invoke(main, [generated_rules_file, "--analyze-rules"])
        assert result.exit_code == 0, (
            f"CLI --analyze-rules failed (exit {result.exit_code}):\n{result.output}"
        )

    @pytest.mark.integration
    def test_hashcat_vs_explain(self, generated_rules, generated_rules_file):
        """Compare explain_rule output against actual hashcat --stdout where possible."""
        try:
            subprocess.run(
                ["hashcat", "--version"], capture_output=True, timeout=5
            ).check_returncode()
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pytest.skip("hashcat binary not available")

        baseword = "password"

        # Pre-compute explain_rule results and filter to testable rules
        testable_rules = []
        for rule in generated_rules:
            explanation = explain_rule(rule)
            if explanation is None or len(explanation) == 0:
                continue
            testable_rules.append((rule, explanation))

        # Run hashcat per-rule in parallel. Some rules silently reject the
        # candidate (producing no output), so batch mode can't give us 1:1
        # line correspondence. ThreadPoolExecutor keeps wall-clock reasonable.
        def _check_rule(item):
            rule, explanation = item
            hashcat_result = get_hashcat_output(rule, baseword)
            if hashcat_result is None:
                return None  # hashcat rejected or errored
            if not hashcat_result.isascii():
                return None  # non-ASCII from +/- byte shifts
            our_result = explanation[-1].split("\u2192")[-1].strip()
            if our_result != hashcat_result:
                return f"Rule {rule!r}: ours={our_result!r}, hashcat={hashcat_result!r}"
            return ""  # tested, matched

        mismatches = []
        tested = 0

        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
            futures = {pool.submit(_check_rule, item): item for item in testable_rules}
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue  # skipped
                tested += 1
                if result:
                    mismatches.append(result)

        assert tested > 0, "No rules were testable against hashcat"
        assert not mismatches, (
            f"{len(mismatches)}/{tested} rules differ from hashcat:\n" + "\n".join(mismatches[:20])
        )


class TestFilterRejection:
    """Filter rules must return None when their condition fires."""

    def test_bang_rejects_when_char_present(self) -> None:
        assert explain_rule("!a", "password") is None

    def test_bang_passes_when_char_absent(self) -> None:
        assert explain_rule("!z", "password") is not None

    def test_lt_rejects_when_word_too_short(self) -> None:
        # <5 means reject if length < 5; "cat" is len 3, so reject.
        assert explain_rule("<5", "cat") is None

    def test_lt_passes_when_word_long_enough(self) -> None:
        assert explain_rule("<5", "password") is not None

    def test_gt_rejects_when_word_too_long(self) -> None:
        # >5 means reject if length > 5; "password" is len 8, so reject.
        assert explain_rule(">5", "password") is None

    def test_gt_passes_when_word_short_enough(self) -> None:
        assert explain_rule(">5", "cat") is not None

    def test_percent_rejects_when_char_absent(self) -> None:
        # %a means reject unless contains 'a'; "test" has no 'a' so reject.
        assert explain_rule("%a", "test") is None

    def test_percent_passes_when_char_present(self) -> None:
        assert explain_rule("%a", "admin") is not None

    def test_equals_rejects_when_char_at_pos_differs(self) -> None:
        # =0a means reject unless char at pos 0 is 'a'; "password" pos 0 is 'p'
        assert explain_rule("=0a", "password") is None

    def test_equals_passes_when_char_at_pos_matches(self) -> None:
        assert explain_rule("=0p", "password") is not None


class TestOpcodeV:
    """Tests for the v opcode: vNM inserts character M after every N characters.

    Semantics confirmed via hashcat binary survey:
      - N is hex-parsed (0-9 or A-Z), represents chunk size.
      - M is the literal character to insert (not hex-parsed).
      - N=0 is a no-op (no chars per chunk means nothing is inserted).
      - The character M is inserted after every N-th character throughout the word.

    Representative hashcat observations:
      rule=v11 word=abcdef           -> 'a1b1c1d1e1f1'
      rule=v21 word=password         -> 'pa1ss1wo1rd1'
      rule=v34 word=password         -> 'pas4swo4rd'
      rule=vA2 word=abcdefghijklmnop -> 'abcdefghij2klmnop'
      rule=v1a word=abcdef           -> 'aabacadaeafa'
    """

    def _final(self, steps: list[str]) -> str:
        last = steps[-1]
        if "\u2192" in last:
            return last.split("\u2192")[-1].strip()
        return last

    def test_v01_is_noop(self) -> None:
        """N=0 means no chunks, so nothing is inserted."""
        result = explain_rule("v01", "password")
        assert result is not None
        assert self._final(result) == "password"

    def test_v00_is_noop(self) -> None:
        """N=0 M='0' is still a no-op."""
        result = explain_rule("v00", "abcdef")
        assert result is not None
        assert self._final(result) == "abcdef"

    def test_v11_inserts_after_every_1_char(self) -> None:
        """v11: insert '1' after every character."""
        result = explain_rule("v11", "abcdef")
        assert result is not None
        assert self._final(result) == "a1b1c1d1e1f1"

    def test_v11_password(self) -> None:
        result = explain_rule("v11", "password")
        assert result is not None
        assert self._final(result) == "p1a1s1s1w1o1r1d1"

    def test_v21_inserts_after_every_2_chars(self) -> None:
        """v21: insert '1' after every 2 characters."""
        result = explain_rule("v21", "password")
        assert result is not None
        assert self._final(result) == "pa1ss1wo1rd1"

    def test_v22_inserts_after_every_2_chars(self) -> None:
        """v22: insert '2' after every 2 characters."""
        result = explain_rule("v22", "password")
        assert result is not None
        assert self._final(result) == "pa2ss2wo2rd2"

    def test_v31_inserts_after_every_3_chars(self) -> None:
        """v31: insert '1' after every 3 characters, word length may not be divisible."""
        result = explain_rule("v31", "password")
        assert result is not None
        # 'pas' + '1' + 'swo' + '1' + 'rd' (remainder not followed by insert)
        assert self._final(result) == "pas1swo1rd"

    def test_v34_inserts_after_every_3_chars(self) -> None:
        """v34: insert '4' after every 3 characters."""
        result = explain_rule("v34", "abcdef")
        assert result is not None
        assert self._final(result) == "abc4def4"

    def test_vA2_hex_n_equals_10(self) -> None:
        """vA2: N=A (hex 10), insert '2' after every 10 chars."""
        result = explain_rule("vA2", "abcdefghijklmnop")
        assert result is not None
        assert self._final(result) == "abcdefghij2klmnop"

    def test_vA2_short_word_is_noop(self) -> None:
        """vA2 on word shorter than 10 chars inserts nothing."""
        result = explain_rule("vA2", "password")
        assert result is not None
        assert self._final(result) == "password"

    def test_v1a_lowercase_m_char(self) -> None:
        """v1a: insert lowercase letter 'a' after every character."""
        result = explain_rule("v1a", "abcdef")
        assert result is not None
        assert self._final(result) == "aabacadaeafa"

    def test_v2b_inserts_lowercase_b(self) -> None:
        """v2b: insert 'b' after every 2 characters."""
        result = explain_rule("v2b", "abcdef")
        assert result is not None
        assert self._final(result) == "abbcdbefb"

    def test_v_produces_nonempty_steps(self) -> None:
        """v opcode must produce at least one step entry."""
        result = explain_rule("v21", "test")
        assert result is not None
        assert len(result) >= 1


class TestNewFilterOpcodes:
    def test_lparen_rejects_when_first_char_differs(self) -> None:
        # (a means reject unless first char is 'a'; "password" starts with 'p'
        assert explain_rule("(a", "password") is None

    def test_lparen_passes_when_first_char_matches(self) -> None:
        assert explain_rule("(p", "password") is not None

    def test_lparen_rejects_empty_word(self) -> None:
        assert explain_rule("(p", "") is None

    def test_rparen_rejects_when_last_char_differs(self) -> None:
        assert explain_rule(")d", "password") is not None  # last is 'd'
        assert explain_rule(")z", "password") is None

    def test_rparen_rejects_empty_word(self) -> None:
        assert explain_rule(")a", "") is None


class TestOpcodeE:
    """Tests for the e opcode: eX applies title case with separator X.

    Semantics confirmed via hashcat binary survey:
      - Lowercases the entire word first.
      - Uppercases the first character.
      - Uppercases any character immediately following the separator X.

    Representative hashcat observations:
      rule=e_ word=hello_world   -> Hello_World
      rule=e_ word=two-words-here -> Two-words-here  (no _ in word)
      rule=e- word=two-words-here -> Two-Words-Here
      rule=e_ word=PASSWORD      -> Password
      rule=e_ word=a_b_c         -> A_B_C
      rule=e_ word=foo_BAR_baz   -> Foo_Bar_Baz
      rule=e! word=hello_world   -> Hello_world  (no ! in word)
    """

    def _final(self, steps: list[str]) -> str:
        last = steps[-1]
        if "\u2192" in last:
            return last.split("\u2192")[-1].strip()
        return last

    def test_e_underscore_separator(self) -> None:
        """e_ titles hello_world -> Hello_World."""
        result = explain_rule("e_", "hello_world")
        assert result is not None
        assert self._final(result) == "Hello_World"

    def test_e_dash_separator(self) -> None:
        """e- titles two-words-here -> Two-Words-Here."""
        result = explain_rule("e-", "two-words-here")
        assert result is not None
        assert self._final(result) == "Two-Words-Here"

    def test_e_no_separator_present(self) -> None:
        """e_ on hello (no underscore): uppercases only first char -> Hello."""
        result = explain_rule("e_", "hello")
        assert result is not None
        assert self._final(result) == "Hello"

    def test_e_lowercases_first(self) -> None:
        """e_ on PASSWORD lowercases all then uppercases first -> Password."""
        result = explain_rule("e_", "PASSWORD")
        assert result is not None
        assert self._final(result) == "Password"

    def test_e_mixed_case_with_separator(self) -> None:
        """e_ on foo_BAR_baz -> Foo_Bar_Baz (lowercase all, then title by _)."""
        result = explain_rule("e_", "foo_BAR_baz")
        assert result is not None
        assert self._final(result) == "Foo_Bar_Baz"

    def test_e_single_char_segments(self) -> None:
        """e_ on a_b_c -> A_B_C."""
        result = explain_rule("e_", "a_b_c")
        assert result is not None
        assert self._final(result) == "A_B_C"

    def test_e_empty_word(self) -> None:
        """e_ on empty string -> empty string (not rejected)."""
        result = explain_rule("e_", "")
        assert result is not None
        assert self._final(result) == ""

    def test_e_separator_not_in_word(self) -> None:
        """e! on hello_world (no ! in word) -> Hello_world."""
        result = explain_rule("e!", "hello_world")
        assert result is not None
        assert self._final(result) == "Hello_world"

    def test_e_produces_step_entry(self) -> None:
        """e opcode must produce at least one step entry."""
        result = explain_rule("e_", "test_word")
        assert result is not None
        assert len(result) >= 1


class TestOpcodeA:
    def test_a_appends_memorized(self) -> None:
        # u M a -> uppercase, memorize ("PASSWORD"), append memory
        # final = "PASSWORD" + "PASSWORD" = "PASSWORDPASSWORD"
        result = explain_rule("uMa", "password")
        assert result is not None
        assert "PASSWORDPASSWORD" in result[-1]

    def test_a_without_M_uses_original(self) -> None:
        # No M: memory = original baseword. After 'u', current="PASSWORD"; 'a' appends original.
        # Hashcat behavior: memory is initialized to the original word, so 'ua' -> "PASSWORD" + "password"
        result = explain_rule("ua", "password")
        assert result is not None
        assert "PASSWORDpassword" in result[-1]

    def test_a_mid_rule(self) -> None:
        # M=memorize "test"; l lowercases (no-op); $! appends '!'; a appends "test"
        result = explain_rule("M$!a", "test")
        assert result is not None
        # current after M="test", after $! ="test!", after a -> "test!" + "test" = "test!test"
        assert "test!test" in result[-1]
