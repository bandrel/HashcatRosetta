"""Parser module for hashcat rules and debug files."""

import warnings


class DebugLogParser:
    """Parse hashcat debug mode 4 output files."""

    def __init__(self):
        """Initialize the debug log parser."""
        self.entries = []

    def parse_debug_file(self, filepath: str) -> list:
        """
        Parse a hashcat debug mode 4 file.

        Format: baseword rule candidate
        Example: password c P@ssword

        Args:
            filepath: Path to the debug file

        Returns:
            List of parsed entries with structure:
            {
                'baseword': str,
                'rule': str,
                'candidate': str,
                'matched': bool (whether candidate matched a hash)
            }
        """
        entries = []
        total_lines = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    total_lines += 1
                    parsed = self._parse_line(line.strip())
                    if parsed:
                        parsed["line_number"] = line_num
                        entries.append(parsed)
        except FileNotFoundError:
            raise FileNotFoundError(f"Debug file not found: {filepath}")
        except (TypeError, AttributeError, IsADirectoryError, PermissionError, ValueError):
            raise
        except Exception as e:
            raise Exception(f"Error parsing debug file: {e}")

        # Validate that we parsed something meaningful
        if len(entries) == 0:
            raise ValueError(
                f"No valid debug entries found in {filepath}.\n"
                f"Expected format: baseword rule candidate (one per line)\n"
                f"Example: password c P@ssword\n\n"
                f"Make sure you're using hashcat with --debug-mode 4:\n"
                f"hashcat -m [mode] -a 0 --debug-mode 4 hashes.txt wordlist.txt -r rules.rule"
            )
        elif total_lines > 10 and len(entries) < total_lines * 0.1:
            # Less than 10% of lines parsed successfully
            warnings.warn(
                f"Only {len(entries)} of {total_lines} lines were parsed successfully. "
                f"This file may not be in the expected --debug-mode 4 format."
            )

        self.entries = entries
        return entries

    def _parse_line(self, line: str) -> dict | None:
        """
        Parse a single debug log line.

        Format can be either:
          - Space-separated: baseword rule candidate
          - Colon-separated: baseword:rule:candidate

        Args:
            line: A line from the debug file

        Returns:
            Dictionary with parsed components or None if line is invalid
        """
        if not line or line.startswith("#"):
            return None

        # Try colon-separated format first (older hashcat versions)
        if ":" in line:
            parts = line.split(":", 2)
            if len(parts) == 3:
                baseword, rule, candidate = parts
                return {
                    "baseword": baseword,
                    "rule": rule,
                    "candidate": candidate,
                    "matched": False,
                }

        # Try space-separated format (newer hashcat --debug-mode 4)
        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            return None

        baseword, rule, candidate = parts[0], parts[1], parts[2]

        # Detect common rule-only patterns that indicate wrong debug mode
        common_rules = set("culrdftE$^[]{}@")
        rule_prefixes = ("s", "i", "o", "T", "+", "-", "*", "x", "O", "D", "'", "z", "Z")

        # If baseword is a single common rule character or starts with rule prefix
        # AND candidate is very short, this is likely wrong format
        if (baseword in common_rules or any(baseword.startswith(p) for p in rule_prefixes)) and len(
            candidate
        ) <= 3:
            return None

        return {
            "baseword": baseword,
            "rule": rule,
            "candidate": candidate,
            "matched": False,
        }

    def parse_debug_lines(self, lines: list) -> list:
        """
        Parse a list of debug output lines.

        Args:
            lines: List of debug output lines

        Returns:
            List of parsed entries
        """
        entries = []
        for line_num, line in enumerate(lines, 1):
            parsed = self._parse_line(line.strip())
            if parsed:
                parsed["line_number"] = line_num
                entries.append(parsed)
        self.entries = entries
        return entries


class RuleParser:
    """Parse and validate hashcat rule syntax."""

    def __init__(self):
        """Initialize the rule parser."""
        self.rules = []
        self.rule_map = {}

    def parse_rule(self, rule_string: str) -> dict | None:
        """
        Parse a single hashcat rule.

        Args:
            rule_string: The rule string to parse

        Returns:
            Dictionary containing parsed rule components
        """
        if not rule_string or rule_string.startswith("#"):
            return None

        rule_string = rule_string.strip()
        if not rule_string:
            return None

        components = self._tokenize_rule(rule_string)

        return {
            "original": rule_string,
            "components": components,
            "complexity": self._calculate_complexity(components),
        }

    def parse_ruleset(self, rules: list) -> list:
        """
        Parse a list of rules.

        Args:
            rules: List of rule strings

        Returns:
            List of parsed rule dictionaries
        """
        parsed_rules = []
        for rule in rules:
            parsed = self.parse_rule(rule)
            if parsed:
                parsed_rules.append(parsed)
        return parsed_rules

    def _tokenize_rule(self, rule_string: str) -> list:
        """Tokenize a rule string into individual operations.

        Supports the full hashcat rule opcode set:
        - No-arg ops: : l u c C t d f r { } [ ] k K q E
        - 1-arg ops (opcode + 1 char): T D p O z Z ^ $ @ ! > < ' + - . , L R
        - 2-arg ops (opcode + 2 chars): s o i * x X
        """
        # No-argument operations (single character, no parameters)
        no_arg_ops = set(":lucCtdfr{}[]kKqE")
        # 1-argument operations (opcode + 1 parameter character)
        one_arg_ops = set("TDpOzZ^$@!><'+-.,%LR")
        # 2-argument operations (opcode + 2 parameter characters)
        two_arg_ops = set("soix*X")

        tokens = []
        i = 0
        while i < len(rule_string):
            char = rule_string[i]

            if char == " ":
                # Spaces are separators, skip
                i += 1
            elif char in two_arg_ops:
                if i + 2 < len(rule_string):
                    tokens.append(rule_string[i : i + 3])
                    i += 3
                else:
                    warnings.warn(
                        f"Incomplete 2-arg opcode '{char}' at position {i} "
                        f"in rule '{rule_string}' - missing parameter(s), skipping"
                    )
                    i += 1
            elif char in one_arg_ops:
                if i + 1 < len(rule_string):
                    tokens.append(rule_string[i : i + 2])
                    i += 2
                else:
                    warnings.warn(
                        f"Incomplete 1-arg opcode '{char}' at position {i} "
                        f"in rule '{rule_string}' - missing parameter, skipping"
                    )
                    i += 1
            elif char in no_arg_ops:
                tokens.append(char)
                i += 1
            else:
                # Unknown opcode, skip
                i += 1

        return tokens

    def _calculate_complexity(self, components: list) -> float:
        """
        Calculate complexity score based on rule components.

        Args:
            components: List of rule components

        Returns:
            Complexity score (0-100)
        """
        if not components:
            return 0.0

        complexity = len(components) * 10.0
        # Bonus for operations that significantly transform the word
        for component in components:
            if not component:
                continue
            op = component[0]
            if op in ("d", "f", "p"):
                # Duplication/reflection ops
                complexity += 5
            elif op in ("x", "X", "O"):
                # Extraction/omission ops
                complexity += 5
            elif op in ("r",):
                # Reverse
                complexity += 3
            elif op in ("s", "*", "i", "o"):
                # Substitution/insertion/swap ops
                complexity += 3

        return min(complexity, 100.0)
