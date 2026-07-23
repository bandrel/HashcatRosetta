"""Parser module for hashcat rules and debug files."""

import logging

logger = logging.getLogger(__name__)


# Sentinel wordlist values hashcat emits when there is no real dict path.
_WORDLIST_SENTINELS = frozenset({"<stdin>", "<generic>", "<none>"})
# Extensions commonly used for wordlist files, used by mode auto-detection.
_WORDLIST_EXTENSIONS = (".txt", ".dict", ".lst", ".wordlist")
# Number of leading non-empty, non-comment lines sampled for format/mode
# auto-detection.
_DETECTION_SAMPLE_SIZE = 20


class DebugLogParser:
    """Parse hashcat debug mode 4 and mode 5 output files.

    Mode 4 lines are ``baseword:rule:candidate`` (or the legacy space-separated
    ``baseword rule candidate``). Mode 5 adds a trailing WORDLIST field:
    ``baseword:rule:candidate:wordlist`` where wordlist is the dict path or one
    of the sentinels ``<stdin>``/``<generic>``/``<none>``.

    Colon-in-data limitation: hashcat does not escape colons, so basewords,
    candidates, and Windows drive-letter wordlist paths (``C:\\...``) may contain
    ``:``. This parser keeps the existing mode-4 assumption (baseword has no
    colon; candidate may contain colons) and additionally assumes the wordlist
    field (the LAST field) has no colon. That holds for Linux paths and the
    sentinels; Windows drive-letter paths are a known, documented limitation,
    mitigated by passing an explicit ``debug_mode`` override.
    """

    def __init__(self, debug_mode: int | None = None):
        """Initialize the debug log parser.

        Args:
            debug_mode: Optional override for the hashcat debug mode. ``None``
                auto-detects, ``4`` forces mode-4 parsing (no wordlist field),
                ``5`` forces mode-5 parsing (trailing wordlist field). An
                explicit override always wins over auto-detection.
        """
        self.debug_mode: int | None = debug_mode
        self.entries: list = []
        self._format: str | None = None  # "space" or "colon", detected per file/batch
        self._mode: int | None = None  # 4 or 5, detected per file/batch (colon only)

    def parse_debug_file(self, filepath: str) -> list:
        """
        Parse a hashcat debug mode 4 or mode 5 file.

        Mode 4 format: baseword:rule:candidate (or space-separated)
        Mode 5 format: baseword:rule:candidate:wordlist
        Example (mode 4): password c P@ssword
        Example (mode 5): password:c:P@ssword:rockyou.txt

        The format (space vs colon) and debug mode (4 vs 5) are auto-detected
        from a sample of lines unless an explicit ``debug_mode`` was passed to
        the constructor.

        Args:
            filepath: Path to the debug file

        Returns:
            List of parsed entries with structure:
            {
                'baseword': str,
                'rule': str,
                'candidate': str,
                'wordlist': str | None (dict path/sentinel for mode 5, else None),
                'matched': bool (whether candidate matched a hash)
            }
        """
        entries: list = []
        line_num = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                # Read all lines for format detection
                all_lines = f.readlines()

            # Detect format and mode from a sample of lines
            sample = [
                line.strip() for line in all_lines if line.strip() and not line.startswith("#")
            ]
            self._format = self._detect_format(sample)
            self._mode = self._resolve_mode(sample)

            for line_num, line in enumerate(all_lines, 1):
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
        elif line_num > 10 and len(entries) < line_num * 0.1:
            # Less than 10% of lines parsed successfully
            logger.warning(
                "Only %d of %d lines were parsed successfully. "
                "This file may not be in the expected --debug-mode 4 format.",
                len(entries),
                line_num,
            )

        self.entries = entries
        return entries

    def _detect_format(self, lines: list[str]) -> str:
        """
        Detect whether the file uses space-separated or colon-separated format.

        Samples up to _DETECTION_SAMPLE_SIZE non-empty, non-comment lines. Uses heuristics
        to distinguish between the two formats:
        - If space-split produces 3+ parts with a clean baseword (no colons),
          it is space-separated.
        - If colon-split produces 3 non-empty parts and space-split either fails
          or produces a baseword containing colons, it is colon-separated.

        Args:
            lines: List of stripped, non-empty, non-comment lines

        Returns:
            "colon" or "space"
        """
        sample = lines[:_DETECTION_SAMPLE_SIZE]
        if not sample:
            return "space"

        colon_votes = 0
        space_votes = 0
        for line in sample:
            space_parts = line.split(maxsplit=2)
            colon_parts = line.split(":", 2)

            has_space_format = len(space_parts) >= 3
            has_colon_format = len(colon_parts) == 3 and all(p for p in colon_parts)

            if has_colon_format and not has_space_format:
                # Only colon format works
                colon_votes += 1
            elif has_space_format and not has_colon_format:
                # Only space format works
                space_votes += 1
            elif has_space_format and has_colon_format:
                # Both formats parse - use heuristic: if the space-split baseword
                # contains a colon, the line is more likely colon-separated
                if ":" in space_parts[0]:
                    colon_votes += 1
                else:
                    space_votes += 1

        return "colon" if colon_votes > space_votes else "space"

    def _resolve_mode(self, lines: list[str]) -> int:
        """Resolve the debug mode, honoring an explicit override.

        The explicit ``debug_mode`` override always wins. Mode detection only
        applies to colon format; space format is always treated as mode-4-style
        (3 fields, wordlist=None).

        Args:
            lines: List of stripped, non-empty, non-comment lines

        Returns:
            4 or 5
        """
        if self.debug_mode is not None:
            return self.debug_mode
        if self._format != "colon":
            return 4
        return self._detect_mode(lines)

    @staticmethod
    def _looks_like_wordlist(field: str) -> bool:
        """Return True if a trailing field looks like a hashcat wordlist value."""
        if field in _WORDLIST_SENTINELS:
            return True
        if "/" in field or "\\" in field:
            return True
        return any(field.endswith(ext) for ext in _WORDLIST_EXTENSIONS)

    def _detect_mode(self, lines: list[str]) -> int:
        """Auto-detect mode 4 vs mode 5 for colon-format lines.

        Uses a majority vote over the sample (mirroring _detect_format): a line
        votes mode 5 when it has >= 3 colons AND its trailing colon-separated
        field looks like a wordlist -- a sentinel, or path-like (contains a
        slash or a common wordlist extension). If the majority of sampled lines
        vote mode 5 the file is mode 5, otherwise mode 4. Voting tolerates the
        occasional odd line (e.g. a candidate ending in ':' or a wordlist with
        no recognized extension) without flipping the whole file.

        Args:
            lines: List of stripped, non-empty, non-comment lines

        Returns:
            4 or 5
        """
        sample = lines[:_DETECTION_SAMPLE_SIZE]
        if not sample:
            return 4

        mode_five_votes = 0
        for line in sample:
            if line.count(":") < 3:
                continue
            last_field = line.rsplit(":", 1)[1]
            if self._looks_like_wordlist(last_field):
                mode_five_votes += 1

        return 5 if mode_five_votes > len(sample) / 2 else 4

    def _parse_line(self, line: str) -> dict | None:
        """
        Parse a single debug log line.

        Format can be either:
          - Space-separated: baseword rule candidate
          - Colon-separated: baseword:rule:candidate

        The format is determined at the file/batch level by _detect_format().
        When no format has been detected (standalone calls), both formats are
        tried with space-separated preferred.

        Args:
            line: A line from the debug file

        Returns:
            Dictionary with parsed components or None if line is invalid
        """
        if not line or line.startswith("#"):
            return None

        fmt = self._format

        if fmt == "colon":
            return self._parse_colon_line(line)
        elif fmt == "space":
            return self._parse_space_line(line)
        else:
            # No format detected yet (standalone _parse_line call) -
            # detect from this single line using the same heuristic
            detected = self._detect_format([line])
            if detected == "colon":
                self._mode = self._resolve_mode([line])
                return self._parse_colon_line(line)
            return self._parse_space_line(line)

    def _parse_colon_line(self, line: str) -> dict | None:
        """Parse a colon-separated debug line (mode 4 or mode 5)."""
        if ":" not in line:
            return None

        mode = self.debug_mode if self.debug_mode is not None else self._mode

        if mode == 5:
            parts = line.split(":", 2)
            if len(parts) != 3:
                return None
            baseword, rule, remainder = parts
            candidate, sep, wordlist = remainder.rpartition(":")
            if not sep:
                # remainder had no colon: this line has only 3 fields and no
                # wordlist. Under forced/detected mode 5 that is malformed --
                # skip it rather than silently misassigning the candidate.
                logger.warning("Skipping malformed mode-5 line (missing wordlist field): %r", line)
                return None
            if not baseword and not rule and not candidate and not wordlist:
                return None
            return {
                "baseword": baseword,
                "rule": rule,
                "candidate": candidate,
                "wordlist": wordlist,
                "matched": False,
            }

        parts = line.split(":", 2)
        if len(parts) != 3:
            return None
        baseword, rule, candidate = parts
        if not baseword and not rule and not candidate:
            return None
        return {
            "baseword": baseword,
            "rule": rule,
            "candidate": candidate,
            "wordlist": None,
            "matched": False,
        }

    def _parse_space_line(self, line: str) -> dict | None:
        """Parse a space-separated debug line."""
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
            "wordlist": None,
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
        # Detect format from the batch of lines
        stripped = [line.strip() for line in lines if line and line.strip()]
        non_comment = [line for line in stripped if not line.startswith("#")]
        self._format = self._detect_format(non_comment)
        self._mode = self._resolve_mode(non_comment)

        entries: list = []
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
        - No-arg ops: : l u c C t d f r { } [ ] k K q E M m S w W h H 3 4 5 7 9
        - 1-arg ops (opcode + 1 char): T D p y Y e z Z ^ $ @ ! > < ' + - . , % L R a ( )
        - 2-arg ops (opcode + 2 chars): s o i * x X = v O B
        """
        # No-argument operations (single character, no parameters)
        no_arg_ops = set(":lucCtdfr{}[]kKqEMmSwWhH34579")
        # 1-argument operations (opcode + 1 parameter character)
        one_arg_ops = set("TDpyYezZ^$@!><'+-.,%LRa()")
        # 2-argument operations (opcode + 2 parameter characters)
        two_arg_ops = set("soix*X=vOB")

        tokens: list = []
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
                    logger.warning(
                        f"Incomplete 2-arg opcode '{char}' at position {i} "
                        f"in rule '{rule_string}' - missing parameter(s), skipping"
                    )
                    i += 1
            elif char in one_arg_ops:
                if i + 1 < len(rule_string):
                    tokens.append(rule_string[i : i + 2])
                    i += 2
                else:
                    logger.warning(
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
