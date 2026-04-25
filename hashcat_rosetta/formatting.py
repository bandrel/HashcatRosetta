"""Formatting utilities for hashcat rule analysis."""

from collections import Counter

import click

from .parser import RuleParser


# Hashcat rule opcode descriptions
OPCODE_DESCRIPTIONS = {
    ":": "Do nothing",
    "l": "Lowercase all characters",
    "u": "Uppercase all characters",
    "c": "Capitalize the first letter",
    "C": "Invert capitalize",
    "t": "Toggle case for all chars",
    "T": "Toggle case at pos N",
    "d": "Duplicate entire word",
    "p": "Append duplicated word N times",
    "f": "Duplicate reversed (reflection)",
    "{": "Rotate left",
    "}": "Rotate right",
    "[": "Delete first character",
    "]": "Delete last character",
    "D": "Delete character at pos N",
    "x": "Extract M chars from pos N",
    "O": "Omit M characters starting at pos N",
    "s": "Substitute character X with Y",
    "@": "Purge all instances of char X",
    "Z": "Duplicate last character N times",
    "z": "Duplicate first character N times",
    "i": "Insert character Y at pos N",
    "o": "Overwrite character at pos N with X",
    "^": "Prepend character X",
    "$": "Append character X",
    "q": "Duplicate every character",
    "X": "Insert from memory: M chars at pos N inserted at pos I",
    "*": "Swap characters at pos N and pos M",
    "k": "Swap first two characters",
    "K": "Swap last two characters",
    "r": "Reverse entire word",
    "R": "Bitwise shift right character at pos N",
    "L": "Bitwise shift left character at pos N",
    "S": "Case swap all",
    "y": "Duplicate first N characters",
    "Y": "Duplicate last N characters",
    "e": "Title case with separator char",
    "B": "Extract range from memory",
    "h": "Lowercase first char, uppercase rest (alias for C)",
    "H": "Uppercase first char, lowercase rest (alias for c)",
    "E": "Title case (uppercase first letter and letters after spaces)",
    "v": "Delete words of length <= N",
    "M": "Memorize current word",
    "m": "Append from memory",
    "4": "4-to-3 leetspeak (convert)",
    "3": "Toggle case at separator char",
    "5": "5-to-3 leetspeak",
    "7": "7-to-3 leetspeak",
    "9": "9-to-5 leetspeak",
    ">": "Reject plains if length is greater than N",
    "<": "Reject plains if length is less than N",
    "!": "Reject plains which contain char X",
    "'": "Truncate word at pos N",
    "+": "Increment character at pos N by 1 ASCII value",
    "-": "Decrement character at pos N by 1 ASCII value",
    ".": "Replace char at pos N with value at pos N+1",
    ",": "Replace char at pos N with value at pos N-1",
    "%": "Reject plains which contain char X less than N times",
    "=": "Reject plains which do not have char X at pos N",
    "(": "Reject plains which do not start with char X",
    ")": "Reject plains which do not end with char X",
    "w": "Leet speak conversion",
    "W": "Reverse leet speak conversion",
    "6": "Prepend memory buffer to beginning of current word",
    "Q": "Reject if current word matches memorized word",
    "a": "No-op stub (RULE_OP_MANGLE_TOGGLECASE_REC unimplemented in hashcat)",
}


def extract_rule_opcodes(rule_file: str) -> tuple[dict[str, int], int]:
    """
    Extract and count unique opcodes from a rule file.

    Args:
        rule_file: Path to the rule file

    Returns:
        Tuple of (opcode counts dict, number of rules in file)
    """
    opcodes: Counter[str] = Counter()
    parser = RuleParser()
    rule_count = 0

    with open(rule_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            rule_count += 1
            # Tokenize the full rule and count the opcode (first char) of each token
            tokens = parser._tokenize_rule(line)
            for token in tokens:
                opcodes[token[0]] += 1

    return dict(opcodes), rule_count


def display_rule_opcodes_summary(rule_file: str, title: str = "Rule Opcode Analysis") -> None:
    """
    Extract and display a formatted summary of opcodes in a rule file.

    Args:
        rule_file: Path to the rule file to analyze
        title: Title for the output table
    """
    opcodes, rule_count = extract_rule_opcodes(rule_file)

    if not opcodes:
        click.echo(f"No opcodes found in {rule_file}")
        return

    total_occurrences = sum(opcodes.values())

    # Sort by frequency (descending)
    sorted_opcodes = sorted(opcodes.items(), key=lambda x: x[1], reverse=True)

    # Print header
    click.echo(f"\n{title}")
    click.echo(f"File: {rule_file}")
    click.echo(f"Total rules analyzed: {rule_count}")
    click.echo(f"Total opcode tokens: {total_occurrences}\n")

    # Print table header
    click.echo(f"{'Opcode':<8} {'Count':<10} {'Percentage':<12} {'Description':<40}")
    click.echo("-" * 70)

    # Print each opcode
    for opcode, count in sorted_opcodes:
        percentage = (count / total_occurrences) * 100
        description = OPCODE_DESCRIPTIONS.get(opcode, "Unknown opcode")
        click.echo(f"{opcode:<8} {count:<10} {percentage:>6.2f}%{' ':<4} {description:<40}")

    click.echo("-" * 70)
    click.echo(f"{'TOTAL':<8} {total_occurrences:<10}")
