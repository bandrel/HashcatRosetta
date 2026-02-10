"""Formatting utilities for hashcat rule analysis."""

import re
from pathlib import Path
from collections import Counter
from typing import Dict, Tuple


# Hashcat rule opcode descriptions
OPCODE_DESCRIPTIONS = {
    ':': 'Do nothing',
    'l': 'Lowercase all characters',
    'u': 'Uppercase all characters',
    'c': 'Capitalize the first letter',
    'C': 'Invert capitalize',
    't': 'Toggle case for all chars',
    'T': 'Toggle case at pos X',
    'd': 'Duplicate entire word',
    'p': 'Duplicate word N times',
    'f': 'Reverse word',
    '{': 'Rotate left',
    '}': 'Rotate right',
    '[': 'Delete first character',
    ']': 'Delete last character',
    'D': 'Delete character at pos X',
    'x': 'Extract N chars from pos X',
    'O': 'Omit character at pos X',
    's': 'Substitute character X with Y',
    '@': 'Purge all instances of char X',
    'Z': 'Zap (remove) character at pos X',
    'z': 'Zap character not at pos X',
    'i': 'Insert character Y at pos X',
    'o': 'Overwrite character at pos X',
    'a': 'Append character X',
    '^': 'Prepend character X',
    'q': 'Invert exclamation marks',
    'X': 'Swap char at pos X with pos 1',
    '*': 'Swap 2 characters at pos X and Y',
    'k': 'Swap position X with position Y',
    'r': 'Rotate word right',
    'R': 'Rotate word left',
    'S': 'Case swap all',
    'E': 'Delete all duplicate chars',
    'v': 'Delete words of length <= X',
    'M': 'Memorize word',
    'm': 'Append from memory',
    '4': '4-to-3 leetspeak (convert)',
    '3': '3-to-4 leetspeak (revert)',
    '5': '5-to-3 leetspeak',
    '7': '7-to-3 leetspeak',
    '9': '9-to-5 leetspeak',
    'L': 'Delete last N characters',
    '>': 'Delete everything beyond N',
    '<': 'Keep only first N',
    '!': 'Negate (not X)',
    '=': 'Position check char at X',
    '(': 'Position check less than',
    ')': 'Position check greater than',
    '%': 'Check word contains char X',
    '^': 'Check word starts with char X',
    '$': 'Check word ends with char X',
    'w': 'Leet speak conversion',
    'W': 'Reverse leet speak',
}


def extract_rule_opcodes(rule_file: str) -> Dict[str, int]:
    """
    Extract and count unique opcodes from a rule file.
    
    Args:
        rule_file: Path to the rule file
        
    Returns:
        Dictionary with opcode counts
    """
    opcodes = Counter()
    
    try:
        with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Extract first character as the primary opcode
                # This represents the operation being performed
                primary_opcode = line[0]
                opcodes[primary_opcode] += 1
    except FileNotFoundError:
        return {}
    
    return dict(opcodes)


def display_rule_opcodes_summary(rule_file: str, title: str = "Rule Opcode Analysis") -> None:
    """
    Extract and display a formatted summary of opcodes in a rule file.
    
    Args:
        rule_file: Path to the rule file to analyze
        title: Title for the output table
    """
    opcodes = extract_rule_opcodes(rule_file)
    
    if not opcodes:
        print(f"No opcodes found in {rule_file}")
        return
    
    total_occurrences = sum(opcodes.values())
    
    # Sort by frequency (descending)
    sorted_opcodes = sorted(opcodes.items(), key=lambda x: x[1], reverse=True)
    
    # Print header
    print(f"\n{title}")
    print(f"File: {rule_file}")
    print(f"Total rules: {total_occurrences}\n")
    
    # Print table header
    print(f"{'Opcode':<8} {'Count':<10} {'Percentage':<12} {'Description':<40}")
    print("-" * 70)
    
    # Print each opcode
    for opcode, count in sorted_opcodes:
        percentage = (count / total_occurrences) * 100
        description = OPCODE_DESCRIPTIONS.get(opcode, 'Unknown opcode')
        print(f"{opcode:<8} {count:<10} {percentage:>6.2f}%{' ':<4} {description:<40}")
    
    print("-" * 70)
    print(f"{'TOTAL':<8} {total_occurrences:<10}")
