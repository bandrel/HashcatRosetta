"""Command-line interface for the hashcat rule analyzer."""

import csv
import json
import os
import sys

import click

from .debug_analyzer import DebugAnalyzer
from .formatting import display_rule_opcodes_summary

# Prefix used by explain_rule() to signal that a word was rejected by a filter opcode.
# Consumers (e.g. scripts/verify_rules.py) check for this prefix to distinguish a
# rejection sentinel from a normal transformation step.
REJECT_SENTINEL_PREFIX = "REJECTED: "


def explain_rule(rule_str: str, baseword: str = "password") -> list | None:
    """Explain what a hashcat rule does with examples."""
    if not rule_str:
        return None

    # Rule explanations
    rule_map = {
        ":": ("No-op", lambda x: x),
        "c": ("Capitalize", lambda x: x[0].upper() + x[1:].lower() if x else x),
        "u": ("Uppercase all", lambda x: x.upper()),
        "l": ("Lowercase all", lambda x: x.lower()),
        "d": ("Duplicate word", lambda x: x + x),
        "r": ("Reverse", lambda x: x[::-1]),
        "t": ("Toggle case all", lambda x: "".join(c.swapcase() for c in x)),
        "[": ("Remove first", lambda x: x[1:] if x else x),
        "]": ("Remove last", lambda x: x[:-1] if x else x),
        "{": ("Rotate left", lambda x: x[1:] + x[0] if x else x),
        "}": ("Rotate right", lambda x: x[-1] + x[:-1] if x else x),
        "f": ("Reflect (duplicate reversed)", lambda x: (x + x[::-1]) if x else x),
        "k": ("Swap first two", lambda x: x[1] + x[0] + x[2:] if len(x) >= 2 else x),
        "K": ("Swap last two", lambda x: x[:-2] + x[-1] + x[-2] if len(x) >= 2 else x),
        "q": ("Duplicate every char", lambda x: "".join(c + c for c in x)),
        "C": (
            "Invert capitalize",
            lambda x: x[0].lower() + x[1:].upper() if x else x,
        ),
        "E": (
            "Title case",
            lambda x: (
                " ".join(w[0].upper() + w[1:].lower() if w else w for w in x.lower().split(" "))
                if x
                else x
            ),
        ),
    }

    # Parse and apply rules sequentially
    current = baseword
    memorized = baseword  # Default memorized word is the original input
    steps = []
    i = 0

    while i < len(rule_str):
        char = rule_str[i]

        # Handle append: $X - Append character X
        if char == "$" and i + 1 < len(rule_str):
            append_char = rule_str[i + 1]
            prev = current
            current = current + append_char
            steps.append(f"${append_char}: Append '{append_char}' → {prev} → {current}")
            i += 2

        # Handle prepend: ^X - Prepend character X
        elif char == "^" and i + 1 < len(rule_str):
            prepend_char = rule_str[i + 1]
            prev = current
            current = prepend_char + current
            steps.append(f"^{prepend_char}: Prepend '{prepend_char}' → {prev} → {current}")
            i += 2

        # Handle parameterized rules
        elif char == "i" and i + 2 < len(rule_str):
            # Insert: iXY where X is position, Y is character
            pos_char = rule_str[i + 1]
            val_char = rule_str[i + 2]

            try:
                # Convert hex position if needed
                if pos_char.isdigit():
                    pos = int(pos_char)
                else:
                    pos = int(pos_char, 16)

                prev = current
                if pos <= len(current):
                    current = current[:pos] + val_char + current[pos:]
                steps.append(
                    f"i{pos_char}{val_char}: Insert '{val_char}' at pos {pos} → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "s" and i + 2 < len(rule_str):
            # Substitute: sXY where X is source char, Y is replacement
            src = rule_str[i + 1]
            dst = rule_str[i + 2]
            prev = current
            current = current.replace(src, dst)
            steps.append(f"s{src}{dst}: Substitute '{src}' with '{dst}' → {prev} → {current}")
            i += 3

        elif char == "p" and i + 1 < len(rule_str):
            # Duplicate word: pN - append duplicated word N times
            n_char = rule_str[i + 1]
            try:
                n = int(n_char)
                prev = current
                # Hashcat no-ops if result would exceed RP_PASSWORD_SIZE (256)
                if len(current) + len(current) * n < 256:
                    current = current * (n + 1)
                steps.append(f"p{n_char}: Append duplicated word {n} times → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "D" and i + 1 < len(rule_str):
            # Delete: DX where X is position
            pos_char = rule_str[i + 1]
            try:
                if pos_char.isdigit():
                    pos = int(pos_char)
                else:
                    pos = int(pos_char, 16)
                prev = current
                if pos < len(current):
                    current = current[:pos] + current[pos + 1 :]
                steps.append(f"D{pos_char}: Delete at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "T" and i + 1 < len(rule_str):
            # Toggle at position: TX
            pos_char = rule_str[i + 1]
            try:
                if pos_char.isdigit():
                    pos = int(pos_char)
                else:
                    pos = int(pos_char, 16)
                prev = current
                if pos < len(current):
                    current = current[:pos] + current[pos].swapcase() + current[pos + 1 :]
                steps.append(f"T{pos_char}: Toggle case at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "O" and i + 2 < len(rule_str):
            # Omit M characters starting at position N
            pos_char = rule_str[i + 1]
            len_char = rule_str[i + 2]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                length = int(len_char, 16) if not len_char.isdigit() else int(len_char)
                prev = current
                if pos < len(current) and pos + length <= len(current):
                    current = current[:pos] + current[pos + length :]
                steps.append(
                    f"O{pos_char}{len_char}: Omit {length} chars at pos {pos} → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "y" and i + 1 < len(rule_str):
            # Duplicate first N characters (prepend)
            n_char = rule_str[i + 1]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                prev = current
                if n <= len(current):
                    current = current[:n] + current
                steps.append(f"y{n_char}: Duplicate first {n} chars → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "Y" and i + 1 < len(rule_str):
            # Duplicate last N characters (append)
            n_char = rule_str[i + 1]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                prev = current
                if n <= len(current):
                    current = current + current[-n:]
                steps.append(f"Y{n_char}: Duplicate last {n} chars → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "z" and i + 1 < len(rule_str):
            # Duplicate first character N times
            n_char = rule_str[i + 1]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                prev = current
                if current:
                    current = current[0] * n + current
                steps.append(f"z{n_char}: Duplicate first char {n} times → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "Z" and i + 1 < len(rule_str):
            # Duplicate last character N times
            n_char = rule_str[i + 1]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                prev = current
                if current:
                    current = current + current[-1] * n
                steps.append(f"Z{n_char}: Duplicate last char {n} times → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "@" and i + 1 < len(rule_str):
            # Purge all instances of char X
            purge_char = rule_str[i + 1]
            prev = current
            current = current.replace(purge_char, "")
            steps.append(f"@{purge_char}: Purge all '{purge_char}' → {prev} → {current}")
            i += 2

        elif char == "!" and i + 1 < len(rule_str):
            # Reject if contains char X (rejection rule)
            reject_char = rule_str[i + 1]
            if reject_char in current:
                sentinel = f"{REJECT_SENTINEL_PREFIX}!{reject_char}: word contains '{reject_char}'"
                steps.append(sentinel)
                return steps
            else:
                steps.append(
                    f"!{reject_char}: Reject-if-contains '{reject_char}'"
                    f" \u2192 passed (word does not contain '{reject_char}')"
                )
            i += 2

        elif char == ">" and i + 1 < len(rule_str):
            # Reject if word length > N
            n_char = rule_str[i + 1]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                if len(current) > n:
                    sentinel = (
                        f"{REJECT_SENTINEL_PREFIX}>{n_char}: word length {len(current)} > {n}"
                    )
                    steps.append(sentinel)
                    return steps
                else:
                    steps.append(
                        f">{n_char}: Reject-if-length-greater-than {n}"
                        f" \u2192 passed (length {len(current)} \u2264 {n})"
                    )
            except ValueError:
                steps.append(f">{n_char}: Reject if length > {n_char} (filter rule)")
            i += 2

        elif char == "<" and i + 1 < len(rule_str):
            # Reject if word length < N
            n_char = rule_str[i + 1]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                if len(current) < n:
                    sentinel = (
                        f"{REJECT_SENTINEL_PREFIX}<{n_char}: word length {len(current)} < {n}"
                    )
                    steps.append(sentinel)
                    return steps
                else:
                    steps.append(
                        f"<{n_char}: Reject-if-length-less-than {n}"
                        f" \u2192 passed (length {len(current)} \u2265 {n})"
                    )
            except ValueError:
                steps.append(f"<{n_char}: Reject if length < {n_char} (filter rule)")
            i += 2

        elif char == "'" and i + 1 < len(rule_str):
            # Truncate word at position N
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                current = current[:pos]
                steps.append(f"'{pos_char}: Truncate at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "+" and i + 1 < len(rule_str):
            # Increment character at position N by 1 (ASCII value)
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if pos < len(current):
                    current = current[:pos] + chr(ord(current[pos]) + 1) + current[pos + 1 :]
                steps.append(f"+{pos_char}: Increment ASCII at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "-" and i + 1 < len(rule_str):
            # Decrement character at position N by 1 (ASCII value)
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if pos < len(current):
                    current = current[:pos] + chr(ord(current[pos]) - 1) + current[pos + 1 :]
                steps.append(f"-{pos_char}: Decrement ASCII at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "." and i + 1 < len(rule_str):
            # Replace char at pos N with char at pos N+1
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if pos < len(current) - 1:
                    current = current[:pos] + current[pos + 1] + current[pos + 1 :]
                steps.append(
                    f".{pos_char}: Replace char at pos {pos} with next → {prev} → {current}"
                )
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "," and i + 1 < len(rule_str):
            # Replace char at pos N with char at pos N-1
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if 0 < pos < len(current):
                    current = current[:pos] + current[pos - 1] + current[pos + 1 :]
                steps.append(
                    f",{pos_char}: Replace char at pos {pos} with prev → {prev} → {current}"
                )
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "%" and i + 1 < len(rule_str):
            # Reject if word does not contain char X (simplified: 1-arg form)
            check_char = rule_str[i + 1]
            if check_char not in current:
                sentinel = (
                    f"{REJECT_SENTINEL_PREFIX}%{check_char}: word does not contain '{check_char}'"
                )
                steps.append(sentinel)
                return steps
            else:
                steps.append(
                    f"%{check_char}: Reject-unless-contains '{check_char}'"
                    f" \u2192 passed (word contains '{check_char}')"
                )
            i += 2

        elif char == "R" and i + 1 < len(rule_str):
            # Bitwise shift right character at position N
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if pos < len(current):
                    current = current[:pos] + chr(ord(current[pos]) >> 1) + current[pos + 1 :]
                steps.append(f"R{pos_char}: Bitwise shift right at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "L" and i + 1 < len(rule_str):
            # Bitwise shift left character at position N
            pos_char = rule_str[i + 1]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if pos < len(current):
                    current = (
                        current[:pos] + chr((ord(current[pos]) << 1) & 0xFF) + current[pos + 1 :]
                    )
                steps.append(f"L{pos_char}: Bitwise shift left at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "o" and i + 2 < len(rule_str):
            # Overwrite character at position X with character Y
            pos_char = rule_str[i + 1]
            val_char = rule_str[i + 2]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                prev = current
                if pos < len(current):
                    current = current[:pos] + val_char + current[pos + 1 :]
                steps.append(
                    f"o{pos_char}{val_char}: Overwrite pos {pos} with "
                    f"'{val_char}' → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "x" and i + 2 < len(rule_str):
            # Extract N characters starting at position M
            pos_char = rule_str[i + 1]
            len_char = rule_str[i + 2]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                length = int(len_char, 16) if not len_char.isdigit() else int(len_char)
                prev = current
                if pos < len(current) and pos + length <= len(current):
                    current = current[pos : pos + length]
                steps.append(
                    f"x{pos_char}{len_char}: Extract {length} chars from "
                    f"pos {pos} → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "*" and i + 2 < len(rule_str):
            # Swap characters at positions X and Y
            pos1_char = rule_str[i + 1]
            pos2_char = rule_str[i + 2]
            try:
                pos1 = int(pos1_char, 16) if not pos1_char.isdigit() else int(pos1_char)
                pos2 = int(pos2_char, 16) if not pos2_char.isdigit() else int(pos2_char)
                prev = current
                if pos1 < len(current) and pos2 < len(current):
                    chars = list(current)
                    chars[pos1], chars[pos2] = chars[pos2], chars[pos1]
                    current = "".join(chars)
                steps.append(
                    f"*{pos1_char}{pos2_char}: Swap pos {pos1} and pos {pos2} → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "M":
            # Memorize current word for later use with X opcode
            memorized = current
            steps.append(f"M: Memorize current word '{current}'")
            i += 1

        elif char == "X" and i + 3 < len(rule_str):
            # Insert substring from memorized word: XNML
            # N = start pos in memorized word, M = length, L = insert pos in current word
            n_char = rule_str[i + 1]
            m_char = rule_str[i + 2]
            l_char = rule_str[i + 3]
            try:
                n = int(n_char, 16) if not n_char.isdigit() else int(n_char)
                m = int(m_char, 16) if not m_char.isdigit() else int(m_char)
                l_pos = int(l_char, 16) if not l_char.isdigit() else int(l_char)
                prev = current
                # Extract substring from memorized word
                if n < len(memorized) and n + m <= len(memorized) and l_pos <= len(current):
                    substring = memorized[n : n + m]
                    current = current[:l_pos] + substring + current[l_pos:]
                steps.append(
                    f"X{n_char}{m_char}{l_char}: Insert {m} chars from memorized word"
                    f" at pos {n} into pos {l_pos} → {prev} → {current}"
                )
                i += 4
            except (ValueError, IndexError):
                i += 1

        elif char == "=" and i + 2 < len(rule_str):
            # Reject unless character at position N is X (filter rule)
            pos_char = rule_str[i + 1]
            check_char = rule_str[i + 2]
            try:
                pos = int(pos_char, 16) if not pos_char.isdigit() else int(pos_char)
                if len(current) <= pos or current[pos] != check_char:
                    if len(current) <= pos:
                        reason = f"word length {len(current)} \u2264 {pos} (pos out of range)"
                    else:
                        reason = f"char at pos {pos} is '{current[pos]}', not '{check_char}'"
                    sentinel = f"{REJECT_SENTINEL_PREFIX}={pos_char}{check_char}: {reason}"
                    steps.append(sentinel)
                    return steps
                else:
                    steps.append(
                        f"={pos_char}{check_char}: Reject-unless-char-at-pos {pos}"
                        f" is '{check_char}' \u2192 passed (char at pos {pos} is '{check_char}')"
                    )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "B" and i + 2 < len(rule_str):
            # B: byte-wise add value to char at position — documented but not yet fully implemented
            # RULE_OP_MANGLE_CHR_ADD: adds arg2 (byte value) to the byte at position arg1.
            arg1 = rule_str[i + 1]
            arg2 = rule_str[i + 2]
            steps.append(
                f"B{arg1}{arg2}: Byte-add {arg2!r} to char at pos {arg1} (not yet simulated)"
            )
            i += 3

        elif char in rule_map:
            name, transform_func = rule_map[char]
            prev = current
            current = transform_func(current)
            steps.append(f"{char}: {name} → {prev} → {current}")
            i += 1

        else:
            # Arity-aware skip for unknown opcodes
            _three_arg = set("X")
            _two_arg = set("soix*=vOB")
            _one_arg = set("TDpyYezZ^$@!><'+-.,%LRa()")
            if char in _three_arg and i + 3 < len(rule_str):
                i += 4
            elif char in _two_arg and i + 2 < len(rule_str):
                i += 3
            elif char in _one_arg and i + 1 < len(rule_str):
                i += 2
            else:
                i += 1

    return steps if steps else None


@click.command()
@click.argument("file", type=click.Path(exists=True), required=False)
@click.option("--explain", type=str, help="Explain what a hashcat rule does")
@click.option(
    "--baseword",
    type=str,
    default="password",
    help="Baseword to transform (used with --explain, default: password)",
)
@click.option("--rules", is_flag=True, help="Show top rules by efficiency")
@click.option("--basewords", is_flag=True, help="Show basewords that appear multiple times")
@click.option("--export", type=click.Path(), help="Export analysis report to file")
@click.option(
    "--metric",
    type=click.Choice(["frequency", "basewords", "candidates"]),
    default="frequency",
    help="Metric to rank rules by (used with --rules)",
)
@click.option(
    "--format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Export format (used with --export)",
)
@click.option("--top", default=10, help="Number of top items to show")
@click.option("--min-occurrences", default=2, help="Minimum occurrences for basewords")
@click.option("--detail", is_flag=True, help="Show detailed rule applications for basewords")
@click.option(
    "--analyze-rules",
    is_flag=True,
    help="Analyze rule file opcodes (FILE should be a rule file, not debug output)",
)
@click.pass_context
def main(
    ctx,
    file,
    explain,
    baseword,
    rules,
    basewords,
    export,
    metric,
    format,
    top,
    min_occurrences,
    detail,
    analyze_rules,
):
    """Hashcat Rule Efficiency Analyzer - Analyze hashcat debug output files.

    Basic usage:
        rosetta debug.txt
        rosetta debug.txt --rules --metric frequency
        rosetta debug.txt --basewords --detail
        rosetta debug.txt --export report.json --format json

    Explain rules:
        rosetta --explain "c"
        rosetta --explain "i74i81i92iA3"
        rosetta --explain "cD0sao" --baseword "admin"
        rosetta --explain "u$!" --baseword "myword"
        rosetta --explain rules.txt --baseword "admin"

    Analyze rule file opcodes:
        rosetta rules.txt --analyze-rules
    """

    # Handle rule explanation
    if explain:
        if os.path.isfile(explain):
            click.echo(f"\nRule File Explanation: '{explain}' applied to '{baseword}'")
            click.echo("=" * 70)
            with open(explain, "r", encoding="utf-8") as rule_file:
                for line_number, raw_line in enumerate(rule_file, 1):
                    rule_line = raw_line.strip()
                    if not rule_line or rule_line.startswith("#"):
                        continue
                    explanations = explain_rule(rule_line, baseword)
                    if explanations:
                        click.echo(f"\nLine {line_number}: {rule_line}")
                        for explanation in explanations:
                            click.echo(f"  {explanation}")
                    else:
                        click.echo(f"\nLine {line_number}: {rule_line}")
                        click.echo("  [!] Unknown rule or no explanation available")
            click.echo("\nNote: Each character is a rule operation applied sequentially.")
            click.echo("      Complex rules combine multiple operations from left to right.")
        else:
            explanations = explain_rule(explain, baseword)
            if explanations:
                click.echo(f"\nRule Explanation: '{explain}' applied to '{baseword}'")
                click.echo("=" * 70)
                for explanation in explanations:
                    click.echo(f"  {explanation}")
                click.echo("=" * 70)
                click.echo("\nNote: Each character is a rule operation applied sequentially.")
                click.echo("      Complex rules combine multiple operations from left to right.")
            else:
                click.echo(f"[!] Unknown rule or no explanation available for: '{explain}'")
        return

    # Require file for other operations
    if not file:
        click.echo("Error: FILE is required (unless using --explain)\n")
        click.echo(ctx.get_help())
        sys.exit(1)

    # Handle rule opcode analysis
    if analyze_rules:
        try:
            display_rule_opcodes_summary(file)
        except (FileNotFoundError, ValueError) as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
        return

    analyzer = DebugAnalyzer()
    try:
        result = analyzer.analyze_debug_file(file)
    except FileNotFoundError:
        click.echo(f"Error: File not found: {file}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Default behavior: show analysis summary
    if not rules and not basewords and not export:
        stats = analyzer.get_rule_statistics_summary()
        bw_stats = analyzer.get_baseword_statistics_summary()

        click.echo(f"\nDebug File Analysis: {file}")
        click.echo(f"   Total Entries: {result['total_entries']}")
        click.echo(f"   Unique Rules: {result['unique_rules']}")
        click.echo(f"   Unique Basewords: {result['unique_basewords']}")
        click.echo()
        click.echo("   Rule Statistics:")
        click.echo(f"      Total Applications: {stats.get('total_applications', 0)}")
        click.echo(f"      Average per Rule: {stats.get('avg_applications_per_rule', 0):.2f}")
        click.echo(f"      Max Applications: {stats.get('max_applications', 0)}")
        click.echo()
        click.echo("   Baseword Statistics:")
        click.echo(f"      Total Occurrences: {bw_stats.get('total_occurrences', 0)}")
        click.echo(
            f"      Average per Baseword: {bw_stats.get('avg_occurrences_per_baseword', 0):.2f}"
        )
        click.echo(f"      Max Occurrences: {bw_stats.get('max_occurrences', 0)}")
        return

    # Show rules
    if rules:
        if metric == "frequency":
            rule_list = analyzer.get_top_rules_by_frequency(top)
            title = "by Frequency"
        elif metric == "basewords":
            rule_list = analyzer.get_top_rules_by_unique_basewords(top)
            title = "by Unique Basewords"
        else:  # candidates
            rule_list = analyzer.get_top_rules_by_unique_candidates(top)
            title = "by Unique Candidates"

        click.echo(f"\nTop {top} Rules {title}")
        click.echo("-" * 50)
        for i, (rule, count) in enumerate(rule_list, 1):
            click.echo(f"{i:2}. Rule: {rule:20} ({count})")

    # Show basewords
    if basewords:
        baseword_list = analyzer.get_basewords_with_min_occurrences(min_occurrences)
        baseword_list = baseword_list[:top]

        click.echo(f"\nBasewords (min {min_occurrences} occurrences, showing top {top}):")
        click.echo("=" * 80)

        for baseword, count in baseword_list:
            click.echo(f"\n{baseword} → {count} occurrences")

            if detail:
                bw_detail = analyzer.get_baseword_detail(baseword)
                if bw_detail:
                    click.echo(f"  Unique Rules: {bw_detail['unique_rules']}")
                    click.echo(f"  Unique Candidates: {bw_detail['unique_candidates']}")
                    click.echo(
                        f"  Rules Applied: {', '.join(sorted(set(occ['rule'] for occ in bw_detail['occurrences'])))}"
                    )

    # Export report
    if export:
        if format == "json":
            data = analyzer.export_to_dict()
            with open(export, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            click.echo(f"Done: JSON report exported to: {export}")

        else:  # csv
            _export_to_csv(analyzer, export)
            click.echo(f"Done: CSV report exported to: {export}")


def _export_to_csv(analyzer: DebugAnalyzer, filepath: str) -> None:
    """Export analysis to CSV format."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        # Rules section
        f.write("# RULES ANALYSIS\n")
        writer = csv.writer(f)
        writer.writerow(["Rule", "Total Applications", "Unique Basewords", "Unique Candidates"])

        for rule in sorted(analyzer.rule_stats.keys()):
            stats = analyzer.rule_stats[rule]
            writer.writerow(
                [rule, stats["count"], len(stats["basewords"]), len(stats["candidates"])]
            )

        # Basewords section
        f.write("\n# BASEWORDS ANALYSIS\n")
        writer.writerow(["Baseword", "Total Occurrences", "Unique Rules", "Unique Candidates"])

        for baseword in sorted(analyzer.baseword_stats.keys()):
            detail = analyzer.get_baseword_detail(baseword)
            if detail:
                writer.writerow(
                    [
                        baseword,
                        detail["total_occurrences"],
                        detail["unique_rules"],
                        detail["unique_candidates"],
                    ]
                )


if __name__ == "__main__":
    main()
