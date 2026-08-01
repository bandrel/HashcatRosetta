"""Command-line interface for the hashcat rule analyzer."""

import csv
import json
import os
import sys

import click

from .debug_analyzer import DebugAnalyzer
from .formatting import display_rule_opcodes_summary
from .mask import describe, format_hcmask_line
from .parser import decode_hex_escapes

# NOTE: hashcat_rosetta.nlmask is deliberately NOT imported here. It pulls in
# the ``openai`` SDK, which costs ~450ms of import time that every non-LLM
# invocation (--explain, debug-file analysis, ...) would otherwise pay. It is
# imported lazily inside the ``--mask`` branch of main().

_BANNER = r"""
 _   _           _               _   ____                _   _
| | | | __ _ ___| |__   ___ __ _| |_|  _ \ ___  ___  ___| |_| |_ __ _
| |_| |/ _` / __| '_ \ / __/ _` | __| |_) / _ \/ __|/ _ \ __| __/ _` |
|  _  | (_| \__ \ | | | (_| (_| | |_|  _ < (_) \__ \  __/ |_| || (_| |
|_| |_|\__,_|___/_| |_|\___\__,_|\__|_| \_\___/|___/\___|\__|\__\__,_|

    Decode the Rosetta Stone of Password Cracking Rules
"""


def _hashcat_pos(c: str) -> int:
    """Parse a hashcat position char.

    Hashcat encodes positions 0-35 as '0'-'9' (0-9) then 'A'-'Z' (10-35).
    Raises ValueError on anything else — matching hashcat, which rejects
    such rules outright. The existing call-sites already catch ValueError
    to skip malformed args, so this drops in cleanly.

    Note: int(c, 16) covers only 0-F (0-15) and silently dropped positions
    G-Z, producing wildly wrong candidates for ~half the position space.
    """
    if c.isdigit():
        return int(c)
    if "A" <= c <= "Z":
        return ord(c) - ord("A") + 10
    raise ValueError(f"invalid hashcat position char: {c!r}")


# hashcat's rule engine works in a fixed RP_PASSWORD_SIZE (256) byte buffer.
# A length-expanding opcode is applied only when its result still fits below
# that size; otherwise hashcat treats the op as a no-op (it does NOT truncate).
# Verified against hashcat 7.1.2: the boundary is strict — a result of exactly
# 256 is rejected, so an op applies iff the result length is < 256.
_RP_PASSWORD_SIZE = 256


def _cap(prev: str, new: str) -> str:
    """Return ``new`` unless it would exceed hashcat's length cap, else ``prev``.

    Mirrors hashcat's no-op-on-overflow behavior for length-expanding opcodes.
    Length-preserving and shrinking ops pass through unchanged.
    """
    return new if len(new) < _RP_PASSWORD_SIZE else prev


def _escape_bytes(text: str) -> str:
    r"""Render raw byte values (control chars and 0x80-0xFF) as ``\xNN``.

    ``explain_rule`` builds transformed words from code points 0-255 (one code
    point per byte). Emitting those directly would UTF-8-encode code points
    0x80-0xFF into multibyte sequences, misrepresenting hashcat's single-byte
    output (e.g. 0x99 -> ``c2 99``). Escape any code point below 0x100 that
    isn't printable ASCII; genuine Unicode in the descriptions (such as the
    U+2192 ``->`` arrow) is >= 0x100 and left intact.
    """
    out = []
    for ch in text:
        o = ord(ch)
        if o < 0x100 and not (0x20 <= o <= 0x7E):
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _ascii_lower(s: str) -> str:
    """Lowercase only ASCII A-Z, like hashcat (leaves 0x80-0xFF untouched)."""
    return "".join(chr(ord(c) + 0x20) if "A" <= c <= "Z" else c for c in s)


def _ascii_upper(s: str) -> str:
    """Uppercase only ASCII a-z, like hashcat."""
    return "".join(chr(ord(c) - 0x20) if "a" <= c <= "z" else c for c in s)


def _ascii_swapcase(s: str) -> str:
    """Toggle case of only ASCII letters, like hashcat."""
    out = []
    for c in s:
        if "A" <= c <= "Z":
            out.append(chr(ord(c) + 0x20))
        elif "a" <= c <= "z":
            out.append(chr(ord(c) - 0x20))
        else:
            out.append(c)
    return "".join(out)


def explain_rule(rule_str: str, baseword: str = "password") -> list | None:
    """Explain what a hashcat rule does with examples."""
    if not rule_str:
        return None

    # hashcat decodes \xNN byte escapes before applying the rule; do the same
    # so the simulated result matches hashcat (e.g. s\x20_ substitutes a space).
    rule_str = decode_hex_escapes(rule_str)

    # Rule explanations
    rule_map = {
        ":": ("No-op", lambda x: x),
        "c": ("Capitalize", lambda x: _ascii_upper(x[0]) + _ascii_lower(x[1:]) if x else x),
        "u": ("Uppercase all", lambda x: _ascii_upper(x)),
        "l": ("Lowercase all", lambda x: _ascii_lower(x)),
        "d": ("Duplicate word", lambda x: x + x),
        "r": ("Reverse", lambda x: x[::-1]),
        "t": ("Toggle case all", lambda x: _ascii_swapcase(x)),
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
            lambda x: _ascii_lower(x[0]) + _ascii_upper(x[1:]) if x else x,
        ),
        "E": (
            "Title case",
            lambda x: (
                " ".join(
                    _ascii_upper(w[0]) + _ascii_lower(w[1:]) if w else w
                    for w in _ascii_lower(x).split(" ")
                )
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
            current = _cap(prev, current + append_char)
            steps.append(f"${append_char}: Append '{append_char}' → {prev} → {current}")
            i += 2

        # Handle prepend: ^X - Prepend character X
        elif char == "^" and i + 1 < len(rule_str):
            prepend_char = rule_str[i + 1]
            prev = current
            current = _cap(prev, prepend_char + current)
            steps.append(f"^{prepend_char}: Prepend '{prepend_char}' → {prev} → {current}")
            i += 2

        # Handle parameterized rules
        elif char == "i" and i + 2 < len(rule_str):
            # Insert: iXY where X is position, Y is character
            pos_char = rule_str[i + 1]
            val_char = rule_str[i + 2]

            try:
                # Convert hex position if needed
                pos = _hashcat_pos(pos_char)

                prev = current
                if pos <= len(current):
                    current = _cap(prev, current[:pos] + val_char + current[pos:])
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
            # Duplicate word: pN - append duplicated word N times.
            # Hashcat positional encoding: '0'-'9' = 0-9, 'A'-'Z' = 10-35.
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
                prev = current
                current = _cap(prev, current * (n + 1))
                steps.append(f"p{n_char}: Append duplicated word {n} times → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "D" and i + 1 < len(rule_str):
            # Delete: DX where X is position
            pos_char = rule_str[i + 1]
            try:
                pos = _hashcat_pos(pos_char)
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
                pos = _hashcat_pos(pos_char)
                prev = current
                if pos < len(current):
                    current = current[:pos] + _ascii_swapcase(current[pos]) + current[pos + 1 :]
                steps.append(f"T{pos_char}: Toggle case at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "O" and i + 2 < len(rule_str):
            # Omit M characters starting at position N
            pos_char = rule_str[i + 1]
            len_char = rule_str[i + 2]
            try:
                pos = _hashcat_pos(pos_char)
                length = _hashcat_pos(len_char)
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
                n = _hashcat_pos(n_char)
                prev = current
                if n <= len(current):
                    current = _cap(prev, current[:n] + current)
                steps.append(f"y{n_char}: Duplicate first {n} chars → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "Y" and i + 1 < len(rule_str):
            # Duplicate last N characters (append)
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
                prev = current
                # n==0 must be a no-op; current[-0:] is current[0:] == current,
                # which would duplicate the whole word. Hashcat treats Y0 as
                # "append zero chars" = no-op.
                if 0 < n <= len(current):
                    current = _cap(prev, current + current[-n:])
                steps.append(f"Y{n_char}: Duplicate last {n} chars → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "z" and i + 1 < len(rule_str):
            # Duplicate first character N times
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
                prev = current
                if current:
                    current = _cap(prev, current[0] * n + current)
                steps.append(f"z{n_char}: Duplicate first char {n} times → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "Z" and i + 1 < len(rule_str):
            # Duplicate last character N times
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
                prev = current
                if current:
                    current = _cap(prev, current + current[-1] * n)
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
            # Reject if contains char X
            reject_char = rule_str[i + 1]
            if reject_char in current:
                return None
            steps.append(
                f"!{reject_char}: Reject if contains '{reject_char}' (no match) "
                f"→ {current} → {current}"
            )
            i += 2

        elif char == ">" and i + 1 < len(rule_str):
            # Reject if word length > N
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
            except ValueError:
                i += 1
                continue
            if len(current) > n:
                return None
            steps.append(
                f">{n_char}: Length {len(current)} <= {n} (filter passed) → {current} → {current}"
            )
            i += 2

        elif char == "<" and i + 1 < len(rule_str):
            # Reject if word length < N
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
            except ValueError:
                i += 1
                continue
            if len(current) < n:
                return None
            steps.append(
                f"<{n_char}: Length {len(current)} >= {n} (filter passed) → {current} → {current}"
            )
            i += 2

        elif char == "'" and i + 1 < len(rule_str):
            # Truncate word at position N
            pos_char = rule_str[i + 1]
            try:
                pos = _hashcat_pos(pos_char)
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
                pos = _hashcat_pos(pos_char)
                prev = current
                if pos < len(current):
                    current = (
                        current[:pos] + chr((ord(current[pos]) + 1) & 0xFF) + current[pos + 1 :]
                    )
                steps.append(f"+{pos_char}: Increment ASCII at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "-" and i + 1 < len(rule_str):
            # Decrement character at position N by 1 (ASCII value)
            pos_char = rule_str[i + 1]
            try:
                pos = _hashcat_pos(pos_char)
                prev = current
                if pos < len(current):
                    current = (
                        current[:pos] + chr((ord(current[pos]) - 1) & 0xFF) + current[pos + 1 :]
                    )
                steps.append(f"-{pos_char}: Decrement ASCII at pos {pos} → {prev} → {current}")
                i += 2
            except (ValueError, IndexError):
                i += 1

        elif char == "." and i + 1 < len(rule_str):
            # Replace char at pos N with char at pos N+1
            pos_char = rule_str[i + 1]
            try:
                pos = _hashcat_pos(pos_char)
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
                pos = _hashcat_pos(pos_char)
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
            # Reject unless word contains char X
            check_char = rule_str[i + 1]
            if check_char not in current:
                return None
            steps.append(
                f"%{check_char}: Contains '{check_char}' (filter passed) → {current} → {current}"
            )
            i += 2

        elif char == "R" and i + 1 < len(rule_str):
            # Bitwise shift right character at position N
            pos_char = rule_str[i + 1]
            try:
                pos = _hashcat_pos(pos_char)
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
                pos = _hashcat_pos(pos_char)
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
                pos = _hashcat_pos(pos_char)
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
                pos = _hashcat_pos(pos_char)
                length = _hashcat_pos(len_char)
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
                pos1 = _hashcat_pos(pos1_char)
                pos2 = _hashcat_pos(pos2_char)
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

        elif char == "a":
            # Append memorized word (RULE_OP_MANGLE_TOGGLECASE_REC in hashcat source,
            # but treated here as append-memorized semantics matching CPU-mode behavior)
            prev = current
            current = _cap(prev, current + memorized)
            steps.append(f"a: Append memorized '{memorized}' → {prev} → {current}")
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
                n = _hashcat_pos(n_char)
                m = _hashcat_pos(m_char)
                l_pos = _hashcat_pos(l_char)
                prev = current
                # Extract substring from memorized word
                if n < len(memorized) and n + m <= len(memorized) and l_pos <= len(current):
                    substring = memorized[n : n + m]
                    current = _cap(prev, current[:l_pos] + substring + current[l_pos:])
                steps.append(
                    f"X{n_char}{m_char}{l_char}: Insert {m} chars from memorized word"
                    f" at pos {n} into pos {l_pos} → {prev} → {current}"
                )
                i += 4
            except (ValueError, IndexError):
                i += 1

        elif char == "=" and i + 2 < len(rule_str):
            # Reject unless character at position N is X
            pos_char = rule_str[i + 1]
            check_char = rule_str[i + 2]
            try:
                pos = _hashcat_pos(pos_char)
            except ValueError:
                i += 1
                continue
            if pos >= len(current) or current[pos] != check_char:
                return None
            steps.append(
                f"={pos_char}{check_char}: Char at pos {pos} is '{check_char}' (filter passed) "
                f"→ {current} → {current}"
            )
            i += 3

        elif char == "(" and i + 1 < len(rule_str):
            # Reject unless first character equals X
            check_char = rule_str[i + 1]
            if not current or current[0] != check_char:
                return None
            steps.append(
                f"({check_char}: First char is '{check_char}' (filter passed) "
                f"→ {current} → {current}"
            )
            i += 2

        elif char == ")" and i + 1 < len(rule_str):
            # Reject unless last character equals X
            check_char = rule_str[i + 1]
            if not current or current[-1] != check_char:
                return None
            steps.append(
                f"){check_char}: Last char is '{check_char}' (filter passed) "
                f"→ {current} → {current}"
            )
            i += 2

        elif char == "v" and i + 2 < len(rule_str):
            # Insert character M after every N characters.
            # vNM: N is hex-parsed chunk size (0-9 or A-Z); M is the literal character to insert.
            # Mirrors hashcat src/rp_cpu.c::mangle_insert_into_string_at_every_Nth.
            # N=0 is a no-op (chunk size of 0 means nothing is ever inserted).
            n_char = rule_str[i + 1]
            m_char = rule_str[i + 2]
            try:
                n = _hashcat_pos(n_char)
            except ValueError:
                i += 1
                continue
            prev = current
            if n > 0:
                result_chars: list[str] = []
                pos = 0
                while pos < len(current):
                    chunk_end = pos + n
                    if chunk_end <= len(current):
                        # Full chunk: append the N chars and the separator
                        result_chars.extend(current[pos:chunk_end])
                        result_chars.append(m_char)
                    else:
                        # Partial chunk at end: append remaining chars, no separator
                        result_chars.extend(current[pos:])
                    pos += n
                current = _cap(prev, "".join(result_chars))
            steps.append(
                f"v{n_char}{m_char}: Insert '{m_char}' after every {n} chars → {prev} → {current}"
            )
            i += 3

        elif char == "e" and i + 1 < len(rule_str):
            # Title case with separator X. Lowercase all, then uppercase
            # first char and any char immediately following separator X.
            # Separator matching is done against the ORIGINAL word (before
            # lowercasing), mirroring hashcat src/rp_cpu.c mangle_title_sep.
            sep = rule_str[i + 1]
            prev = current
            orig = current  # preserve original for separator matching
            lowered = _ascii_lower(current)
            chars = list(lowered)
            if chars:
                chars[0] = _ascii_upper(chars[0])
            for idx in range(1, len(chars)):
                if orig[idx - 1] == sep:
                    chars[idx] = _ascii_upper(chars[idx])
            current = "".join(chars)
            steps.append(f"e{sep}: Title-case with separator '{sep}' → {prev} → {current}")
            i += 2

        elif char == "B" and i + 2 < len(rule_str):
            # BNX: byte at position N += ord(X), mod 256. The second arg is
            # taken as a literal byte value (its raw ASCII codepoint added),
            # NOT as a hashcat-encoded position. Verified empirically against
            # hashcat 7.1.2; this matches the kernel's behavior for the B
            # opcode even though it's not in the official rules docs.
            pos_char = rule_str[i + 1]
            add_char = rule_str[i + 2]
            try:
                pos = _hashcat_pos(pos_char)
                prev = current
                if pos < len(current):
                    new_byte = (ord(current[pos]) + ord(add_char)) & 0xFF
                    current = current[:pos] + chr(new_byte) + current[pos + 1 :]
                steps.append(
                    f"B{pos_char}{add_char}: Add ord('{add_char}')={ord(add_char)} "
                    f"to byte at pos {pos} → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char == "3" and i + 2 < len(rule_str):
            # 3NX: toggle the case of the character immediately after the Nth
            # (0-indexed) occurrence of separator char X. If there is no Nth
            # occurrence (or no char after it) the word is unchanged. Verified
            # against hashcat: '30s' password -> pasSword, '31s' -> passWord.
            n_char = rule_str[i + 1]
            sep = rule_str[i + 2]
            try:
                n = _hashcat_pos(n_char)
                prev = current
                idx = -1
                count = 0
                for k, ch2 in enumerate(current):
                    if ch2 == sep:
                        if count == n:
                            idx = k
                            break
                        count += 1
                if idx != -1 and idx + 1 < len(current):
                    current = (
                        current[: idx + 1] + _ascii_swapcase(current[idx + 1]) + current[idx + 2 :]
                    )
                steps.append(
                    f"3{n_char}{sep}: Toggle case after occurrence {n} of "
                    f"'{sep}' → {prev} → {current}"
                )
                i += 3
            except (ValueError, IndexError):
                i += 1

        elif char in rule_map:
            name, transform_func = rule_map[char]
            prev = current
            # d/f/q grow the word; the rest preserve length. _cap only reverts
            # the growers when they would cross hashcat's 256-byte cap.
            current = _cap(prev, transform_func(current))
            steps.append(f"{char}: {name} → {prev} → {current}")
            i += 1

        else:
            # Arity-aware skip for unknown opcodes
            _three_arg = set("X")
            _two_arg = set("soi3x*=OB")
            _one_arg = set("TDpyYezZ^$@!><'+-.,%LR()")
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
@click.option(
    "--wordlists",
    is_flag=True,
    help="Show top wordlists by attributed entries (debug mode 5 only)",
)
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
@click.option(
    "--debug-mode",
    type=click.Choice(["auto", "4", "5"]),
    default="auto",
    help=(
        "Hashcat debug mode of the input file. 'auto' detects the format; "
        "'4' forces mode 4 (baseword rule candidate); '5' forces mode 5 "
        "(baseword:rule:candidate:wordlist with wordlist attribution)."
    ),
)
@click.option(
    "--mask",
    type=str,
    help="Generate an hcmask from an English description via a local Ollama server",
)
@click.option(
    "-o",
    "--mask-out",
    type=click.Path(),
    help="Write generated mask(s) to a .hcmask file (used with --mask)",
)
@click.option(
    "--model",
    type=str,
    default=lambda: os.environ.get("OLLAMA_MODEL"),
    help="Override the model name used for --mask (default: OLLAMA_MODEL env var)",
)
@click.option(
    "--ollama-host",
    type=str,
    default=None,
    help="Override the Ollama host/URL used for --mask (default: OLLAMA_HOST env var)",
)
@click.pass_context
def main(
    ctx,
    file,
    explain,
    baseword,
    rules,
    basewords,
    wordlists,
    export,
    metric,
    format,
    top,
    min_occurrences,
    detail,
    analyze_rules,
    debug_mode,
    mask,
    mask_out,
    model,
    ollama_host,
):
    """Hashcat Rule Efficiency Analyzer - Analyze hashcat debug output files.

    Supports both debug mode 4 (baseword rule candidate) and debug mode 5
    (baseword:rule:candidate:wordlist). The format is auto-detected by default;
    use --debug-mode 4 or --debug-mode 5 to force a mode. Mode-5 files carry a
    trailing wordlist field, enabling per-wordlist analysis via --wordlists.

    Basic usage:
        hashcat-rosetta debug.txt
        hashcat-rosetta debug.txt --rules --metric frequency
        hashcat-rosetta debug.txt --basewords --detail
        hashcat-rosetta debug.txt --wordlists --detail
        hashcat-rosetta debug.txt --debug-mode 5 --wordlists
        hashcat-rosetta debug.txt --export report.json --format json

    Explain rules:
        hashcat-rosetta --explain "c"
        hashcat-rosetta --explain "i74i81i92iA3"
        hashcat-rosetta --explain "cD0sao" --baseword "admin"
        hashcat-rosetta --explain "u$!" --baseword "myword"
        hashcat-rosetta --explain rules.txt --baseword "admin"

    Analyze rule file opcodes:
        hashcat-rosetta rules.txt --analyze-rules

    Generate masks:
        hashcat-rosetta --mask "The word 'Summer' followed by six digits."
        hashcat-rosetta --mask "a season and a year" -o seasons.hcmask
    """

    # Show the banner (to stderr so it never pollutes piped/exported stdout)
    click.echo(_BANNER, err=True)

    # Handle natural-language mask generation
    if mask:
        # Lazy import: keeps the openai SDK out of the import path of every
        # other command. See the note at the top of this module.
        from . import nlmask

        try:
            suggestions = nlmask.generate_masks(mask, model=model, host=ollama_host)
        except nlmask.MaskGenerationError as e:
            click.echo(f"[!] {e}", err=True)
            sys.exit(1)

        click.echo(f"\nMask Suggestions for: '{mask}'")
        click.echo("=" * 70)
        for i, suggestion in enumerate(suggestions, 1):
            line_str = format_hcmask_line(suggestion.custom_charsets, suggestion.mask)
            click.echo(f"\n{i}. {line_str}")
            # describe() already ends with "→ N candidates", so the keyspace
            # is not printed a second time on its own line.
            click.echo(f"   {describe(suggestion.line)}")
            click.echo(f"   Why: {suggestion.why}")
        click.echo()

        if mask_out:
            # The description is written as a header comment; collapse any
            # newlines so it cannot inject extra lines into the file.
            header = " ".join(mask.splitlines())
            lines = [
                format_hcmask_line(suggestion.custom_charsets, suggestion.mask)
                for suggestion in suggestions
            ]
            try:
                with open(mask_out, "w", encoding="utf-8") as f:
                    f.write(f"# {header}\n")
                    for line_str in lines:
                        # hashcat skips any line starting with '#' as a
                        # comment; '\#' is its accepted escape for a literal
                        # leading '#'.
                        if line_str.startswith("#"):
                            click.echo(
                                f"[!] mask '{line_str}' starts with '#'; written as "
                                f"'\\{line_str}' so hashcat does not treat it as a comment",
                                err=True,
                            )
                            line_str = "\\" + line_str
                        f.write(line_str + "\n")
            except OSError as e:
                click.echo(f"[!] could not write {mask_out}: {e}", err=True)
                sys.exit(1)
            click.echo(f"Done: Mask(s) written to: {mask_out}")
        return

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
                            click.echo(f"  {_escape_bytes(explanation)}")
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
                    click.echo(f"  {_escape_bytes(explanation)}")
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

    mode_map: dict[str, int | None] = {"auto": None, "4": 4, "5": 5}
    analyzer = DebugAnalyzer(debug_mode=mode_map[debug_mode])
    try:
        result = analyzer.analyze_debug_file(file)
    except FileNotFoundError:
        click.echo(f"Error: File not found: {file}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    # Default behavior: show analysis summary
    if not rules and not basewords and not wordlists and not export:
        stats = analyzer.get_rule_statistics_summary()
        bw_stats = analyzer.get_baseword_statistics_summary()
        wl_stats = analyzer.get_wordlist_statistics_summary()

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

        # Wordlist statistics (mode-5 only; omit entirely when absent).
        if wl_stats and result.get("unique_wordlists", 0) > 0:
            click.echo()
            click.echo("   Wordlist Statistics:")
            click.echo(f"      Total Wordlists: {wl_stats.get('total_wordlists', 0)}")
            click.echo(f"      Attributed Entries: {wl_stats.get('total_attributed_entries', 0)}")
            click.echo(
                f"      Average per Wordlist: {wl_stats.get('avg_entries_per_wordlist', 0):.2f}"
            )
            click.echo(f"      Max Entries: {wl_stats.get('max_entries', 0)}")
            click.echo("      Top 5 Wordlists:")
            for wordlist, count in analyzer.get_top_wordlists(5):
                click.echo(f"         {wordlist} ({count})")
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

    # Show wordlists (mode-5 attribution)
    if wordlists:
        wordlist_list = analyzer.get_top_wordlists(top)

        click.echo(f"\nTop {top} Wordlists")
        click.echo("-" * 50)
        for i, (wordlist, count) in enumerate(wordlist_list, 1):
            click.echo(f"{i:2}. Wordlist: {wordlist:20} ({count})")

            if detail:
                wl_detail = analyzer.get_wordlist_detail(wordlist)
                if wl_detail:
                    click.echo(f"      Unique Basewords: {wl_detail['unique_basewords']}")
                    click.echo(f"      Unique Candidates: {wl_detail['unique_candidates']}")
                    click.echo(f"      Unique Rules: {wl_detail['unique_rules']}")

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

        # Wordlist section (mode-5 only; mode-4 files yield header with no rows)
        f.write("\n# WORDLIST ANALYSIS\n")
        writer.writerow(
            [
                "Wordlist",
                "Total Occurrences",
                "Unique Basewords",
                "Unique Candidates",
                "Unique Rules",
            ]
        )

        for wordlist in sorted(analyzer.wordlist_stats.keys()):
            wl_detail = analyzer.get_wordlist_detail(wordlist)
            assert wl_detail is not None  # key came from wordlist_stats
            writer.writerow(
                [
                    wordlist,
                    wl_detail["total_occurrences"],
                    wl_detail["unique_basewords"],
                    wl_detail["unique_candidates"],
                    wl_detail["unique_rules"],
                ]
            )


if __name__ == "__main__":
    main()
