"""Module for parsing and validating hashcat mask syntax (hcmask).

Provides deterministic parsing, validation, and keyspace computation for
hashcat mask lines. No networking or LLM code — pure unit-testable functions.
"""

from dataclasses import dataclass


# Builtin charsets as defined by hashcat
BUILTIN_CHARSETS: dict[str, str] = {
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?d": "0123456789",
    "?h": "0123456789abcdef",
    "?H": "0123456789ABCDEF",
    "?s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "?a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    + " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "?b": "".join(chr(i) for i in range(256)),
}


class MaskError(Exception):
    """Raised when mask parsing or validation fails."""

    pass


@dataclass
class HcmaskLine:
    """Represents a parsed hcmask line.

    Attributes:
        custom: List of custom charset definitions (0-4 items).
        mask: The mask string containing tokens and literals.
        raw: The original unparsed line text (useful for error messages).
    """

    custom: list[str]
    mask: str
    raw: str


def parse_hcmask_line(line: str) -> HcmaskLine:
    """Parse an hcmask line into custom charsets and mask.

    An hcmask line is comma-separated fields. The last field is the mask;
    all preceding fields are custom charset definitions (max 4). Unescaped
    commas are field separators; ``\\,`` is a literal comma within a field.

    Args:
        line: A full hcmask line string (e.g. ``abcdef,?1?1?1?d`` or
            ``?d?d?d?d?d?d``)

    Returns:
        HcmaskLine with parsed custom charsets and mask.

    Raises:
        MaskError: If the line has >4 custom charsets, or if the mask is
            invalid (dangling ``?``, unknown token, invalid custom charset
            reference, etc.)
    """
    raw_line = line
    # Split on unescaped commas
    fields = _split_unescaped_commas(line)

    if not fields:
        raise MaskError("Empty hcmask line")

    # Last field is the mask; all others are custom charsets
    mask = fields[-1]
    custom_fields = fields[:-1]

    if len(custom_fields) > 4:
        raise MaskError(f"at most 4 custom charsets allowed, got {len(custom_fields)}")

    # Unescape each custom charset field
    custom = [_unescape_field(f) for f in custom_fields]

    # Validate the mask against the custom charsets
    validate_mask(mask, custom)

    return HcmaskLine(custom=custom, mask=mask, raw=raw_line)


def _split_unescaped_commas(line: str) -> list[str]:
    """Split a line on unescaped commas.

    A comma preceded by a backslash is escaped and not a separator.
    The backslash is not removed here; it is removed by _unescape_field().
    """
    fields = []
    current = []
    i = 0
    while i < len(line):
        if i > 0 and line[i] == "," and line[i - 1] == "\\":
            # Escaped comma — include it in the current field
            current.append(",")
            i += 1
        elif line[i] == ",":
            # Unescaped comma — field separator
            fields.append("".join(current))
            current = []
            i += 1
        else:
            current.append(line[i])
            i += 1
    fields.append("".join(current))
    return fields


def _unescape_field(field: str) -> str:
    """Remove escape sequences from a field.

    Replaces ``\\,`` with ``,``. Other backslashes are left alone
    (hashcat behavior).
    """
    return field.replace("\\,", ",")


def validate_mask(mask: str, custom: list[str]) -> None:
    """Validate a mask string against a list of custom charsets.

    Args:
        mask: The mask string to validate.
        custom: List of custom charset definitions (0-4 items).

    Raises:
        MaskError: If the mask is invalid (dangling ``?``, unknown token,
            reference to non-existent custom charset, etc.)
    """
    i = 0
    while i < len(mask):
        char = mask[i]

        if char == "?":
            # Token marker — must have a following character
            if i + 1 >= len(mask):
                raise MaskError("dangling trailing '?'")

            next_char = mask[i + 1]

            # Check for escaped ?
            if next_char == "?":
                # ?? is a literal ?
                i += 2
                continue

            # Check for builtin charset
            if next_char in "ludhHsab":
                i += 2
                continue

            # Check for custom charset reference (?1-?4)
            if next_char in "1234":
                custom_index = int(next_char) - 1
                if custom_index >= len(custom):
                    raise MaskError(
                        f"referenced ?{next_char} but only {len(custom)} custom charset(s) provided"
                    )
                i += 2
                continue

            # Unknown token
            raise MaskError(f"unknown token '?{next_char}'")

        # Literal character
        i += 1


def tokens(line: HcmaskLine) -> list[tuple[str, int]]:
    """Return the ordered list of tokens and their charset sizes.

    Tokens are either single literal characters or mask tokens like
    ``?d``, ``?1``, etc. Each token is paired with its charset size:
    literals have size 1, tokens have their builtin or custom size.

    Args:
        line: A parsed HcmaskLine.

    Returns:
        List of (token_string, charset_size) pairs in order.
    """
    result = []
    i = 0
    mask = line.mask

    while i < len(mask):
        char = mask[i]

        if char == "?":
            # Token
            if i + 1 >= len(mask):
                # Should not happen if validate_mask was called
                raise MaskError("dangling trailing '?'")

            next_char = mask[i + 1]

            # Escaped ?
            if next_char == "?":
                result.append(("??", 1))
                i += 2
                continue

            # Builtin charset
            if f"?{next_char}" in BUILTIN_CHARSETS:
                charset = BUILTIN_CHARSETS[f"?{next_char}"]
                result.append((f"?{next_char}", len(charset)))
                i += 2
                continue

            # Custom charset reference
            if next_char in "1234":
                custom_index = int(next_char) - 1
                if custom_index < len(line.custom):
                    charset = line.custom[custom_index]
                    result.append((f"?{next_char}", len(charset)))
                i += 2
                continue

            # Should not happen if validate_mask was called
            raise MaskError(f"unknown token '?{next_char}'")

        # Literal character
        result.append((char, 1))
        i += 1

    return result


def keyspace(line: HcmaskLine) -> int:
    """Compute the total keyspace (product of charset sizes).

    Args:
        line: A parsed HcmaskLine.

    Returns:
        The product of all per-position charset sizes as an arbitrary
        precision integer.
    """
    tok_list = tokens(line)
    result = 1
    for _, size in tok_list:
        result *= size
    return result


def describe(line: HcmaskLine) -> str:
    """Generate a human-readable one-line description of the mask.

    Groups consecutive identical tokens and consecutive literals, showing
    counts and the final keyspace with thousands separators.

    Args:
        line: A parsed HcmaskLine.

    Returns:
        A string like ``literal "Summer", then 6 × digit → 1,000,000
        candidates``.
    """
    tok_list = tokens(line)

    if not tok_list:
        return "empty mask → 1 candidate"

    # Group consecutive identical tokens
    groups = []
    i = 0
    while i < len(tok_list):
        tok, size = tok_list[i]

        # Handle literals: group consecutive single-char literals
        if size == 1 and not tok.startswith("?"):
            # Collect consecutive literals
            literal_chars = [tok]
            j = i + 1
            while j < len(tok_list):
                next_tok, next_size = tok_list[j]
                if next_size == 1 and not next_tok.startswith("?"):
                    literal_chars.append(next_tok)
                    j += 1
                else:
                    break
            groups.append(("literal", "".join(literal_chars), 1, len(literal_chars)))
            i = j
        else:
            # Single token (either ?? or a charset token)
            # Count how many consecutive identical tokens
            count = 1
            j = i + 1
            while j < len(tok_list):
                next_tok, next_size = tok_list[j]
                if next_tok == tok and next_size == size:
                    count += 1
                    j += 1
                else:
                    break
            groups.append(("token", tok, size, count))
            i = j

    # Format each group
    parts = []
    for group_type, token_or_literal, size, count in groups:
        if group_type == "literal":
            # Escape quotes in the literal
            escaped = token_or_literal.replace('"', '\\"')
            if count == 1:
                parts.append(f'literal "{escaped}"')
            else:
                parts.append(f'{count} × literal "{escaped}"')
        else:
            # Token
            if count == 1:
                # Describe the token
                description = _describe_token(token_or_literal)
                parts.append(description)
            else:
                # Multiple identical tokens
                description = _describe_token(token_or_literal)
                parts.append(f"{count} × {description}")

    # Compute keyspace
    ks = keyspace(line)

    # Format keyspace with thousands separators
    ks_str = f"{ks:,}"

    # Add scientific notation if > 10^9
    if ks > 10**9:
        parts.append(f"→ {ks_str} (~{ks:.1e}) candidates")
    else:
        parts.append(f"→ {ks_str} candidates")

    return ", then ".join(parts)


def _describe_token(token: str) -> str:
    """Describe a single token in human-readable form.

    Args:
        token: A token like ``?d``, ``?1``, ``??``, etc.

    Returns:
        A description like ``digit``, ``custom charset 1``, ``literal ?``.
    """
    descriptions = {
        "?l": "lowercase",
        "?u": "uppercase",
        "?d": "digit",
        "?h": "hex (lowercase)",
        "?H": "hex (uppercase)",
        "?s": "special",
        "?a": "alphanumeric+special",
        "?b": "byte",
        "??": "literal ?",
    }

    if token in descriptions:
        return descriptions[token]

    # Custom charset reference
    if token in ("?1", "?2", "?3", "?4"):
        return f"custom charset {token[1]}"

    return token


def format_hcmask_line(custom: list[str], mask: str) -> str:
    """Format custom charsets and mask into a canonical hcmask line.

    Escapes any literal commas in custom charset fields as ``\\,`` and
    joins all fields with commas.

    Args:
        custom: List of custom charset strings (0-4 items).
        mask: The mask string.

    Returns:
        A formatted hcmask line string.
    """
    fields = []

    # Escape custom charsets
    for charset in custom:
        escaped = charset.replace(",", "\\,")
        fields.append(escaped)

    # Add mask (no escaping needed for mask field)
    fields.append(mask)

    return ",".join(fields)
