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

    # Last field is the mask; all others are custom charsets
    mask = _unescape_field(fields[-1])
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


def _expand_charset(field: str, prior_expanded: list[str], position: int) -> str:
    """Expand one custom charset definition into its literal character set.

    hashcat does not treat a custom charset field as an opaque literal
    string: it scans it for the same ``?X`` tokens the mask field supports.
    ``?l``/``?u``/``?d``/``?h``/``?H``/``?s``/``?a``/``?b`` expand to their
    builtin character sets, ``??`` is a literal ``?``, and ``?1``-``?4`` may
    reference an *earlier* custom charset. Everything else is a literal
    character. hashcat then deduplicates the resulting character set, so
    ``aa`` and ``ab?l`` are 1- and 26-character charsets respectively.

    Args:
        field: The raw (comma-unescaped) custom charset field.
        prior_expanded: Already-expanded charsets defined before this one,
            in order, so ``?1``-``?4`` back-references can be resolved.
        position: 1-based index of this charset (i.e. ``1`` for ``?1``),
            used for error messages and for rejecting self/forward
            references.

    Returns:
        The expanded, deduplicated character set as a string.

    Raises:
        MaskError: On an empty field, a dangling trailing ``?``, an unknown
            ``?X`` token, or a reference to a custom charset that is not
            defined yet.
    """
    if not field:
        raise MaskError(f"custom charset ?{position} is empty")

    chars: list[str] = []
    i = 0
    while i < len(field):
        char = field[i]

        if char == "?":
            if i + 1 >= len(field):
                raise MaskError(f"custom charset ?{position} has a dangling trailing '?'")

            next_char = field[i + 1]

            if next_char == "?":
                # ?? is a literal ?
                chars.append("?")
            elif f"?{next_char}" in BUILTIN_CHARSETS:
                chars.extend(BUILTIN_CHARSETS[f"?{next_char}"])
            elif next_char in "1234":
                ref = int(next_char)
                if ref >= position:
                    raise MaskError(
                        f"custom charset ?{position} references ?{ref}, which is not defined yet"
                    )
                chars.extend(prior_expanded[ref - 1])
            else:
                raise MaskError(f"custom charset ?{position} has unknown token '?{next_char}'")

            i += 2
            continue

        # Literal character
        chars.append(char)
        i += 1

    # hashcat deduplicates the characters of a custom charset
    return "".join(dict.fromkeys(chars))


def expand_custom_charsets(custom: list[str]) -> list[str]:
    """Expand every custom charset definition, resolving back-references.

    Args:
        custom: List of raw custom charset fields (0-4 items), in order.

    Returns:
        The expanded, deduplicated charsets in the same order.

    Raises:
        MaskError: If any field is empty or malformed. See
            :func:`_expand_charset`.
    """
    expanded: list[str] = []
    for position, field in enumerate(custom, start=1):
        expanded.append(_expand_charset(field, expanded, position))
    return expanded


def validate_mask(mask: str, custom: list[str]) -> None:
    """Validate a mask string against a list of custom charsets.

    Args:
        mask: The mask string to validate.
        custom: List of custom charset definitions (0-4 items).

    Raises:
        MaskError: If the mask is invalid (dangling ``?``, unknown token,
            reference to non-existent custom charset, >4 custom charsets, etc.)
            or if any custom charset definition is empty or malformed.
    """
    if len(custom) > 4:
        raise MaskError(f"at most 4 custom charsets allowed, got {len(custom)}")

    # Custom charsets are themselves subject to ?X token grammar; expanding
    # them here rejects empty fields, dangling '?', unknown tokens, and
    # references to charsets that are not defined yet.
    expand_custom_charsets(custom)

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
            if f"?{next_char}" in BUILTIN_CHARSETS:
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
    literals have size 1, tokens have their builtin or custom size. Custom
    charset sizes are the size of the *expanded* charset (see
    :func:`expand_custom_charsets`), not the raw field length.

    Args:
        line: A parsed HcmaskLine.

    Returns:
        List of (token_string, charset_size) pairs in order.
    """
    result = []
    i = 0
    mask = line.mask
    expanded_custom = expand_custom_charsets(line.custom)

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
                if custom_index >= len(expanded_custom):
                    raise MaskError(
                        f"referenced ?{next_char} but only {len(expanded_custom)} "
                        f"custom charset(s) provided"
                    )
                charset = expanded_custom[custom_index]
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
            # Literals always show the full string, never with a count prefix
            parts.append(f'literal "{escaped}"')
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

    # Join parts with ", then " to build the description
    description = ", then ".join(parts)

    # Add keyspace: scientific notation if > 10^9, otherwise just the number
    if ks > 10**9:
        description += f" → {ks_str} (~{_short_scientific(ks)}) candidates"
    else:
        description += f" → {ks_str} candidates"

    return description


def _short_scientific(value: int) -> str:
    """Render a non-negative int in ``d.de+NN`` scientific notation.

    Equivalent to ``f"{value:.1e}"`` but done with pure integer/string math
    so it works for keyspaces beyond the range of a Python ``float``. A mask
    may be up to 256 positions long, so e.g. ``?b`` * 200 has a keyspace of
    ~10^481 — converting that to a float raises ``OverflowError``.

    Args:
        value: A non-negative integer.

    Returns:
        A string like ``2.8e+14``.
    """
    digits = str(value)
    exponent = len(digits) - 1

    # Round to two significant digits using integer math.
    significant = int(digits[:3].ljust(3, "0"))
    rounded = (significant + 5) // 10
    if rounded >= 100:
        rounded //= 10
        exponent += 1

    return f"{rounded // 10}.{rounded % 10}e+{exponent:02d}"


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

    # Escape mask field (commas must be escaped as \,)
    escaped_mask = mask.replace(",", "\\,")
    fields.append(escaped_mask)

    return ",".join(fields)
