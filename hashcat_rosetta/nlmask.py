"""Natural-language to hcmask generation via a local LLM.

This is the only module in the package that talks to a network or imports
``openai``. It sends an English description to a local Ollama server (using
Ollama's OpenAI-compatible chat completions endpoint), asks for one or more
hashcat mask suggestions in a strict JSON schema, and validates every
suggested line through :mod:`hashcat_rosetta.mask` before returning it to the
caller.

Import isolation invariant: this module is the *only* place in the package
that imports the third-party ``openai`` SDK. ``cli.py`` and ``__init__.py``
do import names from here (``generate_masks``, ``MaskGenerationError``,
``MaskSuggestion``) — that is expected — but they do so lazily, so that the
cost of importing ``openai`` is paid only when the mask-generation feature is
actually used. ``mask.py`` does not import this module at all; the dependency
runs the other way.
"""

import json
import os
import sys
from dataclasses import dataclass
from typing import Any

from openai import APIConnectionError, APIStatusError, OpenAI

from .mask import (
    HcmaskLine,
    MaskError,
    format_hcmask_line,
    parse_hcmask_line,
    verify_keyspace_with_maskprocessor,
)

# Default model used when neither the ``model`` argument nor the
# ``OLLAMA_MODEL`` environment variable is set.
#
# Full 20-prompt scripts/benchmark_mask_models.py sweep after SYSTEM_PROMPT
# changed to fix the '[...]' bracket hallucination, the arbitrary "always
# pick 6" category cap (now up to 15, real category size permitting), and
# the '?u??literal' word-decomposition bug:
#   gemma3:27b                           — 0 hard fails, 6 soft, mean 4.2, 234s  <- this pick
#   dengcao/Qwen3-30B-A3B-Instruct-2507   — 2 hard fails, 4 soft, mean 4.4, 170s
#   laguna-xs-2.1:latest                  — 5 hard fails, 3 soft, mean 4.2, 781s
# gemma3:27b is the only candidate with zero hard fails, matching the
# benchmark's own recommendation criteria — it stays the default. dengcao is
# faster and scores marginally higher on mean judge score, but its 2 hard
# fails (both a dangling-'?' custom-charset error when a symbol set
# includes a literal '?' without escaping it as '??' — a real gap, not a
# quirk of this sweep) rule it out as a default despite an earlier 2-prompt
# spot-check missing that failure mode.
_DEFAULT_MODEL = "gemma3:27b"

# Default Ollama base URL when neither ``host`` nor ``OLLAMA_HOST`` is set.
_DEFAULT_BASE_URL = "http://localhost:11434/v1"


class MaskGenerationError(Exception):
    """Raised when mask generation fails.

    Covers network/connection failures talking to the model server, and the
    case where model output still fails hcmask validation after one retry.
    """


@dataclass
class MaskSuggestion:
    """A single validated hcmask suggestion returned by the model.

    Attributes:
        mask: The mask field as suggested by the model (before custom
            charsets are prepended), e.g. ``"?1?1?d"``.
        custom_charsets: The custom charset strings (0-8 items) the model
            supplied for this suggestion.
        why: A one-clause human-readable rationale for the suggestion.
        line: The parsed, validated :class:`~hashcat_rosetta.mask.HcmaskLine`
            for this suggestion, so callers can compute keyspace/description
            without re-parsing.
    """

    mask: str
    custom_charsets: list[str]
    why: str
    line: HcmaskLine


# The JSON schema for a single mask suggestion object.
_MASK_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mask": {
            "type": "string",
            "description": (
                "The hcmask mask field, e.g. 'Summer?d?d?d?d?d?d' or, when "
                "referencing custom charsets, 'abc,?1?1?d'."
            ),
        },
        "custom_charsets": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "0-8 custom charset strings referenced in the mask as "
                "?1-?8, in order. Empty array if the mask uses no custom "
                "charsets."
            ),
        },
        "why": {
            "type": "string",
            "description": "One short clause explaining the suggestion. No step-by-step reasoning.",
        },
    },
    "required": ["mask", "custom_charsets", "why"],
    "additionalProperties": False,
}

# The inner JSON schema describing the full response shape:
# {"masks": [{"mask": ..., "custom_charsets": [...], "why": ...}, ...]}
#
# This constant holds the *inner* schema dict (not the full
# response_format wrapper with "name"/"strict" keys); generate_masks() wraps
# it into that structure at call time.
MASK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "masks": {
            "type": "array",
            "items": _MASK_ITEM_SCHEMA,
        }
    },
    "required": ["masks"],
    "additionalProperties": False,
}

SYSTEM_PROMPT = """You are a hashcat mask (hcmask) generator. Given an English \
description of passwords to target, produce one or more hcmask candidate patterns.

## hcmask grammar reference

Builtin charset tokens (each is two characters, a '?' followed by a letter):
  ?l  lowercase a-z
  ?u  uppercase A-Z
  ?d  digit 0-9
  ?h  lowercase hex 0-9a-f
  ?H  uppercase hex 0-9A-F
  ?s  hashcat "specials" (punctuation/symbols)
  ?a  all printable (?l + ?u + ?d + ?s)
  ?b  all 256 byte values

?s, ?a, and ?b are each already a COMPLETE, ready-to-use charset covering
their entire class — ?s already contains every hashcat "special"
character, ?a already contains every letter/digit/special, ?b already
contains all 256 byte values. NEVER attempt to reproduce, re-list, or
hand-spell out the characters any of these three already cover — not in
the mask, not in a custom charset. Doing so is always redundant (the
builtin token already says it) and always error-prone (hand-typing
hashcat's specials list reliably introduces an unescaped '?' or an
invalid token like '?/'). If the request is for "a special character" /
"any symbol" / "punctuation" in general, the answer is simply the token
?s used directly — nothing else needs to be written for it.

These 8 are the ONLY builtin '?X' tokens. There is no '?@', '?/', '?w', or
any other '?<character>' token beyond this list and '??' below, no matter
how intuitively it might seem to abbreviate something (e.g. '?@' is NOT
"the at sign" — it's simply invalid). Any '?X' not in this list or not a
?1-?8 custom charset reference is always a mistake — if you need one
specific symbol, write it as a literal character or put it in a custom
charset, never as a made-up '?X' token.

'??' is a literal '?' character, not a token. This '??' escaping rule applies
INSIDE custom charset fields too, not just the mask field: if a custom
charset must contain a literal '?' character (e.g. a symbol set that
includes '?' itself), write it as '??' there as well — a bare trailing or
embedded '?' in a custom charset is a dangling/malformed token, not a
literal question mark.

You may define up to 8 custom charsets (strings of characters). Do NOT inline
them into the mask string — return them separately in the `custom_charsets`
array, and reference them from the mask as ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 in
the order given. Custom charsets have no range shorthand either — NO "0-9"
or "a-z" syntax; write out every character explicitly (e.g. "0123456789",
not "0-9").

Distinguish a GENERIC character class from a SPECIFIC restricted set — this
determines whether to use a builtin token or a custom charset:
  - GENERIC / unbounded, e.g. "a special character", "a symbol", "a digit",
    "a lowercase letter" (no specific characters named): use the matching
    builtin token (?s, ?d, ?l, ?u) directly. Do NOT spell out hashcat's full
    specials list as literal characters in the mask or as a custom charset —
    it's unnecessary, error-prone, and never what "a symbol" means. WRONG:
    custom_charsets ["!@#$%^&*()_+-=[]{}|;:,.<>?"] for "a special char".
    RIGHT: mask uses "?s" directly, no custom charset needed.
  - SPECIFIC / restricted, e.g. "one of these symbols: !@#$%", "a vowel"
    (only a,e,i,o,u), "the digits 1, 2, and 3": ALWAYS define a custom
    charset containing exactly the named characters, even if they're a
    subset of what a builtin token would cover. Never substitute the
    broader builtin token (?s, ?l, ?d) for a named restricted set, and
    never pick just one representative character instead of defining the
    charset.
  - There is exactly ONE correct way to express a GENERIC class: the
    builtin token. Never additionally emit a second suggestion that
    hand-spells the same generic class as a custom charset "for variety" —
    that is not a distinct pattern, it's the same idea restated in a form
    that's guaranteed to be wrong (hashcat's specials cannot be
    hand-enumerated into a custom charset without an escaping error). When
    asked for "as many distinct suggestions as you can," vary the literal
    basewords or token counts/order, never re-express the same generic
    charset a second way.

Literal characters in the mask (anything that is not a '?' token) are used
as-is, e.g. "Summer" in "Summer?d?d?d?d?d?d" is a literal prefix.

## Hard constraints

- NO '{n}' repetition syntax. Hashcat mask files do not support it. Expand
  repeats explicitly: six digits is "?d?d?d?d?d?d", not "?d{6}".
- The mask field is limited to 256 positions total (hashcat's own hard
  limit) — one position per token or literal character ('??' counts as one
  position, not two). This should never come up for a normal request, but
  never pad a mask with excessive repeats to reach an arbitrary length.
- The `mask` field must never be empty. Hashcat itself rejects an empty
  mask outright ("Invalid mask length (0)."). Even a request for a single
  fixed literal word with no digits/symbols/pattern still needs that word
  as the mask (e.g. mask "Summer", not an empty string).
- NO '[...]' bracket character classes. Hashcat masks have no regex-style
  character-class syntax — '[' and ']' are ordinary literal characters, the
  same as any letter. To express "one of these characters at this position,"
  define a custom charset containing exactly those characters and put it in
  the `custom_charsets` array, then reference it as ?1-?8 in the `mask`
  field. WRONG: mask "Patriots?d?d[ea34@jr?l]" (this is a literal "["
  followed by literal chars, NOT a character class). RIGHT: custom_charsets
  ["ea34@jr?l"], mask "Patriots?d?d?1".
- Never emit two suggestions with the same `mask` AND the same
  `custom_charsets` — every object in `masks` must be a distinct candidate
  pattern, not a repeat.
- When a description names multiple DISTINCT custom charsets to be used
  once each (e.g. "charset A, then charset B, then charset C, combined as
  ?1?2?3"), each must reference its own charset number in the `mask` —
  never collapse them onto a single repeated reference. WRONG: mask
  "?1?1?1?1" when four different charsets were defined. RIGHT: mask
  "?1?2?3?4", with `custom_charsets` holding all four in order. This holds
  for any count up to 8 distinct charsets, not just four.
- Produce one mask object per distinct candidate pattern requested. If the
  description describes multiple variants (e.g. "summer or winter", "either
  4 or 6 digits"), return multiple objects in the `masks` array, one per
  variant.
- If the description names a CATEGORY of words rather than a single literal
  word (e.g. "mushroom varieties", "months of the year", "NFL team names"),
  emit one mask object per (member word x requested pattern) combination,
  using the member word as a literal prefix/suffix. Never emit a
  pattern-only mask with no literal basewords when the description asks for
  basewords from a category. Pick up to 15 concrete real-world members of
  the category from general knowledge — if the category has 15 or fewer
  real members (e.g. months of the year: 12), list all of them; if it has
  more (e.g. NFL teams: 32, US states: 50), pick 15 diverse, well-known
  ones, not an arbitrary handful like 2 or 3. Do not deliberate over the
  exact count — 15 (or the category's true size if smaller) is always
  correct.
- ANY specific named word chosen as a baseword — a category member (a team
  name, a Bible book, a city), a named literal from the description itself
  ("Summer", "Blue"), or any other real, spelled word — is ALWAYS a plain
  literal string, spelled exactly as it's normally written, never
  decomposed into charset tokens letter-by-letter. This applies whether or
  not the description mentions capitalization. WRONG: mask "?u??aguars?d?d?1"
  for the team "Jaguars", or mask "?l?l?l?l?l?d:?d" for the book "Genesis"
  (both replace real, specific letters with charset tokens that could
  produce any letter, plus a stray literal '?' — ??). RIGHT: mask
  "Jaguars?d?d?1", mask "Genesis?d:?d" — the whole word as one literal.
  Only use ?u/?l/?d ON a specific word's own letters if the description
  explicitly asks for a *varying*/unspecified value there (e.g. "any
  capitalization", "an unknown 3-letter prefix") — never to express "this
  exact, specific word".
- The `why` field must be exactly ONE short clause with no step-by-step
  reasoning or "thinking out loud". Do not explain your reasoning process,
  just state the rationale in a few words.

Return your answer as JSON matching the provided schema."""


def resolve_base_url(host: str | None) -> str:
    """Resolve and normalize the Ollama base URL.

    Args:
        host: An explicit host override, or ``None`` to fall back to the
            ``OLLAMA_HOST`` environment variable.

    Returns:
        A normalized base URL ending in ``/v1``, e.g.
        ``http://localhost:11434/v1``. If ``host`` is ``None`` and
        ``OLLAMA_HOST`` is unset, defaults to ``http://localhost:11434/v1``.

    The normalization performed:
        - If the value has no ``://`` scheme, ``http://`` is prepended.
        - Any trailing ``/`` is stripped.
        - ``/v1`` is appended unless the value already ends with it.
    """
    value = host if host is not None else os.environ.get("OLLAMA_HOST")

    if not value:
        return _DEFAULT_BASE_URL

    if "://" not in value:
        value = f"http://{value}"

    value = value.rstrip("/")

    if not value.endswith("/v1"):
        value = f"{value}/v1"

    return value


def _strip_json_fence(text: str) -> str:
    """Strip a leading/trailing markdown code fence from model output.

    Thinking models occasionally wrap JSON in ```json ... ``` fences (or
    stray text around it) despite being asked for raw JSON via
    ``response_format``. This best-effort helper strips a wrapping fence so
    ``json.loads`` has a better chance of succeeding; if there's no fence,
    the text is returned unchanged.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        # Drop the opening fence line (``` or ```json)
        lines = lines[1:]
        # Drop a trailing fence line, if present
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines)
    return stripped


def _parse_response_json(content: str | None) -> tuple[dict[str, Any] | None, str | None]:
    """Parse model response content as JSON.

    Returns:
        A tuple of ``(parsed, error)``. Exactly one of the two is ``None``:
        ``parsed`` is the decoded object on success (guaranteed to be a
        ``dict``; a top-level JSON value that isn't an object, e.g. a bare
        array or string, is treated as a parse failure), or ``error`` is a
        human-readable message on failure.
    """
    if content is None:
        return None, "model response had no content"

    decoded: Any = None
    decode_error: str | None = None
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError:
        try:
            decoded = json.loads(_strip_json_fence(content))
        except json.JSONDecodeError as exc:
            decode_error = f"could not parse model response as JSON: {exc}"

    if decode_error is not None:
        return None, decode_error

    if not isinstance(decoded, dict):
        return None, (
            f"model response was valid JSON but not a JSON object (got {type(decoded).__name__})"
        )

    return decoded, None


def _check_item_types(index: int, mask_field: Any, custom_charsets: Any) -> str | None:
    """Check that a suggestion item's fields have the expected types.

    Args:
        index: Position of the item in the ``masks`` array (for messages).
        mask_field: The raw ``mask`` value from the model.
        custom_charsets: The raw ``custom_charsets`` value from the model.

    Returns:
        ``None`` if the types are acceptable, otherwise a human-readable
        error message suitable for the retry prompt.
    """
    if not isinstance(mask_field, str):
        return f"item {index}: 'mask' must be a string (got {type(mask_field).__name__})"

    if not isinstance(custom_charsets, list):
        return (
            f"item {index}: 'custom_charsets' must be an array of strings "
            f"(got {type(custom_charsets).__name__})"
        )

    for position, charset in enumerate(custom_charsets):
        if not isinstance(charset, str):
            return (
                f"item {index}: custom_charsets[{position}] must be a string "
                f"(got {type(charset).__name__})"
            )

    return None


def _placeholder_item(item: dict[str, Any]) -> dict[str, Any]:
    """Build a type-safe stand-in for an item with wrongly-typed fields.

    Failure records are later re-rendered through
    :func:`~hashcat_rosetta.mask.format_hcmask_line`, which assumes strings,
    so a badly-typed item is replaced by one whose ``mask`` and
    ``custom_charsets`` are guaranteed to be a ``str`` and a ``list[str]``.
    """
    mask_field = item.get("mask", "")
    custom_charsets = item.get("custom_charsets", [])

    safe_mask = mask_field if isinstance(mask_field, str) else repr(mask_field)
    if isinstance(custom_charsets, list) and all(isinstance(c, str) for c in custom_charsets):
        safe_custom = list(custom_charsets)
    else:
        safe_custom = []

    return {"mask": safe_mask, "custom_charsets": safe_custom, "why": ""}


def _validate_items(
    items: list[Any],
) -> tuple[list[MaskSuggestion], list[tuple[dict[str, Any], str]]]:
    """Validate a list of raw suggestion dicts against hcmask syntax.

    Args:
        items: Raw ``{"mask": ..., "custom_charsets": [...], "why": ...}``
            dicts as decoded from the model's JSON response. Items may be
            malformed (e.g. not objects at all) since this is untrusted
            model output.

    Returns:
        A tuple ``(suggestions, failures)`` where ``suggestions`` holds one
        :class:`MaskSuggestion` per item that validated successfully, and
        ``failures`` holds ``(item, error_message)`` pairs for every item
        that failed to validate. All items are checked, not just the first
        failure. An item that isn't a JSON object, or whose ``mask`` is not
        a string, or whose ``custom_charsets`` is not an array of strings,
        is recorded as a failure (wrapped in a placeholder dict) rather than
        raising.
    """
    suggestions: list[MaskSuggestion] = []
    failures: list[tuple[dict[str, Any], str]] = []

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            placeholder = {"mask": "", "custom_charsets": [], "why": ""}
            failures.append(
                (placeholder, f"item {index} is not an object (got {type(item).__name__})")
            )
            continue

        mask_field = item.get("mask", "")
        custom_charsets = item.get("custom_charsets", [])
        why = item.get("why", "")

        # Model output is untrusted: guard field *types* before handing them
        # to mask.py, which assumes strings. A wrong type here must be a
        # normal validation failure (feeding the retry prompt), never an
        # uncaught TypeError/AttributeError.
        type_error = _check_item_types(index, mask_field, custom_charsets)
        if type_error is not None:
            failures.append((_placeholder_item(item), type_error))
            continue

        raw_line = format_hcmask_line(custom_charsets, mask_field)
        try:
            parsed_line = parse_hcmask_line(raw_line)
        except MaskError as exc:
            failures.append((item, str(exc)))
            continue

        # Independent ground-truth check (hashcat-utils mp64), when
        # available. A mismatch means this module's own keyspace() math is
        # wrong for this line, not that the model did anything wrong — but
        # it's still a genuine validation failure, not something a retry can
        # fix by asking the model to try again. Handled identically to any
        # other validation failure since the outcome (don't return this
        # suggestion) is the same either way.
        mismatch = verify_keyspace_with_maskprocessor(parsed_line)
        if mismatch is not None:
            failures.append((item, mismatch))
            continue

        suggestions.append(
            MaskSuggestion(
                mask=mask_field,
                custom_charsets=list(custom_charsets),
                why=why,
                line=parsed_line,
            )
        )

    return suggestions, failures


def _build_retry_message(failures: list[tuple[dict[str, Any], str]]) -> str:
    """Build the user-facing retry prompt describing each failing mask."""
    lines = [
        "The following mask suggestion(s) failed hcmask validation. "
        "Fix only these and resend the full corrected JSON matching the same schema:"
    ]
    for item, error in failures:
        mask_field = item.get("mask", "")
        custom_charsets = item.get("custom_charsets", [])
        raw_line = format_hcmask_line(custom_charsets, mask_field)
        lines.append(f'- "{raw_line}": {error}')
    return "\n".join(lines)


def _print_reasoning(message: Any, label: str) -> None:
    """Print a model's hidden reasoning trace to stderr, if present.

    Ollama surfaces reasoning content (when ``think`` is requested) as a
    ``reasoning`` field alongside ``content`` on the response message. It
    isn't part of the OpenAI SDK's typed schema, so it only shows up via
    ``model_extra`` rather than as a normal attribute.
    """
    reasoning = getattr(message, "reasoning", None) or (message.model_extra or {}).get("reasoning")
    if reasoning:
        print(f"--- {label} thinking ---\n{reasoning}\n--- end thinking ---", file=sys.stderr)


def generate_masks(
    description: str,
    *,
    model: str | None = None,
    host: str | None = None,
    temperature: float = 0.0,
    client: Any = None,
    debug: bool = False,
) -> list[MaskSuggestion]:
    """Generate hcmask suggestions for an English description via a local LLM.

    Sends ``description`` to a local Ollama server (OpenAI-compatible chat
    completions API), asking for JSON matching :data:`MASK_SCHEMA`. Every
    suggested mask line is validated through
    :func:`hashcat_rosetta.mask.parse_hcmask_line`. If any line fails
    validation (or the response isn't valid JSON), one retry turn is sent in
    the same conversation, listing the failures and asking for a corrected
    response. If validation still fails after the retry, raises
    :class:`MaskGenerationError`.

    Requests are sent with ``think`` enabled — since a slow/hybrid-reasoning
    model already costs the full round-trip time either way, letting it think
    tends to improve suggestion quality instead of wasting that time. Ollama
    isolates reasoning into a separate ``reasoning`` field rather than folding
    it into ``content``, so this doesn't interfere with the structured JSON
    response.

    Args:
        description: An English description of the passwords to target.
        model: Model name to request. Falls back to the ``OLLAMA_MODEL``
            environment variable, then to a built-in default.
        host: Ollama base URL/host override. See :func:`resolve_base_url`.
        temperature: Sampling temperature for the chat completion.
        client: An optional pre-built client (e.g. a test double) exposing
            ``.chat.completions.create(...)`` with the same signature as the
            OpenAI SDK client. When omitted, a real ``OpenAI`` client is
            constructed against the resolved base URL.
        debug: When True, print the model's reasoning trace (if any) to
            stderr for each request made (initial and retry).

    Returns:
        A list of validated :class:`MaskSuggestion` objects.

    Raises:
        MaskGenerationError: If the model server can't be reached, or if
            suggested mask lines still fail hcmask validation (or the
            response still isn't valid JSON) after one retry.
    """
    base_url = resolve_base_url(host)
    resolved_model = model if model is not None else os.environ.get("OLLAMA_MODEL", _DEFAULT_MODEL)

    active_client: Any = (
        client
        if client is not None
        else OpenAI(
            base_url=base_url,
            api_key="ollama",
            # The SDK's defaults (600s read timeout x up to 3 attempts) let a
            # hung/saturated server block this interactive CLI call for 30
            # minutes. Fail fast instead: one attempt, generous but bounded.
            # 600s (not the previous 180s) because category-enumeration
            # requests (e.g. "NFL teams") make the model emit up to 15 full
            # mask objects, which measured at ~250s on gemma3:27b alone —
            # 180s cut those requests off before they could finish.
            timeout=600.0,
            max_retries=0,
        )
    )

    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "hcmask_suggestions",
            "strict": True,
            "schema": MASK_SCHEMA,
        },
    }

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": description},
    ]

    try:
        response = active_client.chat.completions.create(
            model=resolved_model,
            temperature=temperature,
            messages=messages,
            response_format=response_format,
            extra_body={"think": True},
        )
    except (APIConnectionError, APIStatusError) as exc:
        raise MaskGenerationError(f"could not reach Ollama at {base_url}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - network/SDK failures must not escape uncaught
        raise MaskGenerationError(f"request to Ollama at {base_url} failed: {exc}") from exc

    if debug:
        _print_reasoning(response.choices[0].message, "initial")

    assistant_content = response.choices[0].message.content
    parsed, parse_error = _parse_response_json(assistant_content)

    failures: list[tuple[dict[str, Any], str]] = []
    suggestions: list[MaskSuggestion] = []

    if parsed is None:
        failures = [({"mask": ""}, parse_error or "invalid JSON")]
    else:
        items = parsed.get("masks", [])
        if not items:
            failures = [({"mask": ""}, "response contained an empty 'masks' array")]
        else:
            suggestions, failures = _validate_items(items)

    if not failures:
        return suggestions

    # One retry: append the assistant's prior response, then a user message
    # describing every failure, and ask for a corrected full response.
    messages.append({"role": "assistant", "content": assistant_content or ""})
    messages.append({"role": "user", "content": _build_retry_message(failures)})

    try:
        retry_response = active_client.chat.completions.create(
            model=resolved_model,
            temperature=temperature,
            messages=messages,
            response_format=response_format,
            extra_body={"think": True},
        )
    except (APIConnectionError, APIStatusError) as exc:
        raise MaskGenerationError(f"could not reach Ollama at {base_url}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - network/SDK failures must not escape uncaught
        raise MaskGenerationError(f"request to Ollama at {base_url} failed: {exc}") from exc

    if debug:
        _print_reasoning(retry_response.choices[0].message, "retry")

    retry_content = retry_response.choices[0].message.content
    retry_parsed, retry_parse_error = _parse_response_json(retry_content)

    if retry_parsed is None:
        raise MaskGenerationError(
            f"model response was not valid JSON after retry: {retry_parse_error}"
        )

    retry_items = retry_parsed.get("masks", [])

    if not retry_items:
        raise MaskGenerationError(
            f"model returned no mask suggestions for this description: {description!r}"
        )

    retry_suggestions, retry_failures = _validate_items(retry_items)

    if retry_failures:
        details = "; ".join(
            f'"{format_hcmask_line(item.get("custom_charsets", []), item.get("mask", ""))}": {error}'
            for item, error in retry_failures
        )
        raise MaskGenerationError(f"mask suggestions still invalid after retry: {details}")

    return retry_suggestions
