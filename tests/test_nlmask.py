"""Tests for natural-language to hcmask generation (nlmask.py).

Uses a fake OpenAI-shaped client so no real network access is required.
"""

import copy
import json
import subprocess
import sys
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from openai import APIConnectionError

from hashcat_rosetta.mask import HcmaskLine
from hashcat_rosetta.nlmask import (
    MASK_SCHEMA,
    SYSTEM_PROMPT,
    MaskGenerationError,
    MaskSuggestion,
    generate_masks,
    resolve_base_url,
)
from hashcat_rosetta.nlmask import _build_retry_message, _validate_items


def _make_response(content: str) -> SimpleNamespace:
    """Build an object shaped like the OpenAI SDK's ChatCompletion response."""
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


@dataclass
class _Call:
    kwargs: dict


class FakeCompletions:
    """Fake `.chat.completions` implementing only `.create(...)`."""

    def __init__(self, responses: list[str]):
        # Each entry is the raw `content` string for one call, in order.
        self._responses = list(responses)
        self.calls: list[_Call] = []

    def create(self, **kwargs):
        # Deep-copy before storing: nlmask.py currently passes the same
        # extra_body dict object to both the initial and retry calls. If a
        # future change started mutating that dict between calls instead of
        # rebuilding it, a shallow/by-reference capture here would silently
        # show call 0's *mutated* extra_body when inspected after the fact,
        # masking the regression instead of catching it.
        self.calls.append(_Call(kwargs=copy.deepcopy(kwargs)))
        if not self._responses:
            raise AssertionError("FakeCompletions.create called more times than responses queued")
        content = self._responses.pop(0)
        return _make_response(content)


class FakeErrorCompletions:
    """Fake `.chat.completions` that always raises a connection error."""

    def __init__(self, exc: Exception):
        self._exc = exc
        self.calls: list[_Call] = []

    def create(self, **kwargs):
        self.calls.append(_Call(kwargs=kwargs))
        raise self._exc


class FakeClient:
    """Fake OpenAI client exposing `.chat.completions`."""

    def __init__(self, completions):
        self.chat = SimpleNamespace(completions=completions)


VALID_JSON = json.dumps(
    {
        "masks": [
            {"mask": "?d?d?d?d?d?d", "custom_charsets": [], "why": "six digit pin"},
        ]
    }
)

VALID_JSON_CUSTOM = json.dumps(
    {
        "masks": [
            {"mask": "?1?1?d", "custom_charsets": ["ab"], "why": "custom prefix"},
        ]
    }
)

INVALID_JSON_UNKNOWN_TOKEN = json.dumps(
    {
        "masks": [
            {"mask": "?z?d?d", "custom_charsets": [], "why": "bogus token"},
        ]
    }
)


class TestResolveBaseUrl:
    """Table from clarification #1 plus env var handling."""

    def test_bare_host_port(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert resolve_base_url("localhost:11434") == "http://localhost:11434/v1"

    def test_http_scheme_no_v1(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert resolve_base_url("http://box:11434") == "http://box:11434/v1"

    def test_https_trailing_slash(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert resolve_base_url("https://h/") == "https://h/v1"

    def test_already_has_v1_idempotent(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert resolve_base_url("http://h/v1") == "http://h/v1"

    def test_none_no_env_defaults(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
        assert resolve_base_url(None) == "http://localhost:11434/v1"

    def test_none_uses_env_var(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_HOST", "envhost:9999")
        assert resolve_base_url(None) == "http://envhost:9999/v1"

    def test_explicit_host_overrides_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_HOST", "envhost:9999")
        assert resolve_base_url("explicit:1234") == "http://explicit:1234/v1"


class TestGenerateMasksHappyPath:
    def test_valid_json_first_try_no_retry(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("six digit pin", client=client)

        assert len(completions.calls) == 1
        assert len(result) == 1
        suggestion = result[0]
        assert isinstance(suggestion, MaskSuggestion)
        assert suggestion.mask == "?d?d?d?d?d?d"
        assert suggestion.custom_charsets == []
        assert suggestion.why == "six digit pin"
        assert isinstance(suggestion.line, HcmaskLine)
        assert suggestion.line.mask == "?d?d?d?d?d?d"

    def test_valid_json_with_custom_charset(self):
        completions = FakeCompletions([VALID_JSON_CUSTOM])
        client = FakeClient(completions)

        result = generate_masks("custom prefix", client=client)

        assert len(completions.calls) == 1
        assert result[0].custom_charsets == ["ab"]
        assert result[0].line.custom == ["ab"]

    def test_request_kwargs_include_model_temperature_and_response_format(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks("six digit pin", model="my-model", temperature=0.5, client=client)

        assert len(completions.calls) == 1
        kwargs = completions.calls[0].kwargs
        assert kwargs["model"] == "my-model"
        assert kwargs["temperature"] == 0.5
        assert kwargs["response_format"]["type"] == "json_schema"
        assert kwargs["response_format"]["json_schema"]["schema"] == MASK_SCHEMA
        assert kwargs["response_format"]["json_schema"]["strict"] is True

    def test_ollama_model_env_var_used_when_model_is_none(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_MODEL", "env-model:latest")
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks("six digit pin", model=None, client=client)

        assert completions.calls[0].kwargs["model"] == "env-model:latest"

    def test_extra_options_merged_into_extra_body(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks("six digit pin", client=client, extra_options={"num_ctx": 8192})

        extra_body = completions.calls[0].kwargs["extra_body"]
        assert extra_body["think"] is True
        assert extra_body["options"] == {"num_ctx": 8192}

    def test_no_options_key_when_extra_options_omitted(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks("six digit pin", client=client)

        extra_body = completions.calls[0].kwargs["extra_body"]
        assert "options" not in extra_body

    def test_think_defaults_to_true_in_extra_body(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks("six digit pin", client=client)

        extra_body = completions.calls[0].kwargs["extra_body"]
        # Exact-equality, not just a value check on "think": pins the
        # default request body to contain nothing else, so a stray third
        # key added later wouldn't slip by unnoticed.
        assert extra_body == {"think": True}

    def test_think_false_omits_think_key_entirely(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks("six digit pin", client=client, think=False)

        extra_body = completions.calls[0].kwargs["extra_body"]
        assert "think" not in extra_body

    def test_extra_request_body_merged_and_coexists_with_options(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks(
            "six digit pin",
            client=client,
            extra_options={"num_ctx": 8192},
            extra_request_body={"chat_template_kwargs": {"thinking": False}},
        )

        extra_body = completions.calls[0].kwargs["extra_body"]
        assert extra_body["options"] == {"num_ctx": 8192}
        assert extra_body["chat_template_kwargs"] == {"thinking": False}

    def test_extra_request_body_collision_with_think_wins(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks(
            "six digit pin",
            client=client,
            think=True,
            extra_request_body={"think": False},
        )

        extra_body = completions.calls[0].kwargs["extra_body"]
        assert extra_body["think"] is False

    def test_extra_request_body_collision_with_options_wins(self):
        completions = FakeCompletions([VALID_JSON])
        client = FakeClient(completions)

        generate_masks(
            "six digit pin",
            client=client,
            extra_options={"num_ctx": 8192},
            extra_request_body={"options": {"num_ctx": 4096}},
        )

        extra_body = completions.calls[0].kwargs["extra_body"]
        assert extra_body["options"] == {"num_ctx": 4096}


class TestGenerateMasksRetry:
    def test_invalid_then_valid_triggers_exactly_one_retry(self):
        completions = FakeCompletions([INVALID_JSON_UNKNOWN_TOKEN, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert len(result) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

        # Minor #7: the retry conversation must carry forward context rather
        # than blindly re-asking - the original system+user turns, the
        # assistant's first (invalid) response, and a new user message
        # naming the specific failing mask line and its error.
        first_messages = completions.calls[0].kwargs["messages"]
        retry_messages = completions.calls[1].kwargs["messages"]

        assert retry_messages[0] == first_messages[0]  # system prompt
        assert retry_messages[1] == first_messages[1]  # original user description
        assert retry_messages[2] == {
            "role": "assistant",
            "content": INVALID_JSON_UNKNOWN_TOKEN,
        }
        assert retry_messages[3]["role"] == "user"
        assert "?z?d?d" in retry_messages[3]["content"]
        assert "unknown token" in retry_messages[3]["content"]

    def test_think_and_extra_request_body_honoured_on_retry_too(self):
        completions = FakeCompletions([INVALID_JSON_UNKNOWN_TOKEN, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks(
            "something",
            client=client,
            think=False,
            extra_request_body={"chat_template_kwargs": {"thinking": False}},
        )

        assert len(completions.calls) == 2
        assert len(result) == 1

        for call in completions.calls:
            extra_body = call.kwargs["extra_body"]
            assert "think" not in extra_body
            assert extra_body["chat_template_kwargs"] == {"thinking": False}

    def test_extra_request_body_honoured_on_retry_with_think_left_at_default(self):
        completions = FakeCompletions([INVALID_JSON_UNKNOWN_TOKEN, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks(
            "something",
            client=client,
            extra_request_body={"chat_template_kwargs": {"thinking": False}},
        )

        assert len(completions.calls) == 2
        assert len(result) == 1

        for call in completions.calls:
            extra_body = call.kwargs["extra_body"]
            assert extra_body["think"] is True
            assert extra_body["chat_template_kwargs"] == {"thinking": False}

    def test_invalid_twice_raises(self):
        completions = FakeCompletions([INVALID_JSON_UNKNOWN_TOKEN, INVALID_JSON_UNKNOWN_TOKEN])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError) as exc_info:
            generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert "?z?d?d" in str(exc_info.value)

    def test_malformed_json_first_call_retries_then_succeeds(self):
        malformed = "```json\n{not valid json"
        completions = FakeCompletions([malformed, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert len(result) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_malformed_json_both_calls_raises(self):
        malformed = "not json at all"
        completions = FakeCompletions([malformed, malformed])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError):
            generate_masks("something", client=client)

        assert len(completions.calls) == 2

    def test_json_wrapped_in_markdown_fence_parses_on_first_try(self):
        fenced = f"```json\n{VALID_JSON}\n```"
        completions = FakeCompletions([fenced])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_json_after_leaked_think_block_parses_on_first_try(self):
        leaked = f"Here's a thinking process:\n1. Do the thing.</think>{VALID_JSON}"
        completions = FakeCompletions([leaked])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_json_after_two_leaked_think_blocks_parses_on_first_try(self):
        leaked = f"Thinking...</think>Reconsidering...</think>{VALID_JSON}"
        completions = FakeCompletions([leaked])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 1
        assert result[0].mask == "?d?d?d?d?d?d"


NON_DICT_TOP_LEVEL_JSON = json.dumps([{"mask": "?d", "custom_charsets": [], "why": "x"}])

NON_DICT_ITEM_JSON = json.dumps({"masks": ["?d?d"]})

EMPTY_MASKS_JSON = json.dumps({"masks": []})


class TestGenerateMasksMalformedShapes:
    """Important #1/#2/#3: non-dict top-level JSON, non-dict items, empty masks array."""

    def test_non_dict_top_level_json_retries_then_succeeds(self):
        completions = FakeCompletions([NON_DICT_TOP_LEVEL_JSON, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert len(result) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_non_dict_top_level_json_both_calls_raises(self):
        completions = FakeCompletions([NON_DICT_TOP_LEVEL_JSON, NON_DICT_TOP_LEVEL_JSON])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError):
            generate_masks("something", client=client)

        assert len(completions.calls) == 2

    def test_non_dict_item_in_masks_array_retries_then_succeeds(self):
        completions = FakeCompletions([NON_DICT_ITEM_JSON, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert len(result) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_non_dict_item_in_masks_array_both_calls_raises(self):
        completions = FakeCompletions([NON_DICT_ITEM_JSON, NON_DICT_ITEM_JSON])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError) as exc_info:
            generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert "not an object" in str(exc_info.value)

    def test_empty_masks_array_retries_then_succeeds(self):
        completions = FakeCompletions([EMPTY_MASKS_JSON, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert len(result) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_empty_masks_array_both_calls_raises(self):
        completions = FakeCompletions([EMPTY_MASKS_JSON, EMPTY_MASKS_JSON])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError) as exc_info:
            generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert "no mask suggestions" in str(exc_info.value)


class TestGenerateMasksConnectionError:
    def test_connection_error_wrapped_with_base_url(self):
        request = SimpleNamespace()
        exc = APIConnectionError(request=request)
        completions = FakeErrorCompletions(exc)
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError) as exc_info:
            generate_masks("something", client=client, host="http://nowhere:9999")

        assert "http://nowhere:9999/v1" in str(exc_info.value)


class TestRealClientTimeout:
    """The OpenAI SDK's defaults (600s read timeout x up to 3 attempts) let a
    saturated/hung server block an interactive CLI call for 30 minutes. When
    no test double is injected, the real client must be built with a much
    tighter bound so a dead server fails fast instead of hanging.
    """

    def test_real_client_constructed_with_bounded_timeout_and_no_sdk_retries(self, monkeypatch):
        captured = {}

        class _FakeOpenAI:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.chat = SimpleNamespace(completions=FakeCompletions([VALID_JSON]))

        monkeypatch.setattr("hashcat_rosetta.nlmask.OpenAI", _FakeOpenAI)

        try:
            generate_masks("something", host="http://nowhere:9999")
        except Exception:
            pass  # the fake client's canned response isn't the point of this test

        assert captured, "OpenAI(...) was never constructed"
        assert captured.get("max_retries") == 0
        timeout = captured.get("timeout")
        assert timeout is not None, "no explicit timeout passed to OpenAI(...)"
        # httpx.Timeout or a plain float/int are both acceptable; either way
        # every leg must be well under the SDK's own 600s x 3-attempt default
        # (i.e. under 1800s), even though 600s itself is no longer "tight" —
        # category-enumeration prompts measured at ~250s on gemma3:27b alone.
        if isinstance(timeout, (int, float)):
            assert timeout <= 600
        else:
            for leg in ("connect", "read", "write", "pool"):
                value = getattr(timeout, leg, None)
                if value is not None:
                    assert value <= 600, f"{leg} timeout {value}s is not tightly bounded"


class TestModuleConstants:
    def test_mask_schema_shape(self):
        assert MASK_SCHEMA["type"] == "object"
        assert "masks" in MASK_SCHEMA["properties"]
        assert MASK_SCHEMA["required"] == ["masks"]
        assert MASK_SCHEMA["additionalProperties"] is False

        item_schema = MASK_SCHEMA["properties"]["masks"]["items"]
        assert set(item_schema["required"]) == {"mask", "custom_charsets", "why"}
        assert item_schema["additionalProperties"] is False

    def test_system_prompt_mentions_key_constraints(self):
        assert "{n}" in SYSTEM_PROMPT
        assert "?1" in SYSTEM_PROMPT
        assert "?d" in SYSTEM_PROMPT
        assert "why" in SYSTEM_PROMPT


NON_STRING_MASK_JSON = json.dumps(
    {"masks": [{"mask": 123, "custom_charsets": [], "why": "a number, not a mask"}]}
)

STRING_CUSTOM_CHARSETS_JSON = json.dumps(
    {"masks": [{"mask": "?1?1", "custom_charsets": "abc", "why": "string, not an array"}]}
)

NON_STRING_CHARSET_ELEMENT_JSON = json.dumps(
    {"masks": [{"mask": "?1?1", "custom_charsets": ["ab", 7], "why": "element is a number"}]}
)


class TestGenerateMasksWronglyTypedFields:
    """Model output is untrusted: wrongly-typed fields must be validation
    failures feeding the retry, never an uncaught TypeError/AttributeError."""

    def test_validate_items_does_not_raise_on_non_string_mask(self):
        suggestions, failures = _validate_items([{"mask": 123, "custom_charsets": [], "why": "x"}])
        assert suggestions == []
        assert len(failures) == 1
        assert "'mask' must be a string" in failures[0][1]
        assert "int" in failures[0][1]

    def test_validate_items_does_not_silently_split_a_string_charset(self):
        # A bare string used to iterate character-by-character into three
        # single-char custom charsets, silently producing a wrong mask.
        suggestions, failures = _validate_items(
            [{"mask": "?1?1", "custom_charsets": "abc", "why": "x"}]
        )
        assert suggestions == []
        assert len(failures) == 1
        assert "'custom_charsets' must be an array of strings" in failures[0][1]

    def test_validate_items_rejects_non_string_charset_element(self):
        suggestions, failures = _validate_items(
            [{"mask": "?1?1", "custom_charsets": ["ab", 7], "why": "x"}]
        )
        assert suggestions == []
        assert len(failures) == 1
        assert "custom_charsets[1] must be a string" in failures[0][1]

    def test_failures_render_into_a_retry_prompt_without_raising(self):
        _, failures = _validate_items(
            [
                {"mask": 123, "custom_charsets": [], "why": "x"},
                {"mask": "?1?1", "custom_charsets": "abc", "why": "x"},
            ]
        )
        message = _build_retry_message(failures)
        assert "'mask' must be a string" in message
        assert "'custom_charsets' must be an array of strings" in message

    def test_non_string_mask_retries_then_succeeds(self):
        completions = FakeCompletions([NON_STRING_MASK_JSON, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert len(result) == 1
        assert result[0].mask == "?d?d?d?d?d?d"

    def test_non_string_mask_both_calls_raises_mask_generation_error(self):
        completions = FakeCompletions([NON_STRING_MASK_JSON, NON_STRING_MASK_JSON])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError) as exc_info:
            generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert "'mask' must be a string" in str(exc_info.value)

    def test_string_custom_charsets_both_calls_raises_mask_generation_error(self):
        completions = FakeCompletions([STRING_CUSTOM_CHARSETS_JSON, STRING_CUSTOM_CHARSETS_JSON])
        client = FakeClient(completions)

        with pytest.raises(MaskGenerationError) as exc_info:
            generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert "'custom_charsets' must be an array of strings" in str(exc_info.value)

    def test_non_string_charset_element_retries_then_succeeds(self):
        completions = FakeCompletions([NON_STRING_CHARSET_ELEMENT_JSON, VALID_JSON])
        client = FakeClient(completions)

        result = generate_masks("something", client=client)

        assert len(completions.calls) == 2
        assert result[0].mask == "?d?d?d?d?d?d"


class TestImportIsolation:
    """nlmask is the only module importing the openai SDK, and it is loaded
    lazily so non-LLM commands do not pay its import cost."""

    def test_importing_package_does_not_import_openai(self):
        code = (
            "import sys; import hashcat_rosetta, hashcat_rosetta.cli; "
            "assert 'openai' not in sys.modules, 'openai was imported eagerly'; "
            "assert 'hashcat_rosetta.nlmask' not in sys.modules"
        )
        subprocess.run([sys.executable, "-c", code], check=True)

    def test_lazy_attribute_access_still_works(self):
        code = (
            "from hashcat_rosetta import generate_masks, MaskGenerationError, MaskSuggestion; "
            "import hashcat_rosetta; assert hashcat_rosetta.generate_masks is generate_masks; "
            "assert 'generate_masks' in dir(hashcat_rosetta)"
        )
        subprocess.run([sys.executable, "-c", code], check=True)

    def test_unknown_attribute_still_raises_attribute_error(self):
        import hashcat_rosetta

        with pytest.raises(AttributeError):
            # getattr(), not attribute syntax: a literal bad attribute is a
            # static error mypy rightly flags on a module with __all__.
            getattr(hashcat_rosetta, "definitely_not_a_real_export")


class TestCategoryDescriptionsAgainstLiveOllama:
    """A description naming a category ("mushroom varieties") rather than a
    literal word must expand into concrete member words crossed with the
    requested pattern(s), not a bare pattern with no basewords. Requires a
    reachable local Ollama; skipped otherwise, matching the hashcat-binary
    integration convention elsewhere in this suite.
    """

    @pytest.mark.integration
    def test_category_description_yields_literal_basewords(self):
        try:
            suggestions = generate_masks(
                "Basewords should be based on mushroom varieties followed by "
                "one of the following patters. [symbol+digit,digit+symbol]"
            )
        except MaskGenerationError as exc:
            pytest.skip(f"Ollama not reachable: {exc}")

        assert len(suggestions) >= 2
        for suggestion in suggestions:
            literal_prefix = suggestion.mask.split("?")[0]
            assert literal_prefix, (
                f"expected a literal baseword prefix in {suggestion.mask!r}, "
                "got a pattern with no basewords"
            )
