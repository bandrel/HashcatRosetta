"""Tests for natural-language to hcmask generation (nlmask.py).

Uses a fake OpenAI-shaped client so no real network access is required.
"""

import json
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
        self.calls.append(_Call(kwargs=kwargs))
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
