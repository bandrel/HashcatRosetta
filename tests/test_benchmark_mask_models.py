"""Tests for scripts/benchmark_mask_models.py — pure-logic pieces only.

The benchmark script lives in scripts/ (not in the package), so we import it
via importlib, matching the convention in tests/test_opcode_sweep.py.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from hashcat_rosetta.mask import parse_hcmask_line
from hashcat_rosetta.nlmask import MaskSuggestion

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "benchmark_mask_models.py"
_spec = importlib.util.spec_from_file_location("benchmark_mask_models", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
benchmark_mask_models = importlib.util.module_from_spec(_spec)
sys.modules["benchmark_mask_models"] = benchmark_mask_models
_spec.loader.exec_module(benchmark_mask_models)


def _suggestion(
    mask_str: str, custom: list[str] | None = None, why: str = "test"
) -> MaskSuggestion:
    """Build a real, parsed MaskSuggestion for a hand-written hcmask line."""
    custom = custom or []
    if custom:
        raw = ",".join(custom) + "," + mask_str
    else:
        raw = mask_str
    line = parse_hcmask_line(raw)
    return MaskSuggestion(mask=mask_str, custom_charsets=custom, why=why, line=line)


class TestPromptResultAndModelReport:
    def test_model_report_aggregates_hard_fails_and_scores(self):
        results = [
            benchmark_mask_models.PromptResult("a", 1.0, None, 5),
            benchmark_mask_models.PromptResult("b", 2.0, "bad output", None),
            benchmark_mask_models.PromptResult("c", 1.5, None, 3),
        ]
        report = benchmark_mask_models.ModelReport("test-model", 4.2, results)

        assert report.hard_fail_count == 1
        assert report.judge_scores == [5, 3]
        assert report.mean_judge_score == 4.0
        assert report.min_judge_score == 3
        assert report.total_seconds == 4.5

    def test_model_report_with_no_judge_scores(self):
        results = [benchmark_mask_models.PromptResult("a", 1.0, "hard fail", None)]
        report = benchmark_mask_models.ModelReport("test-model", 1.0, results)

        assert report.judge_scores == []
        assert report.mean_judge_score is None
        assert report.min_judge_score is None


class TestSummerDigitsChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[0].check(suggestions)
        assert result is None

    def test_wrong_keyspace_fails(self):
        suggestions = [_suggestion("Summer?d?d?d?d?d")]  # only 5 digits
        result = benchmark_mask_models.PROMPTS[0].check(suggestions)
        assert result is not None
        assert "keyspace" in result

    def test_multiple_suggestions_fails(self):
        suggestions = [_suggestion("Summer?d?d?d?d?d?d"), _suggestion("Winter?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[0].check(suggestions)
        assert result is not None
        assert "1 suggestion" in result


class TestMushroomCategoriesChecker:
    def test_multiple_literal_basewords_pass(self):
        suggestions = [
            _suggestion("Chanterelle?s?d"),
            _suggestion("Chanterelle?d?s"),
            _suggestion("Morel?s?d"),
        ]
        result = benchmark_mask_models.PROMPTS[1].check(suggestions)
        assert result is None

    def test_pattern_only_mask_fails(self):
        suggestions = [_suggestion("?s?d"), _suggestion("?d?s")]
        result = benchmark_mask_models.PROMPTS[1].check(suggestions)
        assert result is not None
        assert "literal baseword" in result

    def test_single_suggestion_fails(self):
        suggestions = [_suggestion("Morel?s?d")]
        result = benchmark_mask_models.PROMPTS[1].check(suggestions)
        assert result is not None
        assert ">= 2" in result


class TestSeasonDigitsSpecialChecker:
    def test_correct_tokens_pass(self):
        suggestions = [_suggestion("?u?l?l?l?l?l?d?d?s")]
        result = benchmark_mask_models.PROMPTS[2].check(suggestions)
        assert result is None

    def test_corrupted_special_token_fails(self):
        # The exact qwen2.5:32b bug: "??s?d" parses as literal '?' + literal
        # 's' + digit, not as a real ?s (special) token.
        suggestions = [_suggestion("Summer??s?d")]
        result = benchmark_mask_models.PROMPTS[2].check(suggestions)
        assert result is not None
        assert "?s" in result

    def test_too_few_digits_fails(self):
        suggestions = [_suggestion("Summer?d?s")]
        result = benchmark_mask_models.PROMPTS[2].check(suggestions)
        assert result is not None
        assert "digit" in result


class TestFourOrSixDigitsChecker:
    def test_exactly_two_suggestions_pass(self):
        suggestions = [_suggestion("?d?d?d?d"), _suggestion("?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is None

    def test_one_suggestion_fails(self):
        suggestions = [_suggestion("?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is not None


class TestVowelCustomCharsetChecker:
    def test_correct_custom_charset_passes(self):
        suggestions = [_suggestion("?1?1?1?1?d?d", custom=["aeiou"])]
        result = benchmark_mask_models.PROMPTS[4].check(suggestions)
        assert result is None

    def test_non_vowel_charset_fails(self):
        suggestions = [_suggestion("?1?1?1?1?d?d", custom=["abcde"])]
        result = benchmark_mask_models.PROMPTS[4].check(suggestions)
        assert result is not None
        assert "vowel" in result

    def test_no_custom_charset_fails(self):
        suggestions = [_suggestion("?l?l?l?l?d?d")]
        result = benchmark_mask_models.PROMPTS[4].check(suggestions)
        assert result is not None
        assert "custom charset" in result


class TestHexDigitsChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("?h?h?h?h?d?d")]
        result = benchmark_mask_models.PROMPTS[5].check(suggestions)
        assert result is None

    def test_wrong_hex_count_fails(self):
        suggestions = [_suggestion("?h?h?h?d?d")]
        result = benchmark_mask_models.PROMPTS[5].check(suggestions)
        assert result is not None
        assert "?h" in result


class TestLiteralQuestionMarkChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("???d?d?d")]
        result = benchmark_mask_models.PROMPTS[6].check(suggestions)
        assert result is None

    def test_missing_escape_fails(self):
        # A model that drops the escape entirely and emits a bare '?d?d?d'
        # with no literal '?' at all must fail this check.
        suggestions = [_suggestion("?d?d?d")]
        result = benchmark_mask_models.PROMPTS[6].check(suggestions)
        assert result is not None
        assert "??" in result


class _FakeHTTPResponse:
    """Minimal context-manager stand-in for urllib's response object."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self) -> bytes:
        return self._body


class TestListLocalModels:
    def test_parses_tags_response(self, monkeypatch):
        payload = json.dumps(
            {
                "models": [
                    {"name": "qwen2.5:32b", "size": 19851349669},
                    {"name": "granite4:3b", "size": 2000000000},
                ]
            }
        ).encode()

        def fake_urlopen(url, timeout=None):
            assert "api/tags" in url
            return _FakeHTTPResponse(payload)

        monkeypatch.setattr(benchmark_mask_models.urllib.request, "urlopen", fake_urlopen)

        result = benchmark_mask_models.list_local_models()

        assert result == {"qwen2.5:32b": 19851349669, "granite4:3b": 2000000000}

    def test_empty_models_list(self, monkeypatch):
        payload = json.dumps({"models": []}).encode()
        monkeypatch.setattr(
            benchmark_mask_models.urllib.request,
            "urlopen",
            lambda url, timeout=None: _FakeHTTPResponse(payload),
        )

        assert benchmark_mask_models.list_local_models() == {}


class TestEnsureModelPulled:
    def test_already_present_skips_pull(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.LOCAL_HOST: {"granite4:3b": 123},
        )

        def fail_if_called(*args, **kwargs):
            raise AssertionError(
                "subprocess.run should not be called when model is already present"
            )

        monkeypatch.setattr(benchmark_mask_models.subprocess, "run", fail_if_called)

        assert benchmark_mask_models.ensure_model_pulled("granite4:3b") is True

    def test_pulls_missing_model_successfully(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.LOCAL_HOST: {},
        )
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode=0)

        monkeypatch.setattr(benchmark_mask_models.subprocess, "run", fake_run)

        assert benchmark_mask_models.ensure_model_pulled("granite4:3b") is True
        assert calls == [["ollama", "pull", "granite4:3b"]]

    def test_pull_failure_returns_false(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.LOCAL_HOST: {},
        )
        monkeypatch.setattr(
            benchmark_mask_models.subprocess,
            "run",
            lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, returncode=1),
        )

        assert benchmark_mask_models.ensure_model_pulled("granite4:3b") is False
