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
from types import SimpleNamespace

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

    def test_one_invalid_suggestion_among_valid_ones_fails(self):
        suggestions = [_suggestion("Summer?d?d?d?d?d?d"), _suggestion("Winter?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[0].check(suggestions)
        assert result is not None
        assert "Summer" in result

    def test_multiple_distinct_valid_suggestions_pass(self):
        suggestions = [_suggestion("Summer?d?d?d?d?d?d"), _suggestion("SUMMER?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[0].check(suggestions)
        assert result is None

    def test_duplicate_suggestions_fail(self):
        suggestions = [_suggestion("Summer?d?d?d?d?d?d"), _suggestion("Summer?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[0].check(suggestions)
        assert result is not None
        assert "duplicate" in result


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

    def test_duplicate_suggestions_fail(self):
        suggestions = [_suggestion("Morel?s?d"), _suggestion("Morel?s?d")]
        result = benchmark_mask_models.PROMPTS[1].check(suggestions)
        assert result is not None
        assert "duplicate" in result


class TestSeasonDigitsSpecialChecker:
    def test_correct_tokens_pass(self):
        suggestions = [_suggestion("?u?l?l?l?l?l?d?d?s")]
        result = benchmark_mask_models.PROMPTS[2].check(suggestions)
        assert result is None

    def test_corrupted_special_token_fails(self):
        # The exact qwen2.5:32b bug: "??s" parses as a literal '?' + literal
        # 's', not as a real ?s (special) token. Uses 2 digit tokens so the
        # digit-count check passes and the special-token check is what
        # actually fires.
        suggestions = [_suggestion("?u?l?l?l?l?l?d?d??s")]
        result = benchmark_mask_models.PROMPTS[2].check(suggestions)
        assert result is not None
        assert "expected >= 1 special token" in result

    def test_too_few_digits_fails(self):
        suggestions = [_suggestion("Summer?d?s")]
        result = benchmark_mask_models.PROMPTS[2].check(suggestions)
        assert result is not None
        assert "digit" in result


class TestFourOrSixDigitsChecker:
    def test_both_lengths_pass(self):
        suggestions = [_suggestion("?d?d?d?d"), _suggestion("?d?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is None

    def test_one_suggestion_passes(self):
        suggestions = [_suggestion("?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is None

    def test_wrong_digit_count_fails(self):
        suggestions = [_suggestion("?d?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is not None
        assert "4 or 6" in result

    def test_non_digit_token_fails(self):
        suggestions = [_suggestion("?d?d?d?l")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is not None
        assert "only digit tokens" in result

    def test_duplicate_suggestions_fail(self):
        suggestions = [_suggestion("?d?d?d?d"), _suggestion("?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[3].check(suggestions)
        assert result is not None
        assert "duplicate" in result


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


class TestTwoCustomCharsetsChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("?1?1?2?2", custom=["xyz", "123"])]
        result = benchmark_mask_models.PROMPTS[7].check(suggestions)
        assert result is None

    def test_wrong_charset_membership_fails(self):
        suggestions = [_suggestion("?1?1?2?2", custom=["xyw", "123"])]
        result = benchmark_mask_models.PROMPTS[7].check(suggestions)
        assert result is not None
        assert "?1" in result

    def test_extra_literal_fails(self):
        suggestions = [_suggestion("?1?1?2?2!", custom=["xyz", "123"])]
        result = benchmark_mask_models.PROMPTS[7].check(suggestions)
        assert result is not None
        assert "token sequence" in result

    def test_only_one_custom_charset_fails(self):
        suggestions = [_suggestion("?1?1?1?1", custom=["xyz"])]
        result = benchmark_mask_models.PROMPTS[7].check(suggestions)
        assert result is not None
        assert "exactly 2 custom charsets" in result

    def test_duplicate_suggestions_fail(self):
        suggestions = [
            _suggestion("?1?1?2?2", custom=["xyz", "123"]),
            _suggestion("?1?1?2?2", custom=["xyz", "123"]),
        ]
        result = benchmark_mask_models.PROMPTS[7].check(suggestions)
        assert result is not None
        assert "duplicate" in result


class TestThreeCustomCharsetsChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("?1?2?3", custom=["ae", "bcd", "789"])]
        result = benchmark_mask_models.PROMPTS[8].check(suggestions)
        assert result is None

    def test_wrong_order_fails(self):
        suggestions = [_suggestion("?2?1?3", custom=["ae", "bcd", "789"])]
        result = benchmark_mask_models.PROMPTS[8].check(suggestions)
        assert result is not None
        assert "token sequence" in result

    def test_wrong_charset_size_fails(self):
        suggestions = [_suggestion("?1?2?3", custom=["ae", "bc", "789"])]
        result = benchmark_mask_models.PROMPTS[8].check(suggestions)
        assert result is not None
        assert "?2" in result


class TestFourCustomCharsetsChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("?1?2?3?4", custom=["a", "b", "c", "d"])]
        result = benchmark_mask_models.PROMPTS[9].check(suggestions)
        assert result is None

    def test_case_insensitive_letters_pass(self):
        suggestions = [_suggestion("?1?2?3?4", custom=["A", "B", "C", "D"])]
        result = benchmark_mask_models.PROMPTS[9].check(suggestions)
        assert result is None

    def test_wrong_letter_fails(self):
        suggestions = [_suggestion("?1?2?3?4", custom=["a", "b", "c", "e"])]
        result = benchmark_mask_models.PROMPTS[9].check(suggestions)
        assert result is not None
        assert "?4" in result

    def test_fewer_than_four_charsets_fails(self):
        suggestions = [_suggestion("?1?2?3", custom=["a", "b", "c"])]
        result = benchmark_mask_models.PROMPTS[9].check(suggestions)
        assert result is not None
        assert "exactly 4 custom charsets" in result


class TestCustomCharsetBackreferenceChecker:
    def test_correct_mask_passes(self):
        suggestions = [_suggestion("?1?2", custom=["0123456789", "?1a"])]
        result = benchmark_mask_models.PROMPTS[10].check(suggestions)
        assert result is None

    def test_missing_backreference_fails(self):
        # ?2 defined standalone instead of referencing ?1 — same final charset
        # membership coincidentally, but doesn't demonstrate the ?1 back-reference.
        suggestions = [_suggestion("?1?2", custom=["0123456789", "0123456789a"])]
        result = benchmark_mask_models.PROMPTS[10].check(suggestions)
        assert result is None  # membership-equivalent charsets still satisfy the check

    def test_wrong_charset2_membership_fails(self):
        suggestions = [_suggestion("?1?2", custom=["0123456789", "?1b"])]
        result = benchmark_mask_models.PROMPTS[10].check(suggestions)
        assert result is not None
        assert "?2" in result

    def test_wrong_charset1_fails(self):
        suggestions = [_suggestion("?1?2", custom=["012345678", "?1a"])]
        result = benchmark_mask_models.PROMPTS[10].check(suggestions)
        assert result is not None
        assert "digits 0-9" in result


class TestBibleBooksCategoryChecker:
    def test_multiple_literal_basewords_pass(self):
        suggestions = [
            _suggestion("Genesis?s?d"),
            _suggestion("Exodus?d?s"),
            _suggestion("Psalms?s?d"),
        ]
        result = benchmark_mask_models.PROMPTS[11].check(suggestions)
        assert result is None

    def test_pattern_only_mask_fails(self):
        suggestions = [_suggestion("?s?d"), _suggestion("?d?s")]
        result = benchmark_mask_models.PROMPTS[11].check(suggestions)
        assert result is not None
        assert "literal baseword" in result

    def test_single_suggestion_fails(self):
        suggestions = [_suggestion("Genesis?s?d")]
        result = benchmark_mask_models.PROMPTS[11].check(suggestions)
        assert result is not None
        assert ">= 2" in result

    def test_duplicate_suggestions_fail(self):
        suggestions = [_suggestion("Genesis?s?d"), _suggestion("Genesis?s?d")]
        result = benchmark_mask_models.PROMPTS[11].check(suggestions)
        assert result is not None
        assert "duplicate" in result


class TestEuropeanCitiesCategoryChecker:
    def test_multiple_literal_basewords_pass(self):
        suggestions = [
            _suggestion("Paris?s?d"),
            _suggestion("Berlin?d?s"),
            _suggestion("Madrid?s?d"),
        ]
        result = benchmark_mask_models.PROMPTS[12].check(suggestions)
        assert result is None

    def test_pattern_only_mask_fails(self):
        suggestions = [_suggestion("?s?d"), _suggestion("?d?s")]
        result = benchmark_mask_models.PROMPTS[12].check(suggestions)
        assert result is not None
        assert "literal baseword" in result

    def test_single_suggestion_fails(self):
        suggestions = [_suggestion("Paris?s?d")]
        result = benchmark_mask_models.PROMPTS[12].check(suggestions)
        assert result is not None
        assert ">= 2" in result

    def test_duplicate_suggestions_fail(self):
        suggestions = [_suggestion("Paris?s?d"), _suggestion("Paris?s?d")]
        result = benchmark_mask_models.PROMPTS[12].check(suggestions)
        assert result is not None
        assert "duplicate" in result


class TestBibleVerseFormatChecker:
    def test_correct_format_passes(self):
        suggestions = [_suggestion("John?d:?d?d")]
        result = benchmark_mask_models.PROMPTS[13].check(suggestions)
        assert result is None

    def test_missing_literal_colon_fails(self):
        suggestions = [_suggestion("John3verse16")]
        result = benchmark_mask_models.PROMPTS[13].check(suggestions)
        assert result is not None
        assert "':'" in result

    def test_pattern_only_mask_fails(self):
        suggestions = [_suggestion("?d?d:?d?d")]
        result = benchmark_mask_models.PROMPTS[13].check(suggestions)
        assert result is not None
        assert "book-name prefix" in result

    def test_too_few_digits_fails(self):
        # Has the required literal ':', but only one ?d token (need >= 2).
        suggestions = [_suggestion("John?d:verse")]
        result = benchmark_mask_models.PROMPTS[13].check(suggestions)
        assert result is not None
        assert "digit tokens" in result

    def test_duplicate_suggestions_fail(self):
        suggestions = [_suggestion("John?d?d?d"), _suggestion("John?d?d?d")]
        result = benchmark_mask_models.PROMPTS[13].check(suggestions)
        assert result is not None
        assert "duplicate" in result


class TestBracketCharsetAvoidanceChecker:
    def test_correct_custom_charset_passes(self):
        suggestions = [
            _suggestion("Patriots?d?d?1", custom=["ea34@jr?l"]),
            _suggestion("Eagles?d?d?1", custom=["ea34@jr?l"]),
        ]
        result = benchmark_mask_models.PROMPTS[14].check(suggestions)
        assert result is None

    def test_hallucinated_brackets_fail(self):
        # The exact real-world bug: "[ea34@jr?l]" parsed as literal brackets
        # around real tokens, not a character class (hcmask has none).
        suggestions = [
            _suggestion("Patriots?d?d[ea34@jr?l]"),
            _suggestion("Eagles?d?d[ea34@jr?l]"),
        ]
        result = benchmark_mask_models.PROMPTS[14].check(suggestions)
        assert result is not None
        assert "bracket" in result

    def test_no_custom_charset_fails(self):
        suggestions = [
            _suggestion("Patriots?d?d?l"),
            _suggestion("Eagles?d?d?l"),
        ]
        result = benchmark_mask_models.PROMPTS[14].check(suggestions)
        assert result is not None
        assert "custom charset" in result

    def test_single_suggestion_fails(self):
        suggestions = [_suggestion("Patriots?d?d?1", custom=["ea34@jr?l"])]
        result = benchmark_mask_models.PROMPTS[14].check(suggestions)
        assert result is not None
        assert ">= 2" in result


class TestCustomCharsetNoBracketsChecker:
    def test_correct_custom_charset_passes(self):
        suggestions = [_suggestion("Blue?1", custom=["!@#$%"])]
        result = benchmark_mask_models.PROMPTS[15].check(suggestions)
        assert result is None

    def test_hallucinated_brackets_fail(self):
        suggestions = [_suggestion("Blue[!@#$%]")]
        result = benchmark_mask_models.PROMPTS[15].check(suggestions)
        assert result is not None
        assert "bracket" in result

    def test_wrong_literal_prefix_fails(self):
        suggestions = [_suggestion("Red?1", custom=["!@#$%"])]
        result = benchmark_mask_models.PROMPTS[15].check(suggestions)
        assert result is not None
        assert "'Blue'" in result


class TestDaysOfWeekFullEnumerationChecker:
    def test_all_seven_days_pass(self):
        days = [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        ]
        suggestions = [_suggestion(f"{d}?d?d") for d in days]
        result = benchmark_mask_models.PROMPTS[16].check(suggestions)
        assert result is None

    def test_old_arbitrary_cap_of_two_fails(self):
        # The old regression: models truncating to a handful regardless of
        # the category's real (small) size.
        suggestions = [_suggestion("Monday?d?d"), _suggestion("Tuesday?d?d")]
        result = benchmark_mask_models.PROMPTS[16].check(suggestions)
        assert result is not None
        assert "7 days" in result

    def test_duplicate_days_fail(self):
        suggestions = [_suggestion("Monday?d?d") for _ in range(6)]
        result = benchmark_mask_models.PROMPTS[16].check(suggestions)
        assert result is not None
        assert "duplicate" in result


class TestUsStatesCappedEnumerationChecker:
    def test_fifteen_states_pass(self):
        states = [f"State{i}" for i in range(15)]
        suggestions = [_suggestion(f"{s}?d?d") for s in states]
        result = benchmark_mask_models.PROMPTS[17].check(suggestions)
        assert result is None

    def test_old_arbitrary_cap_of_a_few_fails(self):
        suggestions = [_suggestion("Texas?d?d"), _suggestion("Ohio?d?d")]
        result = benchmark_mask_models.PROMPTS[17].check(suggestions)
        assert result is not None
        assert "10" in result

    def test_way_too_many_fails(self):
        # The cap says "up to 15" — a model that ignores it entirely and
        # tries all 50 defeats the point of capping (it's the same latency
        # problem the 15-item cap exists to avoid).
        states = [f"State{i}" for i in range(25)]
        suggestions = [_suggestion(f"{s}?d?d") for s in states]
        result = benchmark_mask_models.PROMPTS[17].check(suggestions)
        assert result is not None
        assert "cap not respected" in result


class TestLiteralWordNotDecomposedChecker:
    def test_correct_literal_passes(self):
        suggestions = [_suggestion("Falcons?d?d")]
        result = benchmark_mask_models.PROMPTS[18].check(suggestions)
        assert result is None

    def test_decomposed_first_letter_fails(self):
        # The exact real-world bug: "?u??alcons" instead of literal "Falcons".
        suggestions = [_suggestion("?u??alcons?d?d")]
        result = benchmark_mask_models.PROMPTS[18].check(suggestions)
        assert result is not None
        assert "not decomposed" in result


class TestChessPiecesNoDuplicatesChecker:
    def test_all_distinct_pieces_pass(self):
        pieces = ["Pawn", "Knight", "Bishop", "Rook", "Queen", "King"]
        suggestions = [_suggestion(f"{p}?d?d?d?d") for p in pieces]
        result = benchmark_mask_models.PROMPTS[19].check(suggestions)
        assert result is None

    def test_duplicate_pieces_fail(self):
        suggestions = [_suggestion("Pawn?d?d?d?d") for _ in range(5)]
        result = benchmark_mask_models.PROMPTS[19].check(suggestions)
        assert result is not None
        assert "duplicate" in result

    def test_too_few_pieces_fails(self):
        suggestions = [_suggestion("Pawn?d?d?d?d"), _suggestion("King?d?d?d?d")]
        result = benchmark_mask_models.PROMPTS[19].check(suggestions)
        assert result is not None
        assert "6 chess piece names" in result


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
            lambda host=benchmark_mask_models.CANDIDATE_HOST: {"granite4:3b": 123},
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
            lambda host=benchmark_mask_models.CANDIDATE_HOST: {},
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
            lambda host=benchmark_mask_models.CANDIDATE_HOST: {},
        )
        monkeypatch.setattr(
            benchmark_mask_models.subprocess,
            "run",
            lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, returncode=1),
        )

        assert benchmark_mask_models.ensure_model_pulled("granite4:3b") is False


def _judge_response(content: str) -> SimpleNamespace:
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message)
    return SimpleNamespace(choices=[choice])


class _FakeJudgeCompletions:
    def __init__(self, responses: list[str]):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        content = self._responses.pop(0)
        return _judge_response(content)


class _FakeJudgeClient:
    def __init__(self, completions):
        self.chat = SimpleNamespace(completions=completions)


class TestJudgeScore:
    def test_valid_score_returned(self):
        completions = _FakeJudgeCompletions(
            [
                json.dumps(
                    {
                        "score": 4,
                        "reason": "close enough",
                        "prompt_fix_suggestion": "clarify the digit count wording",
                    }
                )
            ]
        )
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        verdict = benchmark_mask_models.judge_score(
            benchmark_mask_models.PROMPTS[0], suggestions, client=client
        )

        assert verdict.score == 4
        assert verdict.reason == "close enough"
        assert verdict.prompt_fix_suggestion == "clarify the digit count wording"
        assert len(completions.calls) == 1

    def test_out_of_range_score_raises_judge_error(self):
        completions = _FakeJudgeCompletions(
            [json.dumps({"score": 9, "reason": "nonsense", "prompt_fix_suggestion": ""})]
        )
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        try:
            benchmark_mask_models.judge_score(
                benchmark_mask_models.PROMPTS[0], suggestions, client=client
            )
            raise AssertionError("expected JudgeError")
        except benchmark_mask_models.JudgeError:
            pass

    def test_malformed_json_raises_judge_error(self):
        completions = _FakeJudgeCompletions(["not json at all"])
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        try:
            benchmark_mask_models.judge_score(
                benchmark_mask_models.PROMPTS[0], suggestions, client=client
            )
            raise AssertionError("expected JudgeError")
        except benchmark_mask_models.JudgeError:
            pass

    def test_missing_prompt_fix_suggestion_raises_judge_error(self):
        # The schema requires prompt_fix_suggestion; a response missing it
        # (e.g. an older/non-conforming judge model) must not silently pass.
        completions = _FakeJudgeCompletions([json.dumps({"score": 5, "reason": "good"})])
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        try:
            benchmark_mask_models.judge_score(
                benchmark_mask_models.PROMPTS[0], suggestions, client=client
            )
            raise AssertionError("expected JudgeError")
        except benchmark_mask_models.JudgeError:
            pass

    def test_prompt_and_suggestions_included_in_request(self):
        completions = _FakeJudgeCompletions(
            [json.dumps({"score": 5, "reason": "good", "prompt_fix_suggestion": ""})]
        )
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        benchmark_mask_models.judge_score(
            benchmark_mask_models.PROMPTS[0], suggestions, client=client
        )

        user_message = completions.calls[0]["messages"][-1]["content"]
        assert "Summer?d?d?d?d?d?d" in user_message
        assert benchmark_mask_models.PROMPTS[0].description in user_message


class TestRunPromptForModel:
    def test_hard_fail_when_generate_masks_raises(self, monkeypatch):
        def raising_generate_masks(description, **kwargs):
            raise benchmark_mask_models.MaskGenerationError("simulated failure")

        monkeypatch.setattr(benchmark_mask_models, "generate_masks", raising_generate_masks)

        result = benchmark_mask_models.run_prompt_for_model(
            "some-model", benchmark_mask_models.PROMPTS[0]
        )

        assert result.hard_fail_reason is not None
        assert "simulated failure" in result.hard_fail_reason
        assert result.judge_score is None

    def test_soft_fail_when_check_fails(self, monkeypatch):
        # generate_masks succeeds, but returns output the checker rejects.
        # This is well-formed-but-wrong content, not an infra failure, so it's
        # a soft fail — the judge still runs and scores it.
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("?d?d?d?d?d")],  # wrong count
        )
        monkeypatch.setattr(
            benchmark_mask_models,
            "judge_score",
            lambda prompt, suggestions, **kwargs: benchmark_mask_models.JudgeVerdict(
                2, "too short", "clarify the digit count"
            ),
        )

        result = benchmark_mask_models.run_prompt_for_model(
            "some-model", benchmark_mask_models.PROMPTS[0]
        )

        assert result.hard_fail_reason is None
        assert result.soft_fail_reason is not None
        assert result.judge_score == 2
        assert result.judge_reason == "too short"

    def test_passes_and_gets_judge_score(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("Summer?d?d?d?d?d?d")],
        )
        monkeypatch.setattr(
            benchmark_mask_models,
            "judge_score",
            lambda prompt, suggestions, **kwargs: benchmark_mask_models.JudgeVerdict(
                5, "perfect", ""
            ),
        )

        result = benchmark_mask_models.run_prompt_for_model(
            "some-model", benchmark_mask_models.PROMPTS[0]
        )

        assert result.hard_fail_reason is None
        assert result.judge_score == 5
        assert result.judge_reason == "perfect"

    def test_judge_failure_does_not_crash(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("Summer?d?d?d?d?d?d")],
        )

        def raising_judge(prompt, suggestions, **kwargs):
            raise benchmark_mask_models.JudgeError("judge is down")

        monkeypatch.setattr(benchmark_mask_models, "judge_score", raising_judge)

        result = benchmark_mask_models.run_prompt_for_model(
            "some-model", benchmark_mask_models.PROMPTS[0]
        )

        assert result.hard_fail_reason is None
        assert result.judge_score is None
        assert result.judge_reason is None

    def test_logs_suggestions_for_manual_review(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("Summer?d?d?d?d?d?d")],
        )
        monkeypatch.setattr(
            benchmark_mask_models,
            "judge_score",
            lambda prompt, suggestions, **kwargs: benchmark_mask_models.JudgeVerdict(
                5, "fully satisfies the request", ""
            ),
        )
        log_path = tmp_path / "suggestions.jsonl"
        monkeypatch.setenv("SUGGESTIONS_LOG_PATH", str(log_path))

        benchmark_mask_models.run_prompt_for_model("some-model", benchmark_mask_models.PROMPTS[0])

        lines = log_path.read_text().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["model"] == "some-model"
        assert entry["prompt"] == benchmark_mask_models.PROMPTS[0].name
        assert entry["suggestions"] == [{"mask": "Summer?d?d?d?d?d?d", "why": "test"}]
        assert entry["judge_score"] == 5
        assert entry["judge_reason"] == "fully satisfies the request"


class TestHostAlwaysLocal:
    """Regression tests for the host=None -> OLLAMA_HOST env fallback bug.

    run_prompt_for_model and benchmark_model must always drive generate_masks
    against CANDIDATE_HOST and judge_score against JUDGE_HOST, never against
    whatever OLLAMA_HOST happens to be set to in the environment (e.g. a
    remote host) — and never against each other's host, since candidates and
    the judge are deliberately split across two different Ollama servers.
    """

    def test_run_prompt_for_model_uses_split_hosts_regardless_of_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_HOST", "some-other-team.example:11434")

        recorded_hosts: dict[str, str | None] = {}

        def fake_generate_masks(description, **kwargs):
            recorded_hosts["generate_masks"] = kwargs.get("host")
            return [_suggestion("Summer?d?d?d?d?d?d")]

        def fake_judge_score(prompt, suggestions, **kwargs):
            recorded_hosts["judge_score"] = kwargs.get("host")
            return benchmark_mask_models.JudgeVerdict(5, "good", "")

        monkeypatch.setattr(benchmark_mask_models, "generate_masks", fake_generate_masks)
        monkeypatch.setattr(benchmark_mask_models, "judge_score", fake_judge_score)

        benchmark_mask_models.run_prompt_for_model("some-model", benchmark_mask_models.PROMPTS[0])

        assert recorded_hosts["generate_masks"] == benchmark_mask_models.CANDIDATE_HOST
        assert recorded_hosts["judge_score"] == benchmark_mask_models.JUDGE_HOST
        assert recorded_hosts["generate_masks"] != "some-other-team.example:11434"
        assert recorded_hosts["judge_score"] != "some-other-team.example:11434"

    def test_benchmark_model_uses_split_hosts_regardless_of_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_HOST", "some-other-team.example:11434")
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.CANDIDATE_HOST: {"some-model": 3 * 1024**3},
        )
        monkeypatch.setattr(
            benchmark_mask_models, "ensure_model_pulled", lambda model, **kwargs: True
        )

        recorded_calls: list[dict[str, str | None]] = []

        def fake_run_prompt_for_model(model, prompt, **kwargs):
            recorded_calls.append(
                {
                    "candidate_host": kwargs.get("candidate_host"),
                    "judge_host": kwargs.get("judge_host"),
                }
            )
            return benchmark_mask_models.PromptResult(prompt.name, 1.0, None, 5)

        monkeypatch.setattr(
            benchmark_mask_models, "run_prompt_for_model", fake_run_prompt_for_model
        )

        benchmark_mask_models.benchmark_model("some-model")

        assert recorded_calls
        assert all(
            c["candidate_host"] == benchmark_mask_models.CANDIDATE_HOST for c in recorded_calls
        )
        assert all(c["judge_host"] == benchmark_mask_models.JUDGE_HOST for c in recorded_calls)
        assert all(c["candidate_host"] != "some-other-team.example:11434" for c in recorded_calls)


class TestBenchmarkModel:
    def test_unpullable_model_hard_fails_every_prompt(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.CANDIDATE_HOST: {},
        )
        monkeypatch.setattr(
            benchmark_mask_models, "ensure_model_pulled", lambda model, **kwargs: False
        )

        report = benchmark_mask_models.benchmark_model("nonexistent:model")

        assert report.disk_size_gb is None
        assert report.hard_fail_count == len(benchmark_mask_models.PROMPTS)

    def test_present_model_runs_all_prompts(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.CANDIDATE_HOST: {"some-model": 3 * 1024**3},
        )
        monkeypatch.setattr(
            benchmark_mask_models, "ensure_model_pulled", lambda model, **kwargs: True
        )
        monkeypatch.setattr(
            benchmark_mask_models,
            "run_prompt_for_model",
            lambda model, prompt, **kwargs: benchmark_mask_models.PromptResult(
                prompt.name, 1.0, None, 5
            ),
        )

        report = benchmark_mask_models.benchmark_model("some-model")

        assert report.disk_size_gb == 3.0
        assert len(report.prompt_results) == len(benchmark_mask_models.PROMPTS)
        assert report.hard_fail_count == 0

    def test_infrastructure_failure_hard_fails_every_prompt_without_crashing(self, monkeypatch):
        def raising_ensure_model_pulled(model, **kwargs):
            raise FileNotFoundError("ollama: command not found")

        monkeypatch.setattr(
            benchmark_mask_models, "ensure_model_pulled", raising_ensure_model_pulled
        )

        report = benchmark_mask_models.benchmark_model("some-model")

        assert report.disk_size_gb is None
        assert report.hard_fail_count == len(benchmark_mask_models.PROMPTS)
        assert all(
            r.hard_fail_reason is not None and "infrastructure error" in r.hard_fail_reason
            for r in report.prompt_results
        )


class TestFormatReport:
    def test_recommends_smallest_passing_model(self):
        reports = [
            benchmark_mask_models.ModelReport(
                "big-good-model",
                20.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, None, 5)
                    for p in benchmark_mask_models.PROMPTS
                ],
            ),
            benchmark_mask_models.ModelReport(
                "small-good-model",
                3.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, None, 4)
                    for p in benchmark_mask_models.PROMPTS
                ],
            ),
            benchmark_mask_models.ModelReport(
                "small-bad-model",
                2.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, "hard fail", None)
                    for p in benchmark_mask_models.PROMPTS
                ],
            ),
        ]

        report_text = benchmark_mask_models.format_report(reports)

        assert "small-good-model" in report_text
        assert "Recommendation: small-good-model" in report_text

    def test_no_candidate_clears_the_bar(self):
        reports = [
            benchmark_mask_models.ModelReport(
                "bad-model",
                2.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, "hard fail", None)
                    for p in benchmark_mask_models.PROMPTS
                ],
            )
        ]

        report_text = benchmark_mask_models.format_report(reports)

        assert "no candidate clears the bar" in report_text

    def test_none_disk_size_renders_na_and_sorts_last(self):
        reports = [
            benchmark_mask_models.ModelReport(
                "small-model",
                2.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, None, 5)
                    for p in benchmark_mask_models.PROMPTS
                ],
            ),
            benchmark_mask_models.ModelReport(
                "unpullable-model",
                None,
                [
                    benchmark_mask_models.PromptResult(
                        p.name, 0.0, "model could not be pulled", None
                    )
                    for p in benchmark_mask_models.PROMPTS
                ],
            ),
            benchmark_mask_models.ModelReport(
                "big-model",
                20.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, None, 4)
                    for p in benchmark_mask_models.PROMPTS
                ],
            ),
        ]

        report_text = benchmark_mask_models.format_report(reports)

        assert "N/A" in report_text
        assert "unpullable-model" in report_text
        # The N/A (None) row must sort after both finite-size rows.
        assert report_text.index("small-model") < report_text.index("unpullable-model")
        assert report_text.index("big-model") < report_text.index("unpullable-model")


class TestMain:
    def test_main_wires_candidates_through_to_printed_report(self, monkeypatch, capsys):
        def fake_benchmark_model(model: str):
            return benchmark_mask_models.ModelReport(
                model,
                1.0,
                [
                    benchmark_mask_models.PromptResult(p.name, 1.0, None, 5)
                    for p in benchmark_mask_models.PROMPTS
                ],
            )

        monkeypatch.setattr(benchmark_mask_models, "benchmark_model", fake_benchmark_model)

        benchmark_mask_models.main()

        captured = capsys.readouterr()
        assert benchmark_mask_models.CANDIDATES[0] in captured.out
        assert "Recommendation:" in captured.out
