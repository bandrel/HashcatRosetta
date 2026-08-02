# Mask Model Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Build a standalone script that benchmarks a curated shortlist of small,
non-thinking local Ollama models against 7 fixed hcmask-generation prompts, scoring
each on deterministic correctness plus an LLM judge, and recommending the
smallest-disk-size model that clears the accuracy bar.

**Architecture:** A single script, `scripts/benchmark_mask_models.py`, following this
repo's existing convention for one-off tools (`scripts/sweep_opcodes.py`,
`scripts/verify_rules.py`): no package `__init__.py`, tested via `importlib` loading
from `tests/`. Built in four self-contained layers: (1) prompt definitions and
deterministic pass/fail checkers, (2) model inventory/pull helpers against the local
Ollama HTTP API, (3) an LLM-judge scorer reusing `hashcat_rosetta.nlmask`'s
tested client/schema pattern, (4) orchestration that ties it together into a report.
Each task adds only the imports it actually uses — the module's import block grows
incrementally task-by-task so every task's own lint step stays clean (no unused-import
warnings from a later task's not-yet-written code).

**Tech Stack:** Python 3.10+, stdlib `urllib.request`/`subprocess`/`json`/`time`, the
already-installed `openai` SDK (for the judge call, same pattern as `nlmask.py`), and
this repo's own `hashcat_rosetta.mask`/`hashcat_rosetta.nlmask` modules.

## Global Constraints

- Script lives at `scripts/benchmark_mask_models.py` — not part of the installed
  package, not wired into the CLI, not imported by any shipped module.
- Runs against the **local** Ollama only (`http://localhost:11434`), never gpu-host or
  any remote host — this is a design requirement from the spec (the security property
  of `--mask` is local-only, so the model chosen for the default must be evaluated on
  realistic local hardware).
- Candidate list is exactly these 7 model names, in this order (spec's Candidates
  table): `granite4:3b`, `mistral:latest`, `qwen2.5:latest`, `llama3.1:8b`, `phi4:14b`,
  `qwen2.5:32b`, `qwen3-coder:latest`.
- Judge model is exactly `qwen3-coder:latest`.
- Recommendation rule (spec's Report section, exact values): smallest disk size among
  candidates with `hard_fail_count == 0` and `mean_judge_score >= 4`. If none qualify,
  print "no candidate clears the bar" — do not silently recommend a failing candidate.
- One run per (model, prompt) pair — no repeated trials, no averaging across multiple
  attempts (spec's Out of Scope section).
- This plan does NOT change `nlmask.py`'s shipped `_DEFAULT_MODEL` — that's a separate
  follow-up decision after reviewing this script's report (spec's Out of Scope section).

---

## Task 1: Prompt definitions and deterministic checkers

**Files:**
- Create: `scripts/benchmark_mask_models.py`
- Test: `tests/test_benchmark_mask_models.py`

**Interfaces:**
- Consumes: `hashcat_rosetta.mask.{expand_custom_charsets, keyspace, tokens}`,
  `hashcat_rosetta.nlmask.MaskSuggestion` (both already-shipped, stable APIs).
- Produces (for later tasks): `BenchmarkPrompt` dataclass (fields: `name: str`,
  `description: str`, `check: Callable[[list[MaskSuggestion]], str | None]`), the
  module-level `PROMPTS: list[BenchmarkPrompt]` (exactly 7 entries, in spec order),
  `PromptResult` dataclass (fields: `prompt_name: str`, `elapsed_seconds: float`,
  `hard_fail_reason: str | None`, `judge_score: int | None`), `ModelReport` dataclass
  (fields: `model: str`, `disk_size_gb: float | None`,
  `prompt_results: list[PromptResult]`, plus properties `hard_fail_count: int`,
  `judge_scores: list[int]`, `mean_judge_score: float | None`,
  `min_judge_score: int | None`, `total_seconds: float`), and the module-level
  constants `LOCAL_HOST = "http://localhost:11434"`, `CANDIDATES: list[str]` (the 7
  names above), `JUDGE_MODEL = "qwen3-coder:latest"` (all three are plain constants
  used starting in later tasks — defining them now is not an unused-import problem,
  only unused *imports* trigger lint failures).

This task has no network calls and no LLM calls — every function here is pure logic
over `MaskSuggestion`/`HcmaskLine` objects you construct by hand in tests via
`hashcat_rosetta.mask.parse_hcmask_line`.

- [x] **Step 1: Write the failing tests for the dataclasses and one checker**

Create `tests/test_benchmark_mask_models.py`:

```python
"""Tests for scripts/benchmark_mask_models.py — pure-logic pieces only.

The benchmark script lives in scripts/ (not in the package), so we import it
via importlib, matching the convention in tests/test_opcode_sweep.py.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from hashcat_rosetta.mask import parse_hcmask_line
from hashcat_rosetta.nlmask import MaskSuggestion

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "benchmark_mask_models.py"
_spec = importlib.util.spec_from_file_location("benchmark_mask_models", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
benchmark_mask_models = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(benchmark_mask_models)


def _suggestion(mask_str: str, custom: list[str] | None = None, why: str = "test") -> MaskSuggestion:
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
```

- [x] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v`
Expected: FAIL with `ModuleNotFoundError` (script doesn't exist yet).

- [x] **Step 3: Write the module header, dataclasses, and the first checker**

Create `scripts/benchmark_mask_models.py`:

```python
#!/usr/bin/env python3
"""Benchmark candidate local Ollama models for the --mask feature.

Runs a fixed set of 7 hcmask-generation prompts against a curated shortlist of
small, non-thinking models via hashcat_rosetta.nlmask.generate_masks (the real
production code path — same timeout/retry logic already shipped). Each
prompt's output is checked deterministically first (hard gate: does it parse,
does it match the hand-written expectation for that prompt), then judged by
qwen3-coder:latest for overall correctness/plausibility. Prints a report
ranking candidates by disk size (a VRAM proxy) among those that pass.

This script is NOT part of the installed package and does NOT change
nlmask.py's shipped default model — see
docs/superpowers/specs/2026-08-01-mask-model-benchmark-design.md.

Runs against the LOCAL Ollama only (http://localhost:11434).

Usage:
    uv run python scripts/benchmark_mask_models.py

Requires: a running local Ollama server; `ollama` on PATH to pull missing
candidates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from hashcat_rosetta.mask import expand_custom_charsets, keyspace, tokens
from hashcat_rosetta.nlmask import MaskSuggestion

LOCAL_HOST = "http://localhost:11434"

CANDIDATES: list[str] = [
    "granite4:3b",
    "mistral:latest",
    "qwen2.5:latest",
    "llama3.1:8b",
    "phi4:14b",
    "qwen2.5:32b",
    "qwen3-coder:latest",
]

JUDGE_MODEL = "qwen3-coder:latest"


@dataclass
class BenchmarkPrompt:
    """One fixed test prompt plus its hand-written deterministic expectation.

    Attributes:
        name: Short identifier, used in reports and test names.
        description: The English description sent to generate_masks.
        check: Given the model's suggestions, returns None if they satisfy
            this prompt's expectation, else a human-readable failure reason.
    """

    name: str
    description: str
    check: Callable[[list[MaskSuggestion]], str | None]


@dataclass
class PromptResult:
    """The outcome of running one (model, prompt) pair.

    Attributes:
        prompt_name: Matches BenchmarkPrompt.name.
        elapsed_seconds: Wall-clock time for the generate_masks call.
        hard_fail_reason: None if the deterministic gate passed, else the
            failure reason (generate_masks raised, or check() returned a
            reason). When set, judge_score is always None — the judge is
            never invoked for a hard-failed prompt.
        judge_score: 1-5 from the judge model, or None if hard-failed or the
            judge call itself failed.
    """

    prompt_name: str
    elapsed_seconds: float
    hard_fail_reason: str | None
    judge_score: int | None


@dataclass
class ModelReport:
    """Aggregated results for one candidate model across all prompts.

    Attributes:
        model: The Ollama model name.
        disk_size_gb: Size on disk in GiB, or None if the model could not be
            pulled at all.
        prompt_results: One PromptResult per entry in PROMPTS, same order.
    """

    model: str
    disk_size_gb: float | None
    prompt_results: list[PromptResult]

    @property
    def hard_fail_count(self) -> int:
        return sum(1 for r in self.prompt_results if r.hard_fail_reason is not None)

    @property
    def judge_scores(self) -> list[int]:
        return [r.judge_score for r in self.prompt_results if r.judge_score is not None]

    @property
    def mean_judge_score(self) -> float | None:
        scores = self.judge_scores
        return sum(scores) / len(scores) if scores else None

    @property
    def min_judge_score(self) -> int | None:
        scores = self.judge_scores
        return min(scores) if scores else None

    @property
    def total_seconds(self) -> float:
        return sum(r.elapsed_seconds for r in self.prompt_results)


def _check_summer_digits(suggestions: list[MaskSuggestion]) -> str | None:
    if len(suggestions) != 1:
        return f"expected exactly 1 suggestion, got {len(suggestions)}"
    s = suggestions[0]
    if s.line.custom:
        return f"expected no custom charsets, got {s.line.custom!r}"
    ks = keyspace(s.line)
    if ks != 1_000_000:
        return f"expected keyspace 1,000,000, got {ks:,} (mask: {s.mask!r})"
    if not s.line.mask.lower().startswith("summer"):
        return f"expected mask to start with literal 'Summer', got {s.mask!r}"
    if not s.line.mask.endswith("?d" * 6):
        return f"expected mask to end with 6 digit tokens, got {s.mask!r}"
    return None


PROMPTS: list[BenchmarkPrompt] = [
    BenchmarkPrompt(
        "summer_digits",
        "The word 'Summer' followed by six digits.",
        _check_summer_digits,
    ),
]
```

Note: `PROMPTS` has only 1 entry after this step, and there is no `main`/`__main__`
block yet — that's added in Task 4. `expand_custom_charsets` and `tokens` are imported
but not yet used by this step's code alone; they ARE used by the checkers added in
Step 7 below, in this same task, so this is not an unused-import problem at any commit
boundary (Step 7 lands before Task 1's Step 9 lint check runs).

- [x] **Step 4: Run the tests to verify Step 1's tests now pass**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v`
Expected: All `TestPromptResultAndModelReport` and `TestSummerDigitsChecker` tests PASS.

- [x] **Step 5: Add the remaining 6 checkers, their prompts, and their tests**

Append to `tests/test_benchmark_mask_models.py`:

```python
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
```

- [x] **Step 6: Run the new tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v`
Expected: FAIL — `IndexError: list index out of range` on `PROMPTS[1]` through
`PROMPTS[6]` (only 1 prompt exists so far).

- [x] **Step 7: Add the remaining 6 checker functions and prompts**

In `scripts/benchmark_mask_models.py`, insert these functions directly above the
`PROMPTS: list[BenchmarkPrompt] = [` line, and replace that list to include all 7
entries:

```python
def _check_mushroom_categories(suggestions: list[MaskSuggestion]) -> str | None:
    if len(suggestions) < 2:
        return f"expected >= 2 suggestions, got {len(suggestions)}"
    for s in suggestions:
        literal_prefix = s.mask.split("?")[0]
        if not literal_prefix:
            return f"suggestion {s.mask!r} has no literal baseword prefix"
    return None


def _check_season_digits_special(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    s = suggestions[0]
    toks = tokens(s.line)
    digit_count = sum(1 for t, _size in toks if t == "?d")
    special_count = sum(1 for t, _size in toks if t == "?s")
    if digit_count < 2:
        return f"expected >= 2 digit tokens (?d), got {digit_count} in {s.mask!r}"
    if special_count < 1:
        return f"expected >= 1 special token (?s), got {special_count} in {s.mask!r}"
    return None


def _check_four_or_six_digits(suggestions: list[MaskSuggestion]) -> str | None:
    if len(suggestions) != 2:
        return f"expected exactly 2 suggestions, got {len(suggestions)}"
    return None


def _check_vowel_custom_charset(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    s = suggestions[0]
    if not s.line.custom:
        return f"expected a custom charset, got none in {s.mask!r}"
    expanded = expand_custom_charsets(s.line.custom)
    charset = expanded[0] if expanded else ""
    if not charset or any(c.lower() not in "aeiou" for c in charset):
        return f"expected custom charset to contain only vowels, got {s.line.custom[0]!r}"
    vowel_count = len(charset)
    expected_keyspace = (vowel_count**4) * 10
    ks = keyspace(s.line)
    if ks != expected_keyspace:
        return (
            f"expected keyspace {expected_keyspace:,} ({vowel_count} vowels^4 * "
            f"10 digits), got {ks:,}"
        )
    return None


def _check_hex_digits(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    s = suggestions[0]
    toks = tokens(s.line)
    hex_count = sum(1 for t, _size in toks if t == "?h")
    digit_count = sum(1 for t, _size in toks if t == "?d")
    if hex_count != 4:
        return f"expected exactly 4 lowercase-hex tokens (?h), got {hex_count} in {s.mask!r}"
    if digit_count != 2:
        return f"expected exactly 2 digit tokens (?d), got {digit_count} in {s.mask!r}"
    return None


def _check_literal_question_mark(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    s = suggestions[0]
    toks = tokens(s.line)
    literal_q_count = sum(1 for t, _size in toks if t == "??")
    digit_count = sum(1 for t, _size in toks if t == "?d")
    if literal_q_count != 1:
        return f"expected exactly 1 literal '?' token (??), got {literal_q_count} in {s.mask!r}"
    if digit_count != 3:
        return f"expected exactly 3 digit tokens (?d), got {digit_count} in {s.mask!r}"
    return None


PROMPTS: list[BenchmarkPrompt] = [
    BenchmarkPrompt(
        "summer_digits",
        "The word 'Summer' followed by six digits.",
        _check_summer_digits,
    ),
    BenchmarkPrompt(
        "mushroom_categories",
        "Basewords should be based on mushroom varieties followed by one of the "
        "following patters. [symbol+digit,digit+symbol]",
        _check_mushroom_categories,
    ),
    BenchmarkPrompt(
        "season_digits_special",
        "a capitalized season, two digits, and a special char",
        _check_season_digits_special,
    ),
    BenchmarkPrompt(
        "four_or_six_digits",
        "either 4 or 6 digits",
        _check_four_or_six_digits,
    ),
    BenchmarkPrompt(
        "vowel_custom_charset",
        "a lowercase vowel repeated four times, followed by two digits",
        _check_vowel_custom_charset,
    ),
    BenchmarkPrompt(
        "hex_digits",
        "a 4-character lowercase hex string followed by two digits",
        _check_hex_digits,
    ),
    BenchmarkPrompt(
        "literal_question_mark",
        "a literal question mark followed by three digits",
        _check_literal_question_mark,
    ),
]
```

- [x] **Step 8: Run all tests to verify they pass**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v`
Expected: All tests PASS (20 tests: 2 dataclass + 3 summer + 3 mushroom + 3 season +
2 four-or-six + 3 vowel + 2 hex + 2 literal-question-mark).

- [x] **Step 9: Lint, format, typecheck**

Run:
```bash
uv run ruff check scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run ruff format scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run mypy scripts/benchmark_mask_models.py
```
Expected: all clean. If `ruff check` flags anything, it means an import got added that
isn't used yet at this point in the file — fix by removing it (only `dataclass`,
`Callable`, `expand_custom_charsets`, `keyspace`, `tokens`, `MaskSuggestion` should be
imported after this task; do not add Task 2/3/4's imports early).

- [x] **Step 10: Commit**

```bash
git add scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
git commit -m "feat(benchmark): add fixed prompts and deterministic checkers"
```

---

## Task 2: Model inventory and pull helpers

**Files:**
- Modify: `scripts/benchmark_mask_models.py`
- Test: `tests/test_benchmark_mask_models.py`

**Interfaces:**
- Consumes: nothing from Task 1 (this task's functions are independent of the prompt
  logic), but shares the file's `LOCAL_HOST` constant already defined in Task 1.
- Produces (for Task 4): `list_local_models(host: str = LOCAL_HOST) -> dict[str, int]`
  (model name -> size in bytes), `ensure_model_pulled(model: str, *, host: str =
  LOCAL_HOST) -> bool` (True if the model is present after this call, whether it was
  already there or successfully pulled).

- [x] **Step 1: Write the failing tests**

Append to `tests/test_benchmark_mask_models.py`. First add the two new stdlib imports
this step's tests need, at the top of the test file alongside the existing imports:

```python
import json
import subprocess
```

Then append:

```python
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
            raise AssertionError("subprocess.run should not be called when model is already present")

        monkeypatch.setattr(benchmark_mask_models.subprocess, "run", fail_if_called)

        assert benchmark_mask_models.ensure_model_pulled("granite4:3b") is True

    def test_pulls_missing_model_successfully(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models, "list_local_models", lambda host=benchmark_mask_models.LOCAL_HOST: {}
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
            benchmark_mask_models, "list_local_models", lambda host=benchmark_mask_models.LOCAL_HOST: {}
        )
        monkeypatch.setattr(
            benchmark_mask_models.subprocess,
            "run",
            lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, returncode=1),
        )

        assert benchmark_mask_models.ensure_model_pulled("granite4:3b") is False
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v -k "ListLocalModels or EnsureModelPulled"`
Expected: FAIL with `AttributeError: module 'benchmark_mask_models' has no attribute
'urllib'` (or `'list_local_models'`).

- [x] **Step 3: Add imports and implement `list_local_models`/`ensure_model_pulled`**

In `scripts/benchmark_mask_models.py`, add two stdlib imports to the top import block
(directly below `from __future__ import annotations`):

```python
import json
import subprocess
import urllib.request
```

Then add these two functions after the `JUDGE_MODEL = "qwen3-coder:latest"` line and
before the `BenchmarkPrompt` dataclass:

```python
def list_local_models(host: str = LOCAL_HOST) -> dict[str, int]:
    """Return {model_name: size_in_bytes} for every model on the local Ollama."""
    url = f"{host.rstrip('/')}/api/tags"
    with urllib.request.urlopen(url, timeout=10) as response:
        data = json.loads(response.read())
    return {m["name"]: m["size"] for m in data.get("models", [])}


def ensure_model_pulled(model: str, *, host: str = LOCAL_HOST) -> bool:
    """Pull `model` if it isn't already present locally.

    Returns True if the model is present after this call (whether it was
    already there or the pull succeeded), False if the pull failed.
    """
    if model in list_local_models(host):
        return True
    result = subprocess.run(["ollama", "pull", model], capture_output=True, timeout=1800)
    return result.returncode == 0
```

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v -k "ListLocalModels or EnsureModelPulled"`
Expected: All 5 tests PASS.

- [x] **Step 5: Run the full test file, lint, format, typecheck**

```bash
uv run pytest tests/test_benchmark_mask_models.py -v
uv run ruff check scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run ruff format scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run mypy scripts/benchmark_mask_models.py
```
Expected: everything passes/clean.

- [x] **Step 6: Commit**

```bash
git add scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
git commit -m "feat(benchmark): add model inventory and pull helpers"
```

---

## Task 3: LLM judge scoring

**Files:**
- Modify: `scripts/benchmark_mask_models.py`
- Test: `tests/test_benchmark_mask_models.py`

**Interfaces:**
- Consumes: Task 1's `BenchmarkPrompt` and `MaskSuggestion`.
- Produces (for Task 4): `class JudgeError(Exception)`,
  `judge_score(prompt: BenchmarkPrompt, suggestions: list[MaskSuggestion], *, model: str
  = JUDGE_MODEL, host: str | None = None, client: Any = None) -> int` — returns an
  integer 1-5, raises `JudgeError` on any failure (bad JSON, out-of-range score,
  connection error). The `client` parameter is the same test-injection seam
  `hashcat_rosetta.nlmask.generate_masks` uses — when `None`, a real `OpenAI` client is
  constructed.

This task's tests reuse the exact fake-client shape from `tests/test_nlmask.py`
(`FakeCompletions`/`FakeClient`/`_make_response`) but define local copies scoped to
this test file (`_FakeJudgeCompletions`/`_FakeJudgeClient`/`_judge_response`) rather
than importing across test files, matching how this repo keeps each test file
self-contained.

- [x] **Step 1: Write the failing tests**

Add one new import to the top of `tests/test_benchmark_mask_models.py`:

```python
from types import SimpleNamespace
```

Then append:

```python
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
        completions = _FakeJudgeCompletions([json.dumps({"score": 4, "reason": "close enough"})])
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        score = benchmark_mask_models.judge_score(
            benchmark_mask_models.PROMPTS[0], suggestions, client=client
        )

        assert score == 4
        assert len(completions.calls) == 1

    def test_out_of_range_score_raises_judge_error(self):
        completions = _FakeJudgeCompletions([json.dumps({"score": 9, "reason": "nonsense"})])
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        try:
            benchmark_mask_models.judge_score(benchmark_mask_models.PROMPTS[0], suggestions, client=client)
            raise AssertionError("expected JudgeError")
        except benchmark_mask_models.JudgeError:
            pass

    def test_malformed_json_raises_judge_error(self):
        completions = _FakeJudgeCompletions(["not json at all"])
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        try:
            benchmark_mask_models.judge_score(benchmark_mask_models.PROMPTS[0], suggestions, client=client)
            raise AssertionError("expected JudgeError")
        except benchmark_mask_models.JudgeError:
            pass

    def test_prompt_and_suggestions_included_in_request(self):
        completions = _FakeJudgeCompletions([json.dumps({"score": 5, "reason": "good"})])
        client = _FakeJudgeClient(completions)
        suggestions = [_suggestion("Summer?d?d?d?d?d?d")]

        benchmark_mask_models.judge_score(benchmark_mask_models.PROMPTS[0], suggestions, client=client)

        user_message = completions.calls[0]["messages"][-1]["content"]
        assert "Summer?d?d?d?d?d?d" in user_message
        assert benchmark_mask_models.PROMPTS[0].description in user_message
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v -k TestJudgeScore`
Expected: FAIL with `AttributeError: module 'benchmark_mask_models' has no attribute
'judge_score'`.

- [x] **Step 3: Add imports and implement `JudgeError`, `_build_judge_prompt`, `judge_score`**

In `scripts/benchmark_mask_models.py`, add to the top import block: change
`from hashcat_rosetta.mask import expand_custom_charsets, keyspace, tokens` to also
include `describe` and `format_hcmask_line`:

```python
from hashcat_rosetta.mask import describe, expand_custom_charsets, format_hcmask_line, keyspace, tokens
```

Add two new imports below the existing `from hashcat_rosetta.nlmask import
MaskSuggestion` line:

```python
from typing import Any

from openai import OpenAI

from hashcat_rosetta.nlmask import MaskSuggestion, resolve_base_url
```

(Merge `resolve_base_url` into the existing `hashcat_rosetta.nlmask` import line rather
than adding a second one; `from typing import Callable` from Task 1 becomes `from
typing import Any, Callable` — merge these into one line too. Run `ruff format`
afterward if the import ordering looks off; `ruff format` does not reorder imports by
itself in this project's config, so arrange them in the same relative order as shown
here.)

Add these definitions after the `JUDGE_MODEL = "qwen3-coder:latest"` line and before
`list_local_models`:

```python
JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "score": {
            "type": "integer",
            "description": "1 (does not satisfy the request) to 5 (fully and precisely satisfies it)",
        },
        "reason": {"type": "string", "description": "one short clause"},
    },
    "required": ["score", "reason"],
    "additionalProperties": False,
}

JUDGE_SYSTEM_PROMPT = (
    "You grade whether a set of hashcat mask suggestions fully and correctly "
    "satisfies an English request. Score 1 (does not satisfy the request at "
    "all) to 5 (fully and precisely satisfies it). Return JSON matching the "
    "schema. No step-by-step reasoning in the `reason` field — one short "
    "clause."
)


class JudgeError(Exception):
    """Raised when the judge model call fails or returns unusable output."""
```

Then add these two functions after the `BenchmarkPrompt` dataclass (they reference it
by name) and before `PromptResult`:

```python
def _build_judge_prompt(prompt: BenchmarkPrompt, suggestions: list[MaskSuggestion]) -> str:
    lines = [f"Original request: {prompt.description}", "", "Candidate's suggestions:"]
    for s in suggestions:
        full_line = format_hcmask_line(s.custom_charsets, s.mask)
        lines.append(f"- mask: {full_line}")
        lines.append(f"  description: {describe(s.line)}")
        lines.append(f"  why: {s.why}")
    return "\n".join(lines)


def judge_score(
    prompt: BenchmarkPrompt,
    suggestions: list[MaskSuggestion],
    *,
    model: str = JUDGE_MODEL,
    host: str | None = None,
    client: Any = None,
) -> int:
    """Score how well `suggestions` satisfies `prompt`, 1-5, via the judge model.

    Raises JudgeError on any failure: the request itself failing, malformed
    JSON in the response, or a score outside 1-5.
    """
    active_client: Any = (
        client
        if client is not None
        else OpenAI(base_url=resolve_base_url(host), api_key="ollama", timeout=60.0, max_retries=0)
    )

    try:
        response = active_client.chat.completions.create(
            model=model,
            temperature=0,
            messages=[
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {"role": "user", "content": _build_judge_prompt(prompt, suggestions)},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "judge_score", "strict": True, "schema": JUDGE_SCHEMA},
            },
        )
    except Exception as exc:  # noqa: BLE001 - judge failures must not crash the benchmark
        raise JudgeError(f"judge request failed: {exc}") from exc

    content = response.choices[0].message.content
    try:
        data = json.loads(content)
        score = int(data["score"])
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise JudgeError(f"judge returned unusable output: {content!r}") from exc

    if not 1 <= score <= 5:
        raise JudgeError(f"judge score out of range 1-5: {score}")

    return score
```

Note `judge_score` is defined here (before `list_local_models`/`ensure_model_pulled`
which Task 2 placed after `JUDGE_MODEL`) — reorder so `JUDGE_SCHEMA` through
`judge_score` come immediately after `JUDGE_MODEL`, and `list_local_models`/
`ensure_model_pulled` follow after that, all still before the `BenchmarkPrompt`
dataclass except `_build_judge_prompt`/`judge_score` themselves which come after it as
shown.

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v -k TestJudgeScore`
Expected: All 4 tests PASS.

- [x] **Step 5: Run the full test file, lint, format, typecheck**

```bash
uv run pytest tests/test_benchmark_mask_models.py -v
uv run ruff check scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run ruff format scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run mypy scripts/benchmark_mask_models.py
```
Expected: everything passes/clean.

- [x] **Step 6: Commit**

```bash
git add scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
git commit -m "feat(benchmark): add LLM judge scoring"
```

---

## Task 4: Orchestration, report formatting, and main()

**Files:**
- Modify: `scripts/benchmark_mask_models.py`
- Test: `tests/test_benchmark_mask_models.py`

**Interfaces:**
- Consumes: everything from Tasks 1-3 (`PROMPTS`, `ModelReport`, `PromptResult`,
  `list_local_models`, `ensure_model_pulled`, `judge_score`, `JudgeError`, `CANDIDATES`).
- Produces: `run_prompt_for_model(model: str, prompt: BenchmarkPrompt, *, host: str |
  None = None) -> PromptResult`, `benchmark_model(model: str) -> ModelReport`,
  `format_report(reports: list[ModelReport]) -> str`, `main() -> None` (the script's
  entry point, and the file's first and only `if __name__ == "__main__":` block).

- [x] **Step 1: Write the failing tests**

Append to `tests/test_benchmark_mask_models.py`:

```python
class TestRunPromptForModel:
    def test_hard_fail_when_generate_masks_raises(self, monkeypatch):
        def raising_generate_masks(description, **kwargs):
            raise benchmark_mask_models.MaskGenerationError("simulated failure")

        monkeypatch.setattr(benchmark_mask_models, "generate_masks", raising_generate_masks)

        result = benchmark_mask_models.run_prompt_for_model("some-model", benchmark_mask_models.PROMPTS[0])

        assert result.hard_fail_reason is not None
        assert "simulated failure" in result.hard_fail_reason
        assert result.judge_score is None

    def test_hard_fail_when_check_fails(self, monkeypatch):
        # generate_masks succeeds, but returns output the checker rejects.
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("?d?d?d?d?d")],  # wrong count
        )

        result = benchmark_mask_models.run_prompt_for_model("some-model", benchmark_mask_models.PROMPTS[0])

        assert result.hard_fail_reason is not None
        assert result.judge_score is None

    def test_passes_and_gets_judge_score(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("Summer?d?d?d?d?d?d")],
        )
        monkeypatch.setattr(benchmark_mask_models, "judge_score", lambda prompt, suggestions, **kwargs: 5)

        result = benchmark_mask_models.run_prompt_for_model("some-model", benchmark_mask_models.PROMPTS[0])

        assert result.hard_fail_reason is None
        assert result.judge_score == 5

    def test_judge_failure_does_not_crash(self, monkeypatch, capsys):
        monkeypatch.setattr(
            benchmark_mask_models,
            "generate_masks",
            lambda description, **kwargs: [_suggestion("Summer?d?d?d?d?d?d")],
        )

        def raising_judge(prompt, suggestions, **kwargs):
            raise benchmark_mask_models.JudgeError("judge is down")

        monkeypatch.setattr(benchmark_mask_models, "judge_score", raising_judge)

        result = benchmark_mask_models.run_prompt_for_model("some-model", benchmark_mask_models.PROMPTS[0])

        assert result.hard_fail_reason is None
        assert result.judge_score is None


class TestBenchmarkModel:
    def test_unpullable_model_hard_fails_every_prompt(self, monkeypatch):
        monkeypatch.setattr(benchmark_mask_models, "list_local_models", lambda host=benchmark_mask_models.LOCAL_HOST: {})
        monkeypatch.setattr(benchmark_mask_models, "ensure_model_pulled", lambda model, **kwargs: False)

        report = benchmark_mask_models.benchmark_model("nonexistent:model")

        assert report.disk_size_gb is None
        assert report.hard_fail_count == len(benchmark_mask_models.PROMPTS)

    def test_present_model_runs_all_prompts(self, monkeypatch):
        monkeypatch.setattr(
            benchmark_mask_models,
            "list_local_models",
            lambda host=benchmark_mask_models.LOCAL_HOST: {"some-model": 3 * 1024**3},
        )
        monkeypatch.setattr(benchmark_mask_models, "ensure_model_pulled", lambda model, **kwargs: True)
        monkeypatch.setattr(
            benchmark_mask_models,
            "run_prompt_for_model",
            lambda model, prompt, **kwargs: benchmark_mask_models.PromptResult(prompt.name, 1.0, None, 5),
        )

        report = benchmark_mask_models.benchmark_model("some-model")

        assert report.disk_size_gb == 3.0
        assert len(report.prompt_results) == len(benchmark_mask_models.PROMPTS)
        assert report.hard_fail_count == 0


class TestFormatReport:
    def test_recommends_smallest_passing_model(self):
        reports = [
            benchmark_mask_models.ModelReport(
                "big-good-model",
                20.0,
                [benchmark_mask_models.PromptResult(p.name, 1.0, None, 5) for p in benchmark_mask_models.PROMPTS],
            ),
            benchmark_mask_models.ModelReport(
                "small-good-model",
                3.0,
                [benchmark_mask_models.PromptResult(p.name, 1.0, None, 4) for p in benchmark_mask_models.PROMPTS],
            ),
            benchmark_mask_models.ModelReport(
                "small-bad-model",
                2.0,
                [benchmark_mask_models.PromptResult(p.name, 1.0, "hard fail", None) for p in benchmark_mask_models.PROMPTS],
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
                [benchmark_mask_models.PromptResult(p.name, 1.0, "hard fail", None) for p in benchmark_mask_models.PROMPTS],
            )
        ]

        report_text = benchmark_mask_models.format_report(reports)

        assert "no candidate clears the bar" in report_text
```

- [x] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v -k "RunPromptForModel or BenchmarkModel or FormatReport"`
Expected: FAIL with `AttributeError: module 'benchmark_mask_models' has no attribute
'generate_masks'` (or `'run_prompt_for_model'`/`'benchmark_model'`/`'format_report'`).

- [x] **Step 3: Add imports and implement orchestration, report, and main()**

In `scripts/benchmark_mask_models.py`, add three stdlib imports to the top import
block (alongside `json`, `subprocess`, `urllib.request` from Task 2):

```python
import sys
import time
```

Extend the existing `from hashcat_rosetta.nlmask import MaskSuggestion,
resolve_base_url` line (from Task 3) to also include `MaskGenerationError` and
`generate_masks`:

```python
from hashcat_rosetta.nlmask import MaskGenerationError, MaskSuggestion, generate_masks, resolve_base_url
```

Then add the following at the end of the file, after the `ModelReport` dataclass and
all 7 checker functions and the `PROMPTS` list:

```python
def run_prompt_for_model(
    model: str, prompt: BenchmarkPrompt, *, host: str | None = None
) -> PromptResult:
    start = time.monotonic()
    try:
        suggestions = generate_masks(prompt.description, model=model, host=host)
    except MaskGenerationError as exc:
        elapsed = time.monotonic() - start
        return PromptResult(prompt.name, elapsed, f"generate_masks raised: {exc}", None)
    elapsed = time.monotonic() - start

    fail_reason = prompt.check(suggestions)
    if fail_reason is not None:
        return PromptResult(prompt.name, elapsed, fail_reason, None)

    try:
        score = judge_score(prompt, suggestions, host=host)
    except JudgeError as exc:
        print(f"  warning: judge failed for {model}/{prompt.name}: {exc}", file=sys.stderr)
        score = None

    return PromptResult(prompt.name, elapsed, None, score)


def benchmark_model(model: str) -> ModelReport:
    pulled = ensure_model_pulled(model)
    models = list_local_models()

    if not pulled or model not in models:
        results = [PromptResult(p.name, 0.0, "model could not be pulled", None) for p in PROMPTS]
        return ModelReport(model, None, results)

    disk_size_gb = models[model] / (1024**3)
    results = [run_prompt_for_model(model, p) for p in PROMPTS]
    return ModelReport(model, disk_size_gb, results)


def format_report(reports: list[ModelReport]) -> str:
    header = f"{'model':<24}{'size(GB)':>10}{'hard_fails':>12}{'mean_score':>12}{'min_score':>11}{'time(s)':>10}"
    lines = [header, "-" * len(header)]

    def sort_key(r: ModelReport) -> float:
        return r.disk_size_gb if r.disk_size_gb is not None else float("inf")

    sorted_reports = sorted(reports, key=sort_key)
    for r in sorted_reports:
        size_str = f"{r.disk_size_gb:.1f}" if r.disk_size_gb is not None else "N/A"
        mean_str = f"{r.mean_judge_score:.1f}" if r.mean_judge_score is not None else "N/A"
        min_str = str(r.min_judge_score) if r.min_judge_score is not None else "N/A"
        lines.append(
            f"{r.model:<24}{size_str:>10}{r.hard_fail_count:>12}"
            f"{mean_str:>12}{min_str:>11}{r.total_seconds:>10.1f}"
        )

    passing = [
        r
        for r in sorted_reports
        if r.hard_fail_count == 0 and r.mean_judge_score is not None and r.mean_judge_score >= 4
    ]
    if passing:
        best = passing[0]
        lines.append(
            f"\nRecommendation: {best.model} (smallest, {best.disk_size_gb:.1f} GB, clears the bar)"
        )
    else:
        lines.append(
            "\nRecommendation: no candidate clears the bar (0 hard fails, mean judge score >= 4)"
        )

    return "\n".join(lines)


def main() -> None:
    reports = [benchmark_model(m) for m in CANDIDATES]
    print(format_report(reports))


if __name__ == "__main__":
    main()
```

- [x] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_benchmark_mask_models.py -v`
Expected: All tests in the file PASS (37 total: 20 from Task 1 + 5 from Task 2 + 4
from Task 3 + 8 from Task 4's three new test classes — count the actual collected
total and confirm it matches `-v`'s printed count, don't just trust this arithmetic).

- [x] **Step 5: Lint, format, typecheck, full project test suite**

```bash
uv run ruff check scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run ruff format scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
uv run mypy scripts/benchmark_mask_models.py
uv run pytest -q
```
Expected: everything clean, full suite passes (this script has no runtime import
side-effects on the shipped package, so the existing suite should be unaffected).

- [x] **Step 6: Commit**

```bash
git add scripts/benchmark_mask_models.py tests/test_benchmark_mask_models.py
git commit -m "feat(benchmark): add orchestration, report, and main entry point"
```

---

## Manual Verification (not a task — run once implementation is complete)

This step requires a live local Ollama and is NOT part of the automated test suite
(the script pulls real models and makes real LLM calls, which can take significant
wall-clock time — expect the `qwen2.5:32b` and `qwen3-coder:latest` rows to run in
seconds each based on prior spot-checks, but budget extra time for the smaller models
that haven't been tried yet, and for `ollama pull` on any candidate not already
present):

```bash
uv run python scripts/benchmark_mask_models.py
```

Confirm: the report table prints one row per candidate in `CANDIDATES`, sorted by disk
size; `qwen2.5:32b`'s row shows a nonzero hard-fail count (it's the known-bad reference
— the `season_digits_special` prompt should be the one that fails, per the earlier
manual finding); `qwen3-coder:latest`'s row shows 0 hard fails; the final
"Recommendation:" line names a real candidate or explicitly states none clears the bar.
