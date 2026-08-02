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
    expected_keyspace = (vowel_count**4) * (10**2)
    ks = keyspace(s.line)
    if ks != expected_keyspace:
        return (
            f"expected keyspace {expected_keyspace:,} ({vowel_count} vowels^4 * "
            f"100 digits), got {ks:,}"
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
