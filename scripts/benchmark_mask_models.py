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

import json
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from openai import OpenAI

from hashcat_rosetta.mask import (
    describe,
    expand_custom_charsets,
    format_hcmask_line,
    keyspace,
    tokens,
)
from hashcat_rosetta.nlmask import (
    MaskGenerationError,
    MaskSuggestion,
    generate_masks,
    resolve_base_url,
)

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


def run_prompt_for_model(
    model: str, prompt: BenchmarkPrompt, *, host: str = LOCAL_HOST
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
    print(f"Benchmarking {model}...", file=sys.stderr)

    try:
        pulled = ensure_model_pulled(model)
        models = list_local_models()
    except Exception as exc:  # noqa: BLE001 - infra failures must not crash the sweep
        results = [PromptResult(p.name, 0.0, f"infrastructure error: {exc}", None) for p in PROMPTS]
        return ModelReport(model, None, results)

    if not pulled or model not in models:
        results = [PromptResult(p.name, 0.0, "model could not be pulled", None) for p in PROMPTS]
        return ModelReport(model, None, results)

    disk_size_gb = models[model] / (1024**3)
    results = [run_prompt_for_model(model, p, host=LOCAL_HOST) for p in PROMPTS]
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
