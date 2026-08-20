#!/usr/bin/env python3
"""Benchmark candidate local Ollama models for the --mask feature.

Runs a fixed, progressively harder set of hcmask-generation prompts against a
curated shortlist of
small, non-thinking models via hashcat_rosetta.nlmask.generate_masks (the real
production code path — same timeout/retry logic already shipped). Each
prompt's output is checked deterministically first (hard gate: does it parse,
does it match the hand-written expectation for that prompt), then judged by
JUDGE_MODEL (deliberately not a candidate itself, to avoid self-grading bias)
for overall correctness/plausibility. Every suggestion is also appended to
SUGGESTIONS_LOG_PATH (if set) for manual/agent spot-checking alongside the
automated score. Prints a report ranking candidates by disk size (a VRAM
proxy) among those that pass the deterministic gate.

This script is NOT part of the installed package and does NOT change
nlmask.py's shipped default model — see
docs/superpowers/specs/2026-08-01-mask-model-benchmark-design.md.

Runs against two Ollama targets — CANDIDATE_HOST for the models under test,
JUDGE_HOST for the judge model — configurable via the BENCHMARK_CANDIDATE_HOST
/ BENCHMARK_JUDGE_HOST environment variables (both default to the local
Ollama). Never falls back to the ambient OLLAMA_HOST env var, to avoid a
prior bug class where pulls landed on a different server than the one being
queried. Point the two at separate hosts (e.g. a large remote GPU box for
candidates, a smaller one for the judge) when the candidate models don't
fit on a single shared GPU, so the judge's GPU/compute needs don't contend
with candidate testing.

Usage:
    uv run python scripts/benchmark_mask_models.py
    BENCHMARK_CANDIDATE_HOST=http://big-gpu-host:11434 \\
        BENCHMARK_JUDGE_HOST=http://other-host:11434 \\
        uv run python scripts/benchmark_mask_models.py

Set BENCHMARK_SKIP_JUDGE=1 to skip the model judge entirely: the
deterministic checkers still run and every suggestion is written to
SUGGESTIONS_LOG_PATH, but scoring is left to whoever reads that log (a
human, or the agent driving the sweep). Judge scores in the report are then
all N/A. Use this when judge calibration is itself in question — a swapped
judge model silently shifts every score and breaks comparison across sweeps.

Set BENCHMARK_THINK=both to sweep each candidate twice, once with
generate_masks(think=True) (the shipped default) and once with think=False;
`true` (default) or `false` runs just that one setting. The report's `think`
column distinguishes the two runs of the same model.

Requires: running Ollama servers at CANDIDATE_HOST and JUDGE_HOST; `ollama`
on PATH locally to pull missing models (pulls are pinned to the relevant
host regardless of the local OLLAMA_HOST setting). Only CANDIDATE_HOST is
needed when BENCHMARK_SKIP_JUDGE is set.
"""

from __future__ import annotations

import json
import os
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

# Never read the ambient OLLAMA_HOST here — see module docstring. Each has
# its own dedicated env var instead, defaulting to the local Ollama.
CANDIDATE_HOST = os.environ.get("BENCHMARK_CANDIDATE_HOST", "http://localhost:11434")
JUDGE_HOST = os.environ.get("BENCHMARK_JUDGE_HOST", "http://localhost:11434")

# Expanded to all non-tiny (>=8GB) models available on the candidate host,
# excluding JUDGE_MODEL itself (never a candidate — self-grading bias).
# SYSTEM_PROMPT has changed materially since any prior sweep (8 custom
# charsets instead of 4, the 256-position/non-empty-mask constraints, the
# generic-vs-specific charset rule, category cap, bracket-avoidance,
# duplicate suppression) — prior per-model results are not comparable,
# every candidate here needs a fresh run.
# Ordered most- to least-decision-relevant rather than by size: the sweep
# writes BENCHMARK_RESULTS_PATH incrementally, so a run cut short still
# answers "should _DEFAULT_MODEL change?" Incumbent default first, then the
# newest-generation models on the host, then prior 0-hard-fail finishers,
# then the rest.
#
# Scoped to models that could plausibly ship as _DEFAULT_MODEL: <=20GB, so
# they fit one GPU alongside a working cracking session. The 26-52GB tier on
# the candidate host (mixtral:8x7b, llama3.3:70b, qwen2.5:72b, hermes3:70b,
# deepseek-r1:70b, qwen3-coder-next:Q4_K_M) is deliberately excluded, not
# overlooked: the prior sweep's best 70B tied devstral-small-2:24b on quality
# at 2.8x the size, so it can't win a tie broken by size. Re-add that tier
# only to answer "what's the ceiling", not "what should we default to".
#
# qwen3.5:27b excluded on measured latency, not quality: in this sweep it
# averaged ~4-5 minutes per prompt against devstral-small-2:24b's ~25s (and
# timed out entirely on its first, cold-load request), which both disqualifies
# it as an interactive default and consumes ~3h of sweep wall clock on its
# own. Re-test it only if the latency changes.
CANDIDATES: list[str] = [
    "devstral-small-2:24b",
    "hf.co/daway845/Qwen3.8-27B-Abliterated-GGUF:Q4_K_M",
    "gemma4:31b",
    "qwen3:30b",
    "gemma3:27b",
    "dengcao/Qwen3-30B-A3B-Instruct-2507:latest",
    "mistral-small:24b",
    "qwen3.5:9b",
    "phi4:14b",
]

JUDGE_MODEL = "gpt-oss:20b"

# Set BENCHMARK_SKIP_JUDGE=1 to run the deterministic checkers only and leave
# scoring to whoever reads SUGGESTIONS_LOG_PATH. JUDGE_MODEL is then never
# contacted or pulled.
SKIP_JUDGE = os.environ.get("BENCHMARK_SKIP_JUDGE", "") not in ("", "0")

# Give up on a candidate after this many consecutive hard fails — see
# benchmark_model(). One is enough to disqualify it; the rest is wall clock
# spent re-proving that. Set above 1 so a single transient blip (a cold model
# load racing the SDK timeout) doesn't end an otherwise fine candidate's run.
MAX_CONSECUTIVE_HARD_FAILS = 3

# Which values of nlmask.generate_masks()'s `think` toggle to sweep, set via
# BENCHMARK_THINK={true,false,both}. `think` is a real quality/latency axis,
# not an implementation detail: for a hybrid-reasoning model it changes both
# the answer and the wall clock, and "true" (the shipped default) is not
# automatically the better setting for a task whose output is a short
# grammar-constrained JSON object. Defaults to the shipped default alone, so
# a plain run still measures production behavior.
_THINK_ENV = os.environ.get("BENCHMARK_THINK", "true").strip().lower()
if _THINK_ENV == "both":
    THINK_SETTINGS: list[bool] = [True, False]
elif _THINK_ENV in ("false", "0", "no"):
    THINK_SETTINGS = [False]
elif _THINK_ENV in ("true", "1", "yes"):
    THINK_SETTINGS = [True]
else:
    raise SystemExit(f"BENCHMARK_THINK must be true, false, or both — got {_THINK_ENV!r}")

# The judge host may have a small/shared GPU with other concurrent consumers
# and a service-wide context-length setting that reserves a KV cache large
# enough to spill even a mid-size model onto CPU; capping it here keeps the
# judge fully on GPU (gemma3:12b @ 8192 ctx measured at 8.0GB / 100% GPU)
# regardless of that global setting. Deliberately not a Qwen3 model, to
# avoid the hidden "thinking" hangs/timeouts that family caused as a judge
# before.
JUDGE_NUM_CTX = 8192

JUDGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "score": {
            "type": "integer",
            "description": "1 (does not satisfy the request) to 5 (fully and precisely satisfies it)",
        },
        "reason": {"type": "string", "description": "one short clause"},
        "prompt_fix_suggestion": {
            "type": "string",
            "description": (
                "If score < 5: one concrete, specific suggestion for how the "
                "generator's system prompt could be reworded to prevent this "
                "exact mistake next time (e.g. 'clarify that X token means Y', "
                "not 'be more careful'). Empty string if score is 5."
            ),
        },
    },
    "required": ["score", "reason", "prompt_fix_suggestion"],
    "additionalProperties": False,
}

JUDGE_SYSTEM_PROMPT = (
    "You grade whether a set of hashcat mask suggestions fully and correctly "
    "satisfies an English request. Score 1 (does not satisfy the request at "
    "all) to 5 (fully and precisely satisfies it). Return JSON matching the "
    "schema. No step-by-step reasoning in the `reason` field — one short "
    "clause. If score < 5, `prompt_fix_suggestion` must name a concrete, "
    "specific rewording of the generator's system prompt that would have "
    "prevented this exact mistake — not generic advice like 'be more "
    "careful' or 'follow instructions better'. If score is 5, "
    "`prompt_fix_suggestion` must be an empty string.\n\n"
    "Judge CORRECTNESS and QUANTITY separately, and never let a quantity "
    "complaint drag down a correctness score: a single suggestion that "
    "exactly and precisely matches the request is still fully correct even "
    "if the request implied several variants would be welcome — that is a "
    "quantity shortfall, not an error, and must not be described as "
    "'incorrect' in the `reason` field. Score purely on whether each given "
    "suggestion, taken on its own, satisfies the pattern described. Before "
    "concluding a custom-charset mask (a comma-separated hcmask line, e.g. "
    "'aeiou,?1?1?1?1?d?d') is wrong, re-read the custom-charset definitions "
    "given alongside it — a mask defining exactly the right charset content "
    "and referencing it correctly is correct syntax, not an error, even "
    "though it looks different from a mask using only builtin tokens."
)


class JudgeError(Exception):
    """Raised when the judge model call fails or returns unusable output."""


@dataclass
class JudgeVerdict:
    """The judge model's full verdict for one (prompt, suggestions) pair.

    Attributes:
        score: 1-5, how well the suggestions satisfy the prompt.
        reason: The judge's one-clause rationale for that score — kept so
            a surprising score (especially a low one) can be audited
            against the judge's own stated reasoning instead of trusted
            blindly.
        prompt_fix_suggestion: When score < 5, the judge's concrete
            suggestion for rewording generator's SYSTEM_PROMPT to prevent
            this exact mistake. Empty string when score is 5.
    """

    score: int
    reason: str
    prompt_fix_suggestion: str


def list_local_models(host: str = CANDIDATE_HOST) -> dict[str, int]:
    """Return {model_name: size_in_bytes} for every model on the local Ollama."""
    url = f"{host.rstrip('/')}/api/tags"
    with urllib.request.urlopen(url, timeout=10) as response:
        data = json.loads(response.read())
    return {m["name"]: m["size"] for m in data.get("models", [])}


def ensure_model_pulled(model: str, *, host: str = CANDIDATE_HOST) -> bool:
    """Pull `model` if it isn't already present locally.

    Returns True if the model is present after this call (whether it was
    already there or the pull succeeded), False if the pull failed.

    The `ollama` CLI picks its target server from the `OLLAMA_HOST`
    environment variable, which may point somewhere other than `host` (e.g.
    a shared team server). Overriding it for this subprocess only ensures
    the pull lands on the same server `host` will be queried against —
    otherwise the model can "pull successfully" to the wrong host and still
    be reported missing on every later check.
    """
    if model in list_local_models(host):
        return True
    env = dict(os.environ)
    env["OLLAMA_HOST"] = host.split("://", 1)[-1]
    result = subprocess.run(["ollama", "pull", model], capture_output=True, timeout=1800, env=env)
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
    lines = [
        f"Original request: {prompt.description}",
        "",
        "hcmask line format: comma-separated fields, where every field except "
        "the last is a custom charset definition (in order, defining ?1, ?2, "
        "?3, ...), and the last field is the mask itself, which may reference "
        "those charsets as ?1-?8. E.g. 'aeiou,?1?1?1?1?d?d' defines custom "
        "charset ?1 as the literal characters a/e/i/o/u, then the mask is "
        "?1?1?1?1?d?d (four vowels, then two digits) -- this is CORRECT syntax "
        "for 'a vowel repeated four times, then two digits', not an error.",
        "",
        "Candidate's suggestions:",
    ]
    for s in suggestions:
        full_line = format_hcmask_line(s.custom_charsets, s.mask)
        lines.append(f"- mask: {full_line}")
        if s.custom_charsets:
            charset_desc = ", ".join(
                f"?{i}={c!r}" for i, c in enumerate(s.custom_charsets, start=1)
            )
            lines.append(f"  custom charsets: {charset_desc}")
        lines.append(f"  description: {describe(s.line)}")
        lines.append(f"  why: {s.why}")
    return "\n".join(lines)


def judge_score(
    prompt: BenchmarkPrompt,
    suggestions: list[MaskSuggestion],
    *,
    model: str = JUDGE_MODEL,
    host: str = JUDGE_HOST,
    client: Any = None,
) -> JudgeVerdict:
    """Score how well `suggestions` satisfies `prompt`, via the judge model.

    Returns the judge's full verdict (score AND its stated reason) — the
    reason is what makes a surprising score auditable instead of an opaque
    number, so it must never be discarded by a caller.

    Raises JudgeError on any failure: the request itself failing, malformed
    JSON in the response, or a score outside 1-5.
    """
    active_client: Any = (
        client
        if client is not None
        else OpenAI(base_url=resolve_base_url(host), api_key="ollama", timeout=180.0, max_retries=0)
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
            # Explicitly disabled: enabling `think` on Qwen3 hybrid-reasoning
            # models caused judge calls to time out at a high rate (same
            # failure mode noted in the CHANGELOG for qwen3.6:35b-a3b's
            # hidden reasoning tokens burning the response budget). Revisit
            # if the judge's score quality needs improving later.
            # num_ctx caps the KV cache so the judge model stays fully on
            # GPU rather than spilling to CPU under the judge host's much
            # larger global context length.
            extra_body={"think": False, "options": {"num_ctx": JUDGE_NUM_CTX}},
        )
    except Exception as exc:  # noqa: BLE001 - judge failures must not crash the benchmark
        raise JudgeError(f"judge request failed: {exc}") from exc

    content = response.choices[0].message.content
    try:
        data = json.loads(content)
        score = int(data["score"])
        reason = str(data["reason"])
        prompt_fix_suggestion = str(data["prompt_fix_suggestion"])
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise JudgeError(f"judge returned unusable output: {content!r}") from exc

    if not 1 <= score <= 5:
        raise JudgeError(f"judge score out of range 1-5: {score}")

    return JudgeVerdict(score=score, reason=reason, prompt_fix_suggestion=prompt_fix_suggestion)


@dataclass
class PromptResult:
    """The outcome of running one (model, prompt) pair.

    Attributes:
        prompt_name: Matches BenchmarkPrompt.name.
        elapsed_seconds: Wall-clock time for the generate_masks call.
        hard_fail_reason: Set only when generate_masks() itself raised — the
            model's output couldn't be turned into valid mask objects at
            all (bad JSON, API error, etc). This is a real infrastructure/
            parsing failure, not a quality judgment. When set, soft_fail_reason
            and judge_score are always None — there's nothing to check or judge.
        soft_fail_reason: Set when generate_masks() succeeded but the
            deterministic checker rejected the content (wrong keyspace,
            wrong token counts, duplicate suggestions, etc). The output was
            well-formed, it just didn't satisfy the request — the judge
            still scores it, so a bad soft fail shows up as a low
            judge_score rather than being hidden.
        judge_score: 1-5 from the judge model, or None if hard-failed or the
            judge call itself failed.
        judge_reason: The judge's one-clause rationale for judge_score, or
            None under the same conditions as judge_score. Kept so a
            surprising (especially low) score can be audited against the
            judge's own stated reasoning rather than trusted blindly.
        prompt_fix_suggestion: When judge_score < 5, the judge's concrete
            suggestion for rewording nlmask.py's SYSTEM_PROMPT to prevent
            this exact mistake. Empty string when judge_score is 5, None
            under the same conditions as judge_score.
        suggestion_count: Number of mask suggestions generate_masks() returned,
            or None if it hard-failed and returned nothing at all.
    """

    prompt_name: str
    elapsed_seconds: float
    hard_fail_reason: str | None
    judge_score: int | None
    soft_fail_reason: str | None = None
    suggestion_count: int | None = None
    judge_reason: str | None = None
    prompt_fix_suggestion: str | None = None


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
    think: bool = True

    @property
    def hard_fail_count(self) -> int:
        return sum(1 for r in self.prompt_results if r.hard_fail_reason is not None)

    @property
    def soft_fail_count(self) -> int:
        return sum(1 for r in self.prompt_results if r.soft_fail_reason is not None)

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
    def mean_suggestion_count(self) -> float | None:
        counts = [r.suggestion_count for r in self.prompt_results if r.suggestion_count is not None]
        return sum(counts) / len(counts) if counts else None

    @property
    def total_seconds(self) -> float:
        return sum(r.elapsed_seconds for r in self.prompt_results)


def _duplicate_reason(suggestions: list[MaskSuggestion]) -> str | None:
    """Return a failure reason if any two suggestions are the same hcmask line."""
    seen: set[str] = set()
    for s in suggestions:
        full_line = format_hcmask_line(s.custom_charsets, s.mask)
        if full_line in seen:
            return f"duplicate suggestion {full_line!r}"
        seen.add(full_line)
    return None


def _check_summer_digits(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
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


def _check_category_with_pattern(suggestions: list[MaskSuggestion]) -> str | None:
    """Shared checker for "name a category, apply a pattern" prompts.

    Used by mushroom_categories, bible_books_category, and
    european_cities_category — the requirement is identical regardless of
    the category's domain: >= 2 distinct suggestions, each with a literal
    baseword prefix.
    """
    if len(suggestions) < 2:
        return f"expected >= 2 suggestions, got {len(suggestions)}"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        literal_prefix = s.mask.split("?")[0]
        if not literal_prefix:
            return f"suggestion {s.mask!r} has no literal baseword prefix"
    return None


def _check_season_digits_special(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        toks = tokens(s.line)
        digit_count = sum(1 for t, _size in toks if t == "?d")
        special_count = sum(1 for t, _size in toks if t == "?s")
        if digit_count < 2:
            return f"expected >= 2 digit tokens (?d), got {digit_count} in {s.mask!r}"
        if special_count < 1:
            return f"expected >= 1 special token (?s), got {special_count} in {s.mask!r}"
    return None


def _check_four_or_six_digits(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        toks = tokens(s.line)
        if any(t != "?d" for t, _size in toks):
            return f"expected only digit tokens (?d), got {s.mask!r}"
        digit_count = len(toks)
        if digit_count not in (4, 6):
            return f"expected 4 or 6 digit tokens, got {digit_count} in {s.mask!r}"
    return None


def _check_vowel_custom_charset(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
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
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
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
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        toks = tokens(s.line)
        literal_q_count = sum(1 for t, _size in toks if t == "??")
        digit_count = sum(1 for t, _size in toks if t == "?d")
        if literal_q_count != 1:
            return f"expected exactly 1 literal '?' token (??), got {literal_q_count} in {s.mask!r}"
        if digit_count != 3:
            return f"expected exactly 3 digit tokens (?d), got {digit_count} in {s.mask!r}"
    return None


def _check_two_custom_charsets(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        if len(s.line.custom) != 2:
            return f"expected exactly 2 custom charsets, got {len(s.line.custom)} in {s.mask!r}"
        c1, c2 = expand_custom_charsets(s.line.custom)
        if set(c1.lower()) != {"x", "y", "z"}:
            return f"expected charset ?1 to be exactly x/y/z, got {s.line.custom[0]!r}"
        if set(c2.lower()) != {"1", "2", "3"}:
            return f"expected charset ?2 to be exactly 1/2/3, got {s.line.custom[1]!r}"
        toks = [t for t, _size in tokens(s.line)]
        if toks != ["?1", "?1", "?2", "?2"]:
            return f"expected token sequence ?1?1?2?2 with nothing else, got {s.mask!r}"
        ks = keyspace(s.line)
        if ks != 81:
            return f"expected keyspace 81 (3^2 * 3^2), got {ks:,}"
    return None


def _check_three_custom_charsets(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        if len(s.line.custom) != 3:
            return f"expected exactly 3 custom charsets, got {len(s.line.custom)} in {s.mask!r}"
        c1, c2, c3 = expand_custom_charsets(s.line.custom)
        if set(c1.lower()) != {"a", "e"}:
            return f"expected charset ?1 to be exactly a/e, got {s.line.custom[0]!r}"
        if set(c2.lower()) != {"b", "c", "d"}:
            return f"expected charset ?2 to be exactly b/c/d, got {s.line.custom[1]!r}"
        if set(c3.lower()) != {"7", "8", "9"}:
            return f"expected charset ?3 to be exactly 7/8/9, got {s.line.custom[2]!r}"
        toks = [t for t, _size in tokens(s.line)]
        if toks != ["?1", "?2", "?3"]:
            return f"expected token sequence ?1?2?3 with nothing else, got {s.mask!r}"
        ks = keyspace(s.line)
        if ks != 18:
            return f"expected keyspace 18 (2 * 3 * 3), got {ks:,}"
    return None


def _check_four_custom_charsets(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    expected_letters = ("a", "b", "c", "d")
    for s in suggestions:
        if len(s.line.custom) != 4:
            return f"expected exactly 4 custom charsets, got {len(s.line.custom)} in {s.mask!r}"
        expanded = expand_custom_charsets(s.line.custom)
        for i, (charset, letter) in enumerate(zip(expanded, expected_letters), start=1):
            if charset.lower() != letter:
                return (
                    f"expected charset ?{i} to be exactly {letter!r}, got {s.line.custom[i - 1]!r}"
                )
        toks = [t for t, _size in tokens(s.line)]
        if toks != ["?1", "?2", "?3", "?4"]:
            return f"expected token sequence ?1?2?3?4 with nothing else, got {s.mask!r}"
        ks = keyspace(s.line)
        if ks != 1:
            return f"expected keyspace 1 (four 1-char charsets), got {ks:,}"
    return None


def _check_custom_charset_backreference(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        if len(s.line.custom) != 2:
            return f"expected exactly 2 custom charsets, got {len(s.line.custom)} in {s.mask!r}"
        c1, c2 = expand_custom_charsets(s.line.custom)
        if set(c1) != set("0123456789"):
            return f"expected charset ?1 to be exactly the digits 0-9, got {s.line.custom[0]!r}"
        if set(c2) != set(c1) | {"a"}:
            return (
                f"expected charset ?2 to be charset ?1 plus the letter 'a', "
                f"got {s.line.custom[1]!r}"
            )
        toks = [t for t, _size in tokens(s.line)]
        if toks != ["?1", "?2"]:
            return f"expected token sequence ?1?2 with nothing else, got {s.mask!r}"
        ks = keyspace(s.line)
        if ks != 110:
            return f"expected keyspace 110 (10 * 11), got {ks:,}"
    return None


def _check_bible_verse_format(suggestions: list[MaskSuggestion]) -> str | None:
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        if not s.mask or s.mask.startswith("?"):
            return f"expected a literal book-name prefix, got {s.mask!r}"
        if ":" not in s.mask:
            return f"expected a literal ':' between chapter and verse, got {s.mask!r}"
        toks = tokens(s.line)
        digit_count = sum(1 for t, _size in toks if t == "?d")
        if digit_count < 2:
            return (
                f"expected at least 2 digit tokens (chapter + verse), got "
                f"{digit_count} in {s.mask!r}"
            )
    return None


def _check_bracket_charset_avoidance(suggestions: list[MaskSuggestion]) -> str | None:
    """Regression check for the '[...]' bracket-character-class hallucination.

    hcmask has no regex-style character class; a model that hallucinates one
    (e.g. "Patriots?d?d[ea34@jr?l]") produces a mask with literal '[' and ']'
    characters instead of using a real custom charset. See SYSTEM_PROMPT's
    "NO '[...]' bracket character classes" constraint.
    """
    if len(suggestions) < 2:
        return f"expected >= 2 suggestions (one per team), got {len(suggestions)}"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        full_line = format_hcmask_line(s.custom_charsets, s.mask)
        if "[" in full_line or "]" in full_line:
            return f"hallucinated bracket character class, got {full_line!r}"
        if not s.line.custom:
            return (
                f"expected a custom charset for 'one of these characters', got none in {s.mask!r}"
            )
        literal_prefix = s.mask.split("?")[0]
        if not literal_prefix:
            return f"suggestion {s.mask!r} has no literal team-name prefix"
    return None


def _check_custom_charset_no_brackets(suggestions: list[MaskSuggestion]) -> str | None:
    """Non-category version of the bracket-avoidance check: a single literal
    baseword followed by "one of these symbols", with no category involved.
    """
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        full_line = format_hcmask_line(s.custom_charsets, s.mask)
        if "[" in full_line or "]" in full_line:
            return f"hallucinated bracket character class, got {full_line!r}"
        if not s.line.custom:
            return f"expected a custom charset for 'one of these symbols', got none in {s.mask!r}"
        if not s.mask.lower().startswith("blue"):
            return f"expected mask to start with literal 'Blue', got {s.mask!r}"
    return None


def _check_small_category_full_enumeration(suggestions: list[MaskSuggestion]) -> str | None:
    """Regression check for the old hardcoded "always pick 6" category cap.

    "Days of the week" has exactly 7 real members — SYSTEM_PROMPT now says
    to list all of them when the category is this small, not truncate to an
    arbitrary handful (the prior default behavior for ANY category).
    """
    if len(suggestions) < 6:
        return (
            f"expected close to all 7 days of the week (>= 6), got "
            f"{len(suggestions)} — looks like the old fixed-count cap regressed"
        )
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        literal_prefix = s.mask.split("?")[0]
        if not literal_prefix:
            return f"suggestion {s.mask!r} has no literal day-name prefix"
    return None


def _check_large_category_capped_enumeration(suggestions: list[MaskSuggestion]) -> str | None:
    """Regression check for both failure directions on a large category.

    "US state names" has 50 real members. SYSTEM_PROMPT says to pick up to
    15 diverse ones — this must catch a regression back to an arbitrary
    small count (the old "always 6" bug) without requiring all 50 (which
    would make every local model time out, per the live testing that
    motivated the 600s timeout and the 15-item cap in the first place).
    """
    if len(suggestions) < 10:
        return (
            f"expected >= 10 (up to the 15-item cap) distinct state names, got "
            f"{len(suggestions)} — looks like the old fixed-count cap regressed"
        )
    if len(suggestions) > 20:
        return f"expected <= ~15 per the cap, got {len(suggestions)} (cap not respected)"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        literal_prefix = s.mask.split("?")[0]
        if not literal_prefix:
            return f"suggestion {s.mask!r} has no literal state-name prefix"
    return None


def _check_literal_word_not_decomposed(suggestions: list[MaskSuggestion]) -> str | None:
    """Regression check for the '?u??literal' letter-by-letter decomposition bug.

    A model asked for "the word 'Falcons', capitalized" must emit the literal
    string "Falcons" as-is, not decompose the first letter into a ?u token
    plus a stray '??' literal-question-mark token (e.g. "?u??alcons").
    """
    if not suggestions:
        return "expected at least 1 suggestion, got 0"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    for s in suggestions:
        if not s.mask.startswith("Falcons"):
            return (
                f"expected mask to start with literal 'Falcons' (not decomposed "
                f"into charset tokens), got {s.mask!r}"
            )
    return None


def _check_no_duplicate_small_category(suggestions: list[MaskSuggestion]) -> str | None:
    """Regression check for duplicate suggestions within one response.

    "Chess piece names" has exactly 6 real members (pawn, knight, bishop,
    rook, queen, king) — enough that a model repeating itself would be easy
    to miss without an explicit duplicate check.
    """
    if len(suggestions) < 5:
        return f"expected close to all 6 chess piece names (>= 5), got {len(suggestions)}"
    if (reason := _duplicate_reason(suggestions)) is not None:
        return reason
    literal_prefixes = [s.mask.split("?")[0].lower() for s in suggestions]
    if len(set(literal_prefixes)) != len(literal_prefixes):
        return f"expected all distinct chess piece names, got {literal_prefixes}"
    return None


PROMPTS: list[BenchmarkPrompt] = [
    BenchmarkPrompt(
        "summer_digits",
        "The word 'Summer' followed by six digits. Give as many distinct mask "
        "suggestions as you can, no duplicates.",
        _check_summer_digits,
    ),
    BenchmarkPrompt(
        "mushroom_categories",
        "Basewords should be based on mushroom varieties followed by one of the "
        "following patterns: [symbol+digit,digit+symbol]. Give suggestions for as "
        "many different mushroom varieties as you can, no duplicates.",
        _check_category_with_pattern,
    ),
    BenchmarkPrompt(
        "season_digits_special",
        "a capitalized season, two digits, and a special char. Give as many "
        "distinct mask suggestions as you can, no duplicates.",
        _check_season_digits_special,
    ),
    BenchmarkPrompt(
        "four_or_six_digits",
        "either 4 or 6 digits. Give as many distinct mask suggestions as you can, no duplicates.",
        _check_four_or_six_digits,
    ),
    BenchmarkPrompt(
        "vowel_custom_charset",
        "a lowercase vowel repeated four times, followed by two digits. Give as "
        "many distinct mask suggestions as you can, no duplicates.",
        _check_vowel_custom_charset,
    ),
    BenchmarkPrompt(
        "hex_digits",
        "a 4-character lowercase hex string followed by two digits. Give as many "
        "distinct mask suggestions as you can, no duplicates.",
        _check_hex_digits,
    ),
    BenchmarkPrompt(
        "literal_question_mark",
        "a literal question mark followed by three digits. Give as many distinct "
        "mask suggestions as you can, no duplicates.",
        _check_literal_question_mark,
    ),
    BenchmarkPrompt(
        "two_custom_charsets",
        "A custom charset made only of the letters x, y, and z, used twice, "
        "followed by a custom charset made only of the digits 1, 2, and 3, used "
        "twice — so the mask is ?1?1?2?2 with no other characters. Give as many "
        "distinct mask suggestions as you can, no duplicates.",
        _check_two_custom_charsets,
    ),
    BenchmarkPrompt(
        "three_custom_charsets",
        "Three custom charsets used once each, in order: the vowels a and e, "
        "the consonants b, c, and d, and the digits 7, 8, and 9 — so the mask "
        "is ?1?2?3 with no other characters. Give as many distinct mask "
        "suggestions as you can, no duplicates.",
        _check_three_custom_charsets,
    ),
    BenchmarkPrompt(
        "four_custom_charsets",
        "Four custom charsets, each containing exactly one distinct letter: A, "
        "B, C, and D respectively, combined in order as ?1?2?3?4 with no other "
        "characters. Give as many distinct mask suggestions as you can, no "
        "duplicates.",
        _check_four_custom_charsets,
    ),
    BenchmarkPrompt(
        "custom_charset_backreference",
        "A custom charset ?1 containing the digits 0-9, and a second custom "
        "charset ?2 defined as charset 1 plus the letter 'a' (i.e. ?2's "
        "definition references ?1), combined as ?1?2 with no other characters. "
        "Give as many distinct mask suggestions as you can, no duplicates.",
        _check_custom_charset_backreference,
    ),
    BenchmarkPrompt(
        "bible_books_category",
        "Basewords should be based on books of the Bible followed by one of "
        "the following patterns: [symbol+digit,digit+symbol]. Give suggestions "
        "for as many different books as you can, no duplicates.",
        _check_category_with_pattern,
    ),
    BenchmarkPrompt(
        "european_cities_category",
        "Basewords should be based on European capital cities followed by one "
        "of the following patterns: [symbol+digit,digit+symbol]. Give "
        "suggestions for as many different cities as you can, no duplicates.",
        _check_category_with_pattern,
    ),
    BenchmarkPrompt(
        "bible_verse_format",
        "A book of the Bible, followed by a chapter number, a literal colon, "
        "and a verse number — the format of a Bible verse reference, like "
        "'John3:16'. Give as many distinct mask suggestions as you can "
        "(different books/chapters/verses), no duplicates.",
        _check_bible_verse_format,
    ),
    # The following 6 prompts have no "give as many as you can, no
    # duplicates" reminder suffix (unlike the prompts above) — they
    # deliberately test whether SYSTEM_PROMPT's own constraints (bracket
    # avoidance, category-size-aware enumeration, literal-word integrity,
    # duplicate avoidance) hold up without a per-prompt nudge.
    BenchmarkPrompt(
        "nfl_teams_bracket_avoidance",
        "NFL sports teams. The first letter should be capitalized and then "
        "the candidate should end it two digits followed by one of the "
        "following characters the 'ea34@jr?l'",
        _check_bracket_charset_avoidance,
    ),
    BenchmarkPrompt(
        "one_of_symbols_no_brackets",
        "The word 'Blue' followed by one of the following symbols: !@#$%",
        _check_custom_charset_no_brackets,
    ),
    BenchmarkPrompt(
        "days_of_week_full_enumeration",
        "Basewords should be the days of the week followed by two digits.",
        _check_small_category_full_enumeration,
    ),
    BenchmarkPrompt(
        "us_states_capped_enumeration",
        "Basewords should be US state names followed by two digits.",
        _check_large_category_capped_enumeration,
    ),
    BenchmarkPrompt(
        "capitalized_literal_word_not_decomposed",
        "The word 'Falcons', with its first letter capitalized, followed by two digits.",
        _check_literal_word_not_decomposed,
    ),
    BenchmarkPrompt(
        "chess_pieces_no_duplicates",
        "Basewords should be chess piece names followed by four digits.",
        _check_no_duplicate_small_category,
    ),
]


def _log_suggestions_for_manual_review(
    model: str,
    prompt: BenchmarkPrompt,
    suggestions: list[MaskSuggestion],
    soft_fail_reason: str | None,
    judge_score: int | None,
    judge_reason: str | None,
    prompt_fix_suggestion: str | None,
    think: bool = True,
) -> None:
    """Append raw suggestions to SUGGESTIONS_LOG_PATH for spot-checking.

    Records the judge's score, its stated reason, and (when score < 5) its
    suggested SYSTEM_PROMPT wording fix alongside the raw suggestions — a
    transparency log so any score (especially a low or surprising one) can
    be audited against both the actual model output and the judge's own
    rationale, not trusted as an opaque number. No-op if
    SUGGESTIONS_LOG_PATH isn't set.
    """
    log_path = os.environ.get("SUGGESTIONS_LOG_PATH")
    if not log_path:
        return
    with open(log_path, "a") as f:
        f.write(
            json.dumps(
                {
                    "model": model,
                    "think": think,
                    "prompt": prompt.name,
                    "description": prompt.description,
                    "soft_fail_reason": soft_fail_reason,
                    "judge_score": judge_score,
                    "judge_reason": judge_reason,
                    "prompt_fix_suggestion": prompt_fix_suggestion,
                    "suggestions": [
                        {
                            "mask": format_hcmask_line(s.custom_charsets, s.mask),
                            "why": s.why,
                            "keyspace": keyspace(s.line),
                        }
                        for s in suggestions
                    ],
                }
            )
            + "\n"
        )
        f.flush()


def run_prompt_for_model(
    model: str,
    prompt: BenchmarkPrompt,
    *,
    candidate_host: str = CANDIDATE_HOST,
    judge_host: str = JUDGE_HOST,
    think: bool = True,
) -> PromptResult:
    start = time.monotonic()
    try:
        # generate_masks() itself now cross-checks every suggestion's
        # keyspace against hashcat-utils mp64 (when installed) as part of
        # its normal validation/retry path — see
        # hashcat_rosetta.mask.verify_keyspace_with_maskprocessor. A mismatch
        # surfaces here as a MaskGenerationError, same as any other
        # validation failure, so there's nothing extra to do in this
        # benchmark script for that check.
        suggestions = generate_masks(
            prompt.description, model=model, host=candidate_host, think=think
        )
    except MaskGenerationError as exc:
        elapsed = time.monotonic() - start
        reason = f"generate_masks raised: {exc}"
        print(f"  HARD FAIL {model}/{prompt.name}: {reason}", file=sys.stderr)
        return PromptResult(prompt.name, elapsed, reason, None)
    elapsed = time.monotonic() - start

    soft_fail_reason = prompt.check(suggestions)
    if soft_fail_reason is not None:
        print(f"  soft fail {model}/{prompt.name}: {soft_fail_reason}", file=sys.stderr)

    if SKIP_JUDGE:
        # No model judge: the deterministic checkers still run, and every
        # suggestion goes to SUGGESTIONS_LOG_PATH for an external reviewer
        # (a human, or the agent running the sweep) to score instead. Avoids
        # the judge-calibration problem where a swapped judge model silently
        # shifts every score and invalidates cross-sweep comparison.
        score, judge_reason, fix_suggestion = None, None, None
    else:
        try:
            verdict = judge_score(prompt, suggestions, host=judge_host)
            score, judge_reason, fix_suggestion = (
                verdict.score,
                verdict.reason,
                verdict.prompt_fix_suggestion,
            )
        except JudgeError as exc:
            print(f"  warning: judge failed for {model}/{prompt.name}: {exc}", file=sys.stderr)
            score, judge_reason, fix_suggestion = None, None, None

    _log_suggestions_for_manual_review(
        model, prompt, suggestions, soft_fail_reason, score, judge_reason, fix_suggestion, think
    )

    return PromptResult(
        prompt.name,
        elapsed,
        None,
        score,
        soft_fail_reason,
        len(suggestions),
        judge_reason,
        fix_suggestion,
    )


def benchmark_model(
    model: str,
    *,
    candidate_host: str = CANDIDATE_HOST,
    judge_host: str = JUDGE_HOST,
    think: bool = True,
) -> ModelReport:
    print(f"Benchmarking {model} (think={think})...", file=sys.stderr)

    try:
        pulled = ensure_model_pulled(model, host=candidate_host)
        models = list_local_models(candidate_host)
    except Exception as exc:  # noqa: BLE001 - infra failures must not crash the sweep
        results = [PromptResult(p.name, 0.0, f"infrastructure error: {exc}", None) for p in PROMPTS]
        return ModelReport(model, None, results, think)

    if not pulled or model not in models:
        results = [PromptResult(p.name, 0.0, "model could not be pulled", None) for p in PROMPTS]
        return ModelReport(model, None, results, think)

    disk_size_gb = models[model] / (1024**3)
    results = []
    consecutive_hard_fails = 0
    for i, p in enumerate(PROMPTS):
        result = run_prompt_for_model(
            model, p, candidate_host=candidate_host, judge_host=judge_host, think=think
        )
        results.append(result)

        # A model that can't answer at all (unreachable, or every request
        # hitting the 600s SDK timeout) would otherwise burn
        # len(PROMPTS) x 600s of wall clock proving the same thing repeatedly.
        # Bail out after MAX_CONSECUTIVE_HARD_FAILS and record the remainder
        # as skipped — the model is already disqualified by any hard fail, so
        # nothing decision-relevant is lost. Logged explicitly rather than
        # silently truncated.
        consecutive_hard_fails = (
            consecutive_hard_fails + 1 if result.hard_fail_reason is not None else 0
        )
        if consecutive_hard_fails >= MAX_CONSECUTIVE_HARD_FAILS:
            remaining = PROMPTS[i + 1 :]
            print(
                f"  ABORT {model}: {consecutive_hard_fails} consecutive hard fails, "
                f"skipping {len(remaining)} remaining prompts",
                file=sys.stderr,
            )
            results.extend(
                PromptResult(
                    r.name,
                    0.0,
                    f"skipped after {consecutive_hard_fails} consecutive hard fails",
                    None,
                )
                for r in remaining
            )
            break

    return ModelReport(model, disk_size_gb, results, think)


def format_report(reports: list[ModelReport]) -> str:
    header = (
        f"{'model':<24}{'think':>7}{'size(GB)':>10}{'hard_fails':>12}{'soft_fails':>12}"
        f"{'mean_score':>12}{'min_score':>11}{'avg_sugg':>10}{'time(s)':>10}"
    )
    lines = [header, "-" * len(header)]

    def sort_key(r: ModelReport) -> float:
        return r.disk_size_gb if r.disk_size_gb is not None else float("inf")

    sorted_reports = sorted(reports, key=sort_key)
    for r in sorted_reports:
        size_str = f"{r.disk_size_gb:.1f}" if r.disk_size_gb is not None else "N/A"
        mean_str = f"{r.mean_judge_score:.1f}" if r.mean_judge_score is not None else "N/A"
        min_str = str(r.min_judge_score) if r.min_judge_score is not None else "N/A"
        sugg_str = (
            f"{r.mean_suggestion_count:.1f}" if r.mean_suggestion_count is not None else "N/A"
        )
        lines.append(
            f"{r.model:<24}{str(r.think):>7}{size_str:>10}{r.hard_fail_count:>12}"
            f"{r.soft_fail_count:>12}{mean_str:>12}{min_str:>11}{sugg_str:>10}"
            f"{r.total_seconds:>10.1f}"
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

    accurate = [
        r for r in sorted_reports if r.hard_fail_count == 0 and r.mean_suggestion_count is not None
    ]
    if accurate:

        def _suggestion_count(r: ModelReport) -> float:
            assert r.mean_suggestion_count is not None
            return r.mean_suggestion_count

        most_prolific = max(accurate, key=_suggestion_count)
        lines.append(
            f"Most suggestions while accurate: {most_prolific.model} "
            f"({most_prolific.mean_suggestion_count:.1f} avg suggestions/prompt, 0 hard fails)"
        )
    else:
        lines.append("Most suggestions while accurate: no candidate has 0 hard fails")

    fix_suggestions = [
        (r.model, res.prompt_name, res.prompt_fix_suggestion)
        for r in sorted_reports
        for res in r.prompt_results
        if res.prompt_fix_suggestion
    ]
    if fix_suggestions:
        lines.append("\nPrompt improvement suggestions from the judge (score < 5):")
        for model, prompt_name, suggestion in fix_suggestions:
            lines.append(f"  [{model}/{prompt_name}] {suggestion}")

    return "\n".join(lines)


def main() -> None:
    if SKIP_JUDGE:
        print(
            "BENCHMARK_SKIP_JUDGE set: deterministic checks only, no model judge", file=sys.stderr
        )
    elif not ensure_model_pulled(JUDGE_MODEL, host=JUDGE_HOST):
        print(f"FATAL: judge model {JUDGE_MODEL!r} could not be pulled/found", file=sys.stderr)
        sys.exit(1)

    results_path = os.environ.get("BENCHMARK_RESULTS_PATH")
    reports = []
    for think in THINK_SETTINGS:
        for m in CANDIDATES:
            report = benchmark_model(m, think=think)
            reports.append(report)
            if not results_path:
                continue
            with open(results_path, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "model": report.model,
                            "think": report.think,
                            "disk_size_gb": report.disk_size_gb,
                            "hard_fail_count": report.hard_fail_count,
                            "soft_fail_count": report.soft_fail_count,
                            "mean_judge_score": report.mean_judge_score,
                            "min_judge_score": report.min_judge_score,
                            "mean_suggestion_count": report.mean_suggestion_count,
                            "total_seconds": report.total_seconds,
                        }
                    )
                    + "\n"
                )
                f.flush()
    print(format_report(reports))


if __name__ == "__main__":
    main()
