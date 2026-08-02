# Benchmark harness: selecting the smallest reliable model for `--mask`

## Context

The `--mask` feature's default model, `qwen3.6:35b-a3b`, turned out to be a "thinking"
model: for the mushroom-varieties test prompt its hidden reasoning chain ran past 4,000
tokens without ever reaching the visible answer, and Ollama's OpenAI-compatible endpoint
(the only interface `nlmask.py` uses) does not honor the `think: false` switch that
suppresses this on Ollama's native API. A same-family non-thinking model,
`qwen3-coder:latest`, was spot-checked and produced correct, fast output for several
prompts. A different candidate, `qwen2.5:32b`, was also fast but silently corrupted
`?s?d` into `??s?d` — a 33x keyspace undercount that our own deterministic validator
cannot catch, because the output is syntactically valid hcmask, just semantically wrong.

Those findings were all single, ad-hoc spot-checks. This harness formalizes the
comparison: run a fixed set of prompts against a curated shortlist of small, non-thinking
models, time each, and judge correctness, so the `--mask` default can be chosen from
evidence instead of one-off manual testing. Thinking models are excluded from the
candidate list entirely — that determination was already made in the parent debugging
session (`nlmask.py`'s hidden-reasoning problem is inherent to the model class, not a
prompt-tuning problem), so this harness is scoped to comparing non-thinking candidates.

## Scope

A standalone script, run manually and not part of the shipped package: `scripts/benchmark_mask_models.py`.
Not a CLI subcommand, not wired into `tests/`. Runs against the **local** Ollama only
(the security property of `--mask` is that it never leaves the operator's machine, so the
model chosen for the *default* must be evaluated on realistic local hardware, not a
shared multi-GPU box).

## Candidates

Seven non-thinking models spanning a real size range, to find the smallest one that
still clears the accuracy bar:

| Model | Params | Notes |
|---|---|---|
| `granite4:3b` | ~3.4B | smallest; needs pulling |
| `mistral:latest` | 7.2B | needs pulling |
| `qwen2.5:latest` | 7.6B | already local |
| `llama3.1:8b` | 8B | needs pulling |
| `phi4:14b` | 14.7B | needs pulling |
| `qwen2.5:32b` | 32.8B | already local; known to corrupt `?s?d` — kept as a "known-bad" reference point |
| `qwen3-coder:latest` | ~18GB on disk (MoE) | already local; known-good reference point from manual spot-check |

The script pulls any candidate not already present (`ollama pull <name>`) before running.

## Test prompts (fixed set of 7)

Each prompt has a hand-written expectation used by the deterministic gate, and is also
shown to the judge model alongside the candidate's raw output:

1. **Literal + digits** — `"The word 'Summer' followed by six digits."` Expect exactly
   one suggestion, mask `Summer?d?d?d?d?d?d`, keyspace 1,000,000.
2. **Category enumeration** — the mushroom-varieties prompt from the earlier bug fix.
   Expect ≥2 suggestions, every one with a non-empty literal prefix (this is the
   regression test for the `SYSTEM_PROMPT` fix already shipped in `nlmask.py`).
3. **Mixed builtin composition** — `"a capitalized season, two digits, and a special
   char"`. Expect only real builtin tokens (`?u`/`?l`/`?d`/`?s`) in the mask, nothing that
   parses as an accidental literal — the deterministic gate checks this by confirming
   `mask.tokens()` contains no unexpected literal `?`/letter split.
4. **Explicit multi-variant** — `"either 4 or 6 digits"`. Expect exactly 2 suggestions.
5. **Custom charset** — `"a lowercase vowel repeated four times, followed by two
   digits"`. Expect a mask referencing `?1` with a custom charset whose expanded content
   is exactly `aeiou` (5 chars) or a subset, and keyspace matching `5**4 * 10`.
6. **Hex token** — `"a 4-character lowercase hex string followed by two digits"`. Expect
   `?h?h?h?h?d?d`.
7. **Literal `?` escaping** — `"a literal question mark followed by three digits"`.
   Expect the mask, once parsed, to contain exactly one literal `?` token followed by
   3 digit tokens — this is the direct regression test for the `qwen2.5:32b` corruption
   bug (`??s?d` instead of `?s?d`), just phrased as an intentional escape instead of an
   accidental one.

## Execution and timing

For each candidate model, for each prompt: call `hashcat_rosetta.nlmask.generate_masks`
directly (the real production function — same timeout/retry logic already shipped, and
`client=None` so a real `OpenAI` client hits the real local Ollama), record wall-clock
time. Run once per (model, prompt) pair — no repeated trials; the fixed 60s client
timeout already shipped means a hung request fails fast rather than skewing an average.

## Scoring

**Deterministic gate (hard, per prompt):** `generate_masks` must return without raising,
produce at least one suggestion, and each suggestion's `mask.HcmaskLine` must satisfy the
prompt's hand-written expectation above (checked with plain code, not an LLM). Any
failure here is a hard 0 for that prompt — the judge is not invoked for it, since no
score from an LLM judge changes "produced no valid answer" or "produced a token-corrupted
mask" into a pass.

**Judge gate (only for prompts that pass the deterministic gate):** `qwen3-coder:latest`
is shown the original prompt, the candidate's raw suggestions (mask lines + `why`
fields), and the deterministic facts our own parser computed (keyspace, per-token
breakdown from `mask.describe()`). It scores 1-5 on "does this fully and correctly
satisfy the request" — this catches things the deterministic gate can't, like prompt 2's
category enumeration picking implausible or repeated category members, or prompt 3
choosing a technically-valid but semantically odd interpretation.

## Report

One row per candidate: disk size in GB (`ollama list` output, the VRAM proxy), count of
deterministic hard-fails (out of 7), mean judge score across prompts that passed the
gate, minimum judge score across those prompts (worst case matters more than average for
a security tool — one badly wrong prompt should not be averaged away by six good ones),
and total wall-clock time across all 7 prompts. Printed as a plain table, sorted by disk
size ascending, with hard-fail count and min judge score highlighted for any candidate
that fails to clear zero hard-fails / mean score ≥ 4. Final line of the report states the
recommendation explicitly: the smallest-disk-size candidate with zero hard-fails and mean
judge score ≥ 4 — or "no candidate clears the bar" if none do.

## Error handling

A model that 404s/times out on every prompt is recorded as a full-row failure (all 7
prompts hard-failed, disk size still shown since the model is present locally) rather
than crashing the whole run. A model that fails to *pull* is recorded with disk size
`N/A` and all 7 prompts hard-failed, for the same reason. Either way the script proceeds
to the remaining candidates rather than aborting.

## Out of scope

- No change to `nlmask.py`'s shipped default model as part of this script — the
  benchmark produces a recommendation; adopting it (changing `_DEFAULT_MODEL`, updating
  docs/tests) is a separate follow-up decision after reviewing the report.
- No gpu-host/remote comparison (see Scope).
- No repeated-trial statistics (min/max/stddev) — one run per (model, prompt) is enough
  for this comparison; this is a one-off evaluation tool, not a CI benchmark suite.
