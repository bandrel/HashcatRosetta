# Plan: correct `--wordlists` ranking under duplicate debug lines

## Problem

1. Duplicate lines inflate counts: `_compute_analysis()` increments per entry and
   `get_top_wordlists()` sorts on that count. hashcat writes one debug line per cracked
   hash and appends to the debugfile, so password reuse and re-runs both inflate ranking.
2. Wordlist keys unnormalized: `parser.py` stores the field verbatim, so `./rockyou.txt`
   and `rockyou.txt` are two rows, splitting one wordlist's count.

## Decisions

- Dedup ON by default, `--no-dedup` to opt out.
- Dedup key is the full tuple `(baseword, rule, candidate, wordlist_key)`.
- Normalize the path (`normpath`), keep full path as label. Do NOT basename, do NOT
  resolve symlinks or absolutize.
- Dedup lives in `DebugAnalyzer._compute_analysis()`, not the parser.

## Global Constraints

- Sentinels (`<stdin>`, `<generic>`, `<none>`) must NOT be path-normalized.
- Mode-4 entries (`wordlist is None`) keep working, stay excluded from wordlist_stats.
- `--no-dedup` applies to debug-file analysis only.
- Collapsed-duplicate count must be visible in summary output and `export_to_dict()`.
- Line length 100; ruff check, ruff format --check, and mypy must pass.

## Task 1: dedup + wordlist path normalization

TDD. Tests must cover: exact duplicates collapse with reported count; `--no-dedup`
preserves raw count; same triple under two wordlists stays 2 entries; `./x` merges with
`x` while `/opt/x` stays separate; sentinels unchanged; mode-4 still works; cross-file
dedup via `analyze_debug_files()`.

Implement: `_normalize_wordlist()` helper; dedup in `_compute_analysis()` with skip
counting; `DebugAnalyzer(dedup=True)`; `--no-dedup` CLI flag; summary + export reporting;
CLAUDE.md and --help updates.
