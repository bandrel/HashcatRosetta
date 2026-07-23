# Plan: Support hashcat debug mode 5

## Background

Hashcat `--debug-mode` writes a debug file with one line per rule application.
Field layouts (confirmed in `hashcat/src/debugfile.c`):

- Mode 4: `Original-Word:Finding-Rule:Processed-Word`
- Mode 5: `Original-Word:Finding-Rule:Processed-Word:Wordlist`

Mode 5 adds a trailing **wordlist** field: the dict path (e.g. `rockyou.txt`,
`/opt/wordlists/x.txt`) or one of the sentinels `<stdin>`, `<generic>`, `<none>`.
Modern hashcat always uses `:` as the separator; the legacy space-separated
format only ever had 3 fields.

`hashcat_rosetta.parser.DebugLogParser` currently hardwires 3 fields. On a mode-5
file, `_parse_colon_line` does `line.split(":", 2)` and the wordlist bleeds into
the candidate (candidate becomes `"processed:wordlist"`), silently corrupting
every candidate.

### Design decisions (locked with the user)

1. **Mode detection:** auto-detect field count, with an optional
   `--debug-mode {auto,4,5}` override flag (default `auto`). Backward compatible.
2. **Wordlist field:** store it AND add per-wordlist analysis (attribution of
   basewords/rules/candidates per source dict).

### Colon-in-data limitation (document, don't solve)

Hashcat does not escape colons, so basewords, candidates, and Windows wordlist
paths (`C:\...`) can contain `:`. The parser keeps the existing mode-4 assumption
(baseword has no colon; candidate may) and additionally assumes the **wordlist
field (last field) has no colon**. This is true for Linux paths and the
`<stdin>`/`<generic>`/`<none>` sentinels; Windows drive-letter paths are a known,
documented limitation, mitigated by the `--debug-mode 5` override.

## Task 1 — Parser: mode-5 field parsing, detection, and override

**File:** `hashcat_rosetta/parser.py` (+ tests in `tests/test_parser.py` or existing parser tests)

Use TDD. Write failing tests first, then implement.

Requirements:
- `DebugLogParser.__init__(self, debug_mode=None)` accepts an optional override:
  `None` (auto), `4`, or `5`. Store on `self`.
- Every parsed entry dict gains a `"wordlist"` key: the dict/sentinel string for
  mode-5 lines, `None` for mode-4 lines and the legacy space format.
- Colon parsing:
  - Mode 4 (3 fields): unchanged behavior — `baseword`, `rule`, `candidate`
    (candidate may contain colons), `wordlist=None`.
  - Mode 5 (4 fields): `baseword`, `rule` from `split(":", 2)`; then split the
    remainder into `candidate` and `wordlist` via `rsplit(":", 1)` so the
    candidate keeps any internal colons and the wordlist is the last field.
- Space parsing: add `wordlist: None` (space format stays 3-field).
- Auto-detection of mode from a sample of lines when no override is given:
  classify as mode 5 when the trailing colon-separated field is consistently a
  wordlist — i.e. equals one of `<stdin>`/`<generic>`/`<none>`, or is path-like
  (contains `/` or `\` or a common wordlist extension) and lines consistently
  have >= 3 colons. Otherwise mode 4. An explicit `debug_mode` override wins.
- Thread the override through `parse_debug_file` and `parse_debug_lines`
  (the analyzer sets it on the instance; keep the public method signatures stable
  or accept an optional arg — the analyzer will construct the parser with the mode).

Tests must cover:
- Mode-4 colon line → unchanged, `wordlist is None` (backward compat).
- Mode-4 candidate containing a colon is preserved.
- Mode-5 colon line → correct baseword/rule/candidate + wordlist; candidate NOT
  polluted with the wordlist.
- Mode-5 candidate containing an internal colon preserved (wordlist still = last field).
- Sentinel wordlists `<stdin>`, `<generic>`, `<none>` detected as mode 5.
- Auto-detection picks mode 5 for a mode-5 sample and mode 4 for a mode-4 sample.
- `--debug-mode` override forces the interpretation even against the heuristic.
- Space-format line still parses with `wordlist is None`.

## Task 2 — Analyzer: per-wordlist statistics

**File:** `hashcat_rosetta/debug_analyzer.py` (+ tests)

Use TDD.

Requirements:
- Add `debug_mode` param to `DebugAnalyzer.__init__` (default `None`) and pass it
  to `DebugLogParser`.
- Track a `wordlist_stats` structure in `_compute_analysis`, keyed by wordlist,
  aggregating count, unique basewords, unique candidates, unique rules
  (skip entries whose `wordlist` is `None`).
- Add `get_wordlist_statistics_summary()` (aggregate: total wordlists, total
  attributed entries) and `get_top_wordlists(top_n=10)` returning
  `(wordlist, count)` tuples, plus a per-wordlist detail accessor mirroring
  `get_rule_detail` (unique basewords/candidates/rules for a given wordlist).
- Include wordlist data in `export_to_dict` (only meaningfully populated for
  mode-5 inputs; empty for mode-4).
- `_compute_analysis` return dict gains `unique_wordlists`.

Tests must cover: wordlist aggregation from mode-5 entries, empty/absent for
mode-4 entries, top-wordlists ordering, export includes wordlist section.

## Task 3 — CLI: `--debug-mode` option and wordlist output

**File:** `hashcat_rosetta/cli.py` (+ tests using Click's `CliRunner`)

Use TDD.

Requirements:
- Add a Click option `--debug-mode` with choices `auto`/`4`/`5`, default `auto`;
  map `auto` → `None` and pass to `DebugAnalyzer(debug_mode=...)`.
- When wordlist data is present, add a "Wordlist Statistics" section to the
  default summary (total wordlists + top wordlists).
- Add a `--wordlists` flag (parallel to `--rules`/`--basewords`) that prints top
  wordlists with counts; with `--detail`, show unique basewords/rules per wordlist.
- Update the command docstring/help to mention mode-5 support.
- Does not affect the `--analyze-rules` path (rule-file analysis is unrelated).

Tests must cover: `--debug-mode 5` on a mode-5 fixture, `--wordlists` output,
default-summary wordlist section appears for mode-5 and is absent for mode-4.

## Task 4 — Documentation

**Files:** `CLAUDE.md`, `README.md`

- Document mode-5 support, the `--debug-mode` flag, the new `--wordlists` output,
  and the Windows-path colon limitation.
- No code; docs only.

## Verification (whole feature)

- `uv run pytest` green.
- `uv run ruff check hashcat_rosetta/ tests/` and `ruff format --check` clean.
- `uv run mypy hashcat_rosetta/` clean.
- Manual smoke: craft a small mode-5 fixture and run
  `uv run hashcat-rosetta fixture.txt --debug-mode 5 --wordlists`.
