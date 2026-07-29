# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases predating this file are summarized from their git history; see the tags
for exact timing.

## [0.4.0] - 2026-07-29

The headline is accuracy. A full byte-for-byte comparison against hashcat 7.1.2
over all 32.4M rules in `BARRAGE.rule` now reports **0 mismatches across
32,331,257 oracle-comparable rules**, and the per-opcode sweep is at 0
regressions. Getting there took a stack of engine fixes, most of which were
cases where `explain_rule()` was confidently describing a transformation
hashcat does not perform.

### Changed

- **BREAKING: the console script is now `hashcat-rosetta`, not `rosetta`.**
  Renamed to avoid a future `PATH` collision with unrelated tools. If you
  installed 0.3.0 and have `rosetta` in a script or in muscle memory, update
  it. `python -m hashcat_rosetta` works as before, and `hashcat_rosetta` with
  an underscore remains the import name rather than a command.
- **ASCII-only case mapping.** `l`, `u`, `c`, `C`, `t`, `E`, `e`, `T`, and `3`
  now case-map only ASCII `A-Z`/`a-z`, matching hashcat. Python's
  `str.lower()`/`upper()`/`swapcase()` also map Latin-1 accented bytes, which
  diverged whenever `L`/`R`/`B`/`+`/`-` had produced a high byte upstream in
  the same rule (`L6 l`, for example).
- **Length-expanding opcodes respect hashcat's 256-byte cap.** hashcat works in
  a fixed 256-byte buffer and treats a growing op as a no-op when the result
  would reach the cap — it does not truncate. Only `p` enforced this before, so
  `d`, `f`, `q`, `z`, `Z`, `y`, `Y`, `a`, `X`, `v` and the single-character
  appenders (`$`, `^`, `i`) grew the word unconditionally and produced
  candidates longer than hashcat's on long basewords. This was the cause of the
  intermittent nightly accuracy failures.
- Dev tooling moved to a PEP 735 dependency group.

### Added

- **hashcat `--debug-mode 5` support.** Mode 5 adds the source wordlist as a
  fourth field, and it is now handled end to end: parsed by `parser.py`,
  aggregated into per-wordlist statistics by `DebugAnalyzer`, exposed on the
  CLI via `--wordlists`, and emitted as a `WORDLIST` section in CSV export.
  Format detection covers mode 5 alongside mode 4, and can still be pinned
  explicitly with `--debug-mode`.
- **`B` now simulates hashcat's actual semantics.** The opcode is absent from
  hashcat's published rule documentation, but the kernel implements it as "byte
  at position N += ord(X) mod 256", with `X` read as a literal byte rather than
  a hashcat-encoded position. Verified empirically against 7.1.2 by sweeping
  `B0X` over `A`.
- **The `3NX` opcode is implemented** — toggle the case of the character after
  the Nth (0-indexed) occurrence of separator `X`. Roughly 25K rules in
  BARRAGE use it.
- **`\xNN` hex escape decoding.** Rules are decoded before application, mirroring
  hashcat, so `s\x20_` substitutes a literal space. About 572K BARRAGE rules
  use hex escapes. With this and `3NX` landed, unimplemented-opcode hits across
  the BARRAGE sweep dropped from 48,428 to 4.
- **Per-opcode correctness sweep.** A deterministic rule generator crossed with
  an argument grid, aggregated by leading opcode, with markdown and JSON
  renderers, exit-code wiring, and a CI job. `KNOWN_LATENT` marks opcodes whose
  divergence is understood and tracked rather than silently tolerated.
- **CLI banner**, printed to stderr so it never pollutes piped or exported
  stdout.
- A fast lint/type/unit-test CI workflow that runs on every PR. Previously only
  the heavy hashcat-dependent accuracy workflow ran in CI, so the unit suite
  never executed there. (#35)

### Fixed

- **Position arguments above 15 were parsed as hex and silently corrupted the
  rule.** 29 call sites used `int(c, 16)`, which handles only positions `0-F`,
  while hashcat encodes positions `0-Z` (0-35). Positions `G-Z` raised
  `ValueError`, the handler advanced by one byte, and the argument bytes were
  then reparsed as opcodes — producing wildly wrong candidates across half the
  position space. All opcodes now share a single `_hashcat_pos()` helper.
- **Bytewise ops rendered as UTF-8 instead of raw bytes in `--explain`.**
  `+`, `-`, `L`, `R`, and `B` build words from code points 0-255; printing
  those directly encoded 0x80-0xFF as multibyte sequences, misrepresenting
  hashcat's single-byte output. Bytes now display as `\xNN` at the print sites
  only, leaving genuine Unicode (the `→` arrow) intact. `+` and `-` also gained
  hashcat's mod-256 wrap, which additionally removes a `ValueError` on `-`
  at byte 0x00 that had been silently dropping the step. (#31)
- **Tokenizer arity was wrong for `3`, `X`, and `a`**, producing false
  "Incomplete opcode" warnings on valid rules during `--analyze-rules`
  (surfaced by `BARRAGE.rule`). `3` is 2-arg and was 0-arg; `X` is 3-arg and
  was 2-arg; `a` is a 0-arg legacy op, and as 1-arg it swallowed the following
  opcode. After the fix, sampling 150 distinct warned rules from BARRAGE,
  hashcat rejects 150/150 as genuinely malformed — the remaining warnings are
  true positives.
- **`Y0` duplicated the entire word.** `current[-0:]` is `current[0:]`, so it
  appended a full copy instead of zero characters. hashcat treats `Y0` as a
  no-op.
- **`p` rejected letter positions.** It parsed its argument with `int(n_char)`,
  decimal only, so `pA` raised and the rule fell through silently.
- **Filter opcodes leaked explanation prose into the candidate string.** When a
  filter (`!`, `<`, `>`, `%`, `(`, `)`, `=`) passed, the recorded step omitted
  the arrow separator that `_extract_final` keys on, so the description text
  became the candidate for any rule ending in a passing filter.
- **A space was treated as a truncation marker.** `_has_truncated_opcode` now
  only reports genuine truncation — running off the end of the rule — since a
  space is a valid literal argument (`$ ` appends a space).
- Verification-harness accuracy, so the oracle stops reporting spurious
  mismatches: filter opcodes are marked unsupported for `--stdout` comparison
  (hashcat refuses to emit candidates for any rule containing one, since
  filters live in the hashing flow); rules carrying an invalid position
  encoding are skipped rather than compared, because hashcat rejects them
  outright; and `3`'s first argument is validated for encoding without being
  bounds-checked, as it is an occurrence index rather than a word position and
  therefore never out of range (`3Zs` on a short word is a verified silent
  no-op).
- `--help` examples showed `rosetta ...` after the entry point had been
  renamed, so copy-pasting them failed. (#35)
- The pytest pre-commit hook now runs `uv run --extra dev pytest`, so a bare
  `uv sync` can no longer leave the venv without pytest and fall through to a
  `PATH` shim that recursed into an infinite exec loop.

## [0.3.0] - 2026-05-11

- Implement `a` (append memorized), `e` (title-case w/ separator), `v` (toggle
  every N chars), `(`/`)` (first/last char filters).
- Refresh opcode descriptions to match hashcat source.
- Add private `_verify` harness library and `verify_rule` / `verify_corpus` API.
- Add baseword corpus + accuracy smoke parametrized across it.
- Filter opcodes now reject (return `None`) when their condition fires, with a
  rejection-semantics agreement check against hashcat.
- CI: add per-PR accuracy smoke + nightly full verification, plus a stack of
  oracle-reliability fixes — bump the hashcat-utils pin to post-v1.9, strip
  trailing whitespace from generated rules, skip rules hashcat `--stdout`
  cannot oracle (`M`, `X`, JtR-only opcodes, truncated opcodes, out-of-bounds
  positions), preserve baseword whitespace through verification, treat empty
  result or baseword as parity rejections, use a per-call `--session` to dodge
  the hashcat 6.2.x single-instance lock under thread parallelism, prewarm the
  POCL kernel cache before the parallel pool, and scope the nightly run to fit
  the POCL runtime budget on `ubuntu-latest`.

## [0.2.0] - 2026-04-25

The version vendored by hate_crack.

- Apply QA review fixes across parser and analyzer.
- Add comprehensive test suite (rule matrix, edge cases, CLI, fixes).
- Implement missing opcodes (`M`, `X`, `=`, `B`) and add `verify_rules.py`
  validation script.
- Fix incorrect opcode documentation against hashcat source.
- Add hashcat-utils integration tests.
- Add pytest pre-commit hook.
