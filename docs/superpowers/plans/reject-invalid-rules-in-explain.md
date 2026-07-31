# Plan: stop silently dropping invalid rule tokens

## Problem

`--explain` prints a confident, fabricated explanation for rules hashcat rejects outright.

Reproduced (hashcat v7 `--stdout` as oracle):

| Rule | hashcat | HashcatRosetta `--explain` |
|---|---|---|
| `$1 R32` | `No valid rules left.` | prints `$1` then `R3`, exit 0 |
| `$1 Zq` | `No valid rules left.` | prints `$1` then **`q: Duplicate every char`**, exit 0 |
| `$1 R3` | `pas9word1` | correct |
| `$1 Z2` | `password111` | correct |

Two root causes:

1. **`hashcat_rosetta/cli.py:712-724`** — `explain_rule`'s terminal `else` advances past
   anything it cannot explain with no record kept. Unknown opcodes vanish silently.
2. **`hashcat_rosetta/cli.py:700-701`** (and sibling `except (ValueError, IndexError)`
   handlers) — a bad numeric argument is swallowed and `i` advances by **1**, not past the
   argument. The argument character is then re-parsed as its own opcode. This is what turns
   `Zq` into a bogus `q: Duplicate every char` step: strictly worse than dropping, because
   the output is wrong rather than incomplete.
3. **`hashcat_rosetta/parser.py:488-490`** — `_tokenize_rule` drops unknown opcodes with a
   bare `i += 1` and no warning, while every other failure path there logs.

## Ground truth established against the hashcat binary

- **Unknown opcode → whole rule invalid.** Definitive; this is what kills `$1 R32`.
- **Numeric ("position") args use `conv_ctoi`: only `0-9` and `A-Z` are legal.**
  Verified: `D1` ok, `DA` ok, `Dz` invalid, `D!` invalid, `TA` ok, `Ta` invalid,
  `'z` / `pz` / `Lz` / `y!` all invalid.
- **Character args accept any byte.** Verified: `$z`, `$!`, `^z`, `@z` all valid.
- **Reject-class opcodes cannot be validated through `--stdout`.** hashcat discards reject
  rules in stdout mode, so `>5`, `<5`, `_5` report `No valid rules left.` even though the
  syntax is fine. The oracle cannot distinguish "invalid syntax" from "all candidates
  rejected" for these. **The validator must not flag their arguments.**

## Design

Keep `explain_rule`'s return contract exactly as-is — `hashcat_rosetta/_verify.py` consumes
its step list and the 32.4M-rule BARRAGE corpus run depends on it. Add validation alongside
rather than rewiring the walk.

### Task 1 — `find_rule_issues()` in `parser.py`

New pure function `find_rule_issues(rule_string: str) -> list[str]`, returning human-readable
problems (empty list == no detected problem). It walks the rule using the arity tables
already in `_verify.py` (`_THREE_ARG_OPCODES`, `_TWO_ARG_OPCODES`, `_ONE_ARG_OPCODES`,
`_ZERO_ARG_OPCODES`, `_ALL_KNOWN_OPCODES`) — import them or lift them to a shared home; do
not hand-copy a second table that can drift.

Flag only what the oracle proved:

- unknown opcode
- opcode truncated by end-of-rule (missing argument chars)
- non-`[0-9A-Z]` argument for a **numeric-arg** opcode, excluding the reject class

Be conservative: a false "invalid" verdict is worse than the current bug, since it would
break BARRAGE-scale analysis. When unsure, stay silent.

Derive the numeric-arg opcode set from the oracle, not from
`scripts/sweep_opcodes.py:102-103` — that file classifies `>` and `<` as char-arg, which is
fine for generating sweep rules but wrong for validation.

### Task 2 — arity-correct argument-error handling in `explain_rule`

Fix the `except (ValueError, IndexError)` handlers so a failed argument parse advances `i`
past the **whole token** (opcode + its declared arg count), never leaving an argument
character to be re-read as an opcode. `$1 Zq` must stop emitting a `q` step.

### Task 3 — surface it in the CLI

Both `--explain` call sites (`cli.py:833` for a rule file, `cli.py:844` for a single rule)
call `find_rule_issues()` first. On issues, report the rule as invalid — hashcat would
reject it — instead of printing a fabricated explanation. Single-rule `--explain` exits
non-zero. Rule-file mode reports the bad line and continues to the next rule.

### Task 4 — `parser.py` unknown-opcode warning

Replace the silent `i += 1` at `parser.py:488-490` with a `logger.warning`, matching the
three surrounding incomplete-opcode paths.

## Tests

TDD — failing test before each fix.

- `$1 R32` and `$1 Zq` are reported invalid, not explained (the two reproducers above).
- `$1 R3`, `$1 Z2`, `c sa@ ss$ $2 $0 $2 $5 i8- +0 ]` still explain correctly (regression).
- `find_rule_issues` returns `[]` for every rule in the existing verified fixtures — the
  false-positive guard. This is the most important test in the change.
- Numeric-arg matrix from the oracle table above: `DA`/`TA` clean, `Dz`/`D!`/`Ta` flagged.
- Char-arg opcodes with odd args (`$z`, `$!`, `^z`, `@z`) are never flagged.
- Reject-class opcodes (`>5`, `<z`, `_5`) are never flagged, per the oracle limitation.
- `parser.py` unknown-opcode path logs a warning (`caplog`).

## Verification

- `uv run pytest`
- `uv run ruff check hashcat_rosetta/ tests/ && uv run ruff format --check hashcat_rosetta/ tests/`
- `uv run mypy hashcat_rosetta/`
- `uv run python scripts/sweep_opcodes.py` — no new mismatches outside `KNOWN_LATENT`
- Re-run the four oracle rules and confirm agreement with hashcat
