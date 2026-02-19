# Unimplemented Opcodes in `explain_rule()`

These hashcat rule opcodes are recognized by `parser.py` (tokenizer) and listed in
`formatting.py` (descriptions), but **not yet simulated** in `explain_rule()` in `cli.py`.

When a rule contains only unhandled opcodes, `explain_rule()` returns `None`/empty.
When a rule mixes handled and unhandled opcodes, the unhandled ones are silently
skipped (arity-aware skip ensures argument bytes aren't misinterpreted).

## Memory opcodes

These require a second internal buffer ("memory") that `explain_rule()` does not track.
Memory opcodes are CPU-side only (`-j`/`-k` mode) and not available in GPU rule files.

| Opcode | Arity | Description | Hashcat source reference |
|--------|-------|-------------|--------------------------|
| `M` | 0 | Memorize current word into memory buffer | `RULE_OP_MEMORIZE_WORD` |
| `4` | 0 | Append memory buffer to end of current word | `RULE_OP_MANGLE_APPEND_MEMORY` |
| `6` | 0 | Prepend memory buffer to beginning of current word | `RULE_OP_MANGLE_PREPEND_MEMORY` |
| `X` | 3 | Extract M chars from memory at pos N, insert into current at pos I | `RULE_OP_MANGLE_EXTRACT_MEMORY` |
| `Q` | 0 | Reject if current word matches memorized word | `RULE_OP_REJECT_MEMORY` |

### Implementation notes

- Add a `memory: str` variable alongside `current` in the explain loop.
- `M` saves `current` to `memory`.
- `4` does `current += memory`.
- `6` does `current = memory + current`.
- `X` is `XNMI`: extract M chars from memory starting at pos N, insert into current at pos I.
- `Q` rejects the candidate if `current == memory`.

**Note:** In hashcat-legacy, `m` (lowercase) was `RULE_OP_MANGLE_APPEND_MEMORY`, but modern
hashcat reassigned that function to `4`. The character `m` is unused in modern hashcat's rule engine.

## Reject/filter opcodes (no simulation needed)

These reject the candidate rather than transforming it. They are already partially
handled (steps are appended as informational notes) but do not modify `current`.

| Opcode | Arity | Description | Hashcat source reference |
|--------|-------|-------------|--------------------------|
| `=` | 2 | Reject if char at pos N is not X | `RULE_OP_REJECT_EQUAL_AT` |
| `(` | 1 | Reject if first char is not X | `RULE_OP_REJECT_EQUAL_FIRST` |
| `)` | 1 | Reject if last char is not X | `RULE_OP_REJECT_EQUAL_LAST` |

### Implementation notes

- These could optionally return a rejection indicator so the caller knows the
  candidate would be filtered out by hashcat. Currently `!`, `>`, `<`, `%` are
  handled as informational steps.

## Case/toggle opcodes

| Opcode | Arity | Description | Hashcat source reference |
|--------|-------|-------------|--------------------------|
| `S` | 0 | Keyboard shift transformation (US layout) | `RULE_OP_MANGLE_SHIFT_CASE` |
| `h` | 0 | Convert word to lowercase hex encoding | `RULE_OP_MANGLE_TO_HEX_LOWER` |
| `H` | 0 | Convert word to uppercase hex encoding | `RULE_OP_MANGLE_TO_HEX_UPPER` |

### Implementation notes

- `S` is **not** the same as `t`. It uses a `cshift_lookup` table (256-byte array) that
  mimics pressing the Shift key on a US keyboard. This transforms both alphabetic characters
  (case toggle) **and** non-alpha characters to their shifted equivalents (e.g., `1` -> `!`,
  `2` -> `@`, `[` -> `{`, `;` -> `:`). Requires extracting the full lookup table from hashcat
  source to implement correctly.
- `h` converts each byte of the word to its two-digit lowercase hex representation.
  Example: `password` -> `70617373776f7264`. This doubles the word length.
- `H` is the same as `h` but uses uppercase hex digits.
  Example: `password` -> `70617373776F7264`.
- `h` and `H` are hashcat-only extensions (not from JtR/hashcat-legacy).

## Separator-based opcodes

| Opcode | Arity | Description | Hashcat source reference |
|--------|-------|-------------|--------------------------|
| `e` | 1 | Title case using char X as separator | `RULE_OP_MANGLE_TITLE_SEP` |
| `3` | 2 | Toggle case of char after Nth occurrence of separator X | `RULE_OP_MANGLE_TOGGLE_AT_SEP` |

### Implementation notes

- `eX`: lowercase everything, then uppercase the first char and every char immediately after X.
- `3NX`: toggle the case of the character immediately after the Nth occurrence (0-based) of
  separator character X. This is a single toggle, not all occurrences.

## Hashcat-legacy-only opcodes

These opcodes existed in hashcat-legacy but were reassigned to different characters in modern
hashcat. If encountered, they should be flagged as legacy-only and will produce syntax errors
in modern hashcat. Their modern equivalents are already implemented.

| Legacy opcode | Legacy behavior | Modern equivalent |
|---------------|----------------|-------------------|
| `m` | Append memory buffer | `4` |
| `w` | Duplicate first N chars (prepend copy) | `y` (`RULE_OP_MANGLE_DUPEBLOCK_FIRST`) |
| `W` | Duplicate last N chars (append copy) | `Y` (`RULE_OP_MANGLE_DUPEBLOCK_LAST`) |
| `5` | Duplicate first char N times | `z` (`RULE_OP_MANGLE_DUPECHAR_FIRST`) |
| `7` | Duplicate last char N times | `Z` (`RULE_OP_MANGLE_DUPECHAR_LAST`) |
| `9` | Duplicate every character in place | `q` (`RULE_OP_MANGLE_DUPECHAR_ALL`) |

## Other

| Opcode | Arity | Description | Hashcat source reference |
|--------|-------|-------------|--------------------------|
| `B` | 2 | Byte-wise add value to character at position | `RULE_OP_MANGLE_CHR_ADD` |
| `v` | 2 | Insert char X every N characters | `RULE_OP_MANGLE_INSERT_EVERY` |
| `a` | 0 | No-op (unimplemented in hashcat itself) | `RULE_OP_MANGLE_TOGGLECASE_REC` |

### Implementation notes

- `B` adds a numeric value to the byte at a given position. Not a memory opcode as previously
  documented.
- `vNX`: inserts character X every N characters. Example: `v3!` on `password` -> `pas!swo!rd`.
- `a` is defined as `RULE_OP_MANGLE_TOGGLECASE_REC` in hashcat source but the implementation
  is an explicit `/* todo */ break;` stub. It is a no-op in practice.

---

*Generated from analysis of 1000 random rules (seed 42) via `generate-rules.bin`.
Corrected against hashcat source (`OpenCL/inc_rp_common.h`, `OpenCL/inc_rp.cl`, `src/rp_cpu.c`)
and hashcat-legacy source (`include/rp.h`) on 2026-02-19.*
