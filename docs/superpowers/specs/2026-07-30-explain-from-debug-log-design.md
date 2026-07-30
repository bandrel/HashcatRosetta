# Explain rules straight from a debug log

Date: 2026-07-30
Status: approved

## Problem

`--explain` and debug-file analysis are two disconnected halves of the tool.
`--rules` tells you *which* rules dominate a cracking session but not what they
do; `--explain` tells you what a rule does but only if you copy the rule string
out of the listing and re-run the tool by hand. For a session with a few dozen
interesting rules that is a lot of copy-paste, and the baseword you pass to
`--explain` is a guess (`password` by default) rather than a word the rule was
actually applied to.

## Goal

Let `--explain` decorate debug-file listings, using real basewords from the log
and cross-checking the simulation against the candidate hashcat actually
produced.

## CLI surface

`--explain` becomes an option with an optional value (Click:
`is_flag=False, flag_value=<sentinel>, default=None`).

| Invocation | Behavior |
| --- | --- |
| `--explain "c$1"` | Unchanged: explain one rule against `--baseword`. |
| `--explain rules.txt` | Unchanged: explain every rule in a rule file. |
| `debug.txt --rules --explain` | New: explain each top rule from the log. |
| `debug.txt --basewords --explain` | New: explain each rule applied to each top baseword. |
| `debug.txt --explain` | New: same as `--rules --explain`. |
| `--explain` with no FILE | Error: `--explain needs a rule, a rule file, or a debug file argument`. |

The sentinel is a module constant containing a NUL byte, so no real rule string
or file path can collide with it.

Combining `--explain` with `--analyze-rules` is an error (`--analyze-rules`
reads a rule file, not a debug log). `--explain` alongside `--export` explains
to stdout and still writes the export; explanations are display-only and never
enter the exported report.

`--baseword` is ignored in debug-log mode — the whole point is that basewords
come from the log. Passing both prints a one-line note to stderr.

## Output shape

For `--rules`, each listed rule keeps its existing line and gains an indented
block:

```
Top 3 Rules by Frequency
--------------------------------------
 1. Rule: $1                   (412)
      baseword 'summer' (from log)
        $1: Append '1' → summer → summer1
      hashcat produced: summer1  [match]
```

For `--basewords`, each listed baseword gains a block per rule applied to it,
capped at `--top` rules per baseword so a hot baseword cannot flood the screen.
When the cap truncates, print `... and N more rules` — no silent truncation.

Representative baseword selection for `--rules`: the first entry in
`DebugAnalyzer.entries` whose rule matches. First-seen keeps output stable
across runs (`rule_stats["basewords"]` is a `set`, so it is not ordered) and
pairs the baseword with the exact candidate hashcat emitted for it.

## Match checking

Each block compares the simulated final word to the logged candidate:

- equal → `[match]`
- different → `[MISMATCH]`
- either side contains a non-ASCII character → `[unverified: non-ASCII]`

The non-ASCII carve-out exists because `DebugLogParser` reads debug files as
`utf-8` with `errors="ignore"`, while `explain_rule` models the word as one code
point per byte. For high-byte data the two representations legitimately differ,
so a mismatch marker there would be noise, not a finding. Fixing the parser's
encoding is out of scope for this change.

When `explain_rule` returns `None` (no explanation available — unsupported
opcode, or a filter opcode that rejected the word), print
`[!] no explanation available` followed by the logged candidate. A logged entry
means hashcat did *not* reject the word, so this is a real gap worth surfacing.

## Accurate final word

`_verify._extract_final` recovers the final word by string-parsing the last step
(`"<op>: <desc> → <prev> → <current>"`). Steps that carry no arrow break it: a
rule ending in `M` produces `"M: Memorize current word 'x'"`, and the parse
returns that whole sentence as the "final word". In the new feature that would
render as a guaranteed false `[MISMATCH]`.

Fix at the source: extract the simulation loop in `cli.py` into
`_simulate_rule(rule_str, baseword) -> tuple[list[str], str] | None` returning
`(steps, final_word)`. `explain_rule` becomes a thin wrapper returning only
`steps`, so its signature and every existing caller are unchanged. The new
debug-log path calls `_simulate_rule` and gets the final word directly.

`_verify` switches to `_simulate_rule` for its final word as well, removing the
string-parse. That is a behavior change in the verification harness, so the
per-opcode sweep (`scripts/sweep_opcodes.py`) is the gate: it must show no new
mismatches outside `KNOWN_LATENT`.

## Testing

- `_simulate_rule` returns the same steps as `explain_rule` for a sample of
  rules, and returns the true final word for a rule ending in `M` (regression
  for the arrow-parse bug).
- Click parses bare `--explain` before another flag (`--explain --rules`) as the
  sentinel, and `--explain c$1` as the rule string.
- `--explain` with no FILE and no value exits non-zero with the error message.
- `--explain` with `--analyze-rules` exits non-zero.
- On a fixture debug log: `--rules --explain` prints a step line and `[match]`
  for a rule the simulator handles; `--basewords --explain` prints per-rule
  blocks; the per-baseword cap prints `... and N more rules`.
- A fixture whose logged candidate disagrees with the simulation renders
  `[MISMATCH]`; a fixture with a non-ASCII candidate renders
  `[unverified: non-ASCII]`.
- `--explain` with `--export` still writes the export file, and the exported
  JSON contains no explanation keys.

## Out of scope

- Changing `DebugLogParser`'s `utf-8`/`errors="ignore"` read.
- Explanations in the default no-flag summary or in `--wordlists`.
- Putting explanations into `--export` output.
