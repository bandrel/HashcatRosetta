# BARRAGE Sweep Report

**Generated:** 2026-08-01
**Command:** `uv run python scripts/verify_rules.py --count 500 --rounds 1 --seed 1 --basewords tests/data/basewords.json --workers 16 --report reports/barrage-opcode-report.json`

## Methodology note

Task 9 of the `oracle-every-opcode` plan called for re-running "the full BARRAGE
sweep" against `~/projects/hashcat/rules/BARRAGE.rule` (32,467,620 lines,
31,421,168 unique) via `scripts/verify_rules.py --rules <file> --json <file>`.
That invocation does not exist: `scripts/verify_rules.py` has never accepted a
`--rules` flag (confirmed back to the `v0.4.0` tag, `f92c099`) — it always
generates rules itself via `generate-rules.bin` and compares them against a
baseword corpus. There is also no other committed tool that feeds a real rule
file into the oracle harness one rule at a time; `_verify.py`'s oracle calls
shell out to `hashcat` once per rule, so a literal 32.4M-line, live-oracle
sweep is computationally infeasible in this environment (benchmarked at
~0.157s/invocation serially; even fully parallel across 16 cores that is
multiple days for 31.4M unique rules).

A batch/bulk oracle shortcut (loading all predicted candidates as target
hashes and cracking them in one `hashcat -m0` run) was prototyped and rejected:
hashcat stops trying further candidates against a digest once it is cracked,
so when two different rule strings legitimately produce the same candidate
(common in BARRAGE — a plain-Python classification pass over the 31.4M unique
lines found roughly 15M such candidate collisions), only the first-encountered
rule for a shared candidate would actually be verified, silently understating
coverage.

Given that, this report instead re-runs the project's actual, existing,
fully-oracle-verified accuracy tooling (`scripts/verify_rules.py` and
`scripts/sweep_opcodes.py`) at a larger-than-CI-default scale. Every rule
counted below was genuinely compared against a live `hashcat` process (GPU
`-r` engine or CPU `-j` engine, routed per opcode) — there is no shortcut or
simulation in this number itself, only in the scope (synthetic generated
rules across the standard 24-baseword corpus, rather than the literal
BARRAGE.rule file).

See `task-9-report.md` for the full accounting, including the historical
32.4M-rule figure this could not exactly reproduce.

## Results

Real hashcat oracle (`hashcat --stdout`, GPU `-r` / CPU `-j`, routed per
opcode), 500 randomly-generated rules x 24 basewords (`tests/data/basewords.json`),
seed 1:

| Metric | Count |
|---|---|
| Total rule x baseword pairs | 12,000 |
| Skipped (unimplemented opcode) | 0 |
| Skipped (hashcat process failure/timeout) | 2 |
| Skipped (hashcat-unsupported: OOB position, truncated opcode, invalid position arg, empty baseword) | 4,304 |
| Skipped (non-ASCII hashcat output) | 149 |
| **Oracle-tested** | **7,545** |
| **Matched** | **7,545** |
| **Mismatches** | **0** |

Per-opcode systematic sweep (`scripts/sweep_opcodes.py`), 253 canonical-arg-grid
rules x 24 basewords: `pass=60 regression=0 latent=0 unverifiable=0
untracked=0` — every opcode has real oracle coverage and no opcode regressed.

**RESULT: PASS** on both. Zero mismatches, zero opcodes without oracle
coverage.
