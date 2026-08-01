# Task 7d Report: X mutates the memory buffer as a side effect

## Status: DONE

## Step 0: Investigation — does the full 256-byte physical buffer matter?

**Initial (wrong) hypothesis.** I first tried to prove analytically that a
same-logical-length buffer (sized to `mem_len`, never touching bytes beyond
it) was sufficient, by tracing `mangle_insert_multi`'s three C lines position
by position. I initially convinced myself the read in the final `memcpy`
(`memcpy(arr+arr_pos, arr2, arr_len-arr_pos+arr2_cpy)`) could read past
`mem_len` (real hashcat's `mem` is a 256-byte buffer, so this read is valid
there), which looked like a hard requirement for a full 256-byte model.

**Re-derivation.** Working through the algebra more carefully: the region
`arr2` reads in that final memcpy (`[0, arr_len-arr_pos+arr2_cpy)`) is
*always* exactly the union of what the previous two lines *just wrote*
(the `memmove`'s shifted region `[0, m)` = `old_mem[n:n+m]`, and the
`memcpy`'s spliced region `[m, m+write_len)` = `current[l_pos:]`, where
`write_len = arr_len-arr_pos` by construction). That means the final
"substring" being inserted into `current` is always exactly
`old_mem[n:n+m] + current[l_pos:]` truncated to length
`arr_len-arr_pos+arr2_cpy` — which collapses to the *original*, pre-existing
`substring = memorized[n:n+m]` formula already in `cli.py`, concatenated at
`l_pos`. In other words: **the current-word transformation was never
broken** (single `X` already passed all tests); only the *residual state of
`memorized`* for the *next* op was wrong.

For that residual state, I derived the three-way piecewise update for each
position `p` in `[0, mem_len)`:
- `m <= p < m+write_len` → splice in `current[l_pos + (p-m)]` (current's tail)
- else if `p < mem_len - n` → shift in from `old_mem[n+p]`
- else → unchanged

This only ever reads `old_mem` positions `< mem_len` (never beyond), so no
256-byte buffer is needed to *compute* it. A concrete example: `M X118 X014`
on `abcdefgh` with n=1, m=1, write_len=0 (empty tail) shows position 0 of
the result: since `0 < mem_len - 1 = 7`, it reads `old_mem[1]` = 'b', giving
the residual `'b...'` not `'a...'` — confirming that the shift-in is not
gated by `p < m` but by `p < mem_len - n`.

**Empirical stress test.** To confirm the derivation rather than trust it
blindly, I implemented both the derived same-length formula and a
deliberately-buggy naive 256-slice prototype in a throwaway Python script,
and ran a batch of adversarial cases against real hashcat 7.1.2
(`hashcat --stdout -a0 -j '<rule>' <file>`), specifically designed to force
writes past the logical `mem_len` within a single `X` call (e.g. `X020` /
`X010 X010` on a 5-char baseword, `X334 X444` on "password" — this second
one is the exact ground-truth case from the brief where `arr_len-arr_pos+m`
reaches 11 against `mem_len=8`). All of the following matched hashcat
exactly with the same-length model:

```
X020 on abcde                    -> \x00\x00abcde
X010 X010 on abcde               -> \x00\x00abcde
X010 X010 X010 on abcde          -> \x00\x00\x00abcde
X012 X012 on abc                 -> ab\x00\x00c
X024 X024 on abcde               -> abcd\x00\x00\x00\x00e
X013 X023 on abcd                -> abc\x00d\x00d
X002 X102 on abc                 -> None (rejected)
X014 X014 X014 on abcde          -> abcd\x00\x00\x00e
MX014 X014 on abcd               -> abcda a -> abcdaa
X011 X011 X011 on ab             -> a\x00\x00\x00b
X034 X014 on abcdefgh            -> abcd\x00\x00\x00\x00efgh
X044 X004 on abcdefgh            -> None (rejected)
X334 X444 on password            -> passord\x00\x00\x00\x00word
```

Plus the four brief-verified ground-truth cases (`X011`, `X011 X011`,
`X011 X021`, `X334 X444`) all matched.

**Finding: the same-logical-length model is sufficient.** A full 256-byte
physical buffer is *not* needed. The reason the brief's concern ("a case
where `arr2_cpy` plus the copied region would exceed the logical `mem_len`
but still fit inside the real 256-byte buffer could behave differently")
does not materialize is that hashcat's own final read in `X` is always
exactly bounded by what was *just written* in the same call — never by
stale bytes sitting further out in the 256-byte buffer. I did not find any
constructible case where the two models diverge.

## Step 1–2: Failing tests

Appended `TestChainedXMemoryMutation` to `tests/test_missing_opcodes.py`
verbatim from the brief. Ran `uv run pytest tests/test_missing_opcodes.py -v -k ChainedX`:
2 of 4 failed as predicted (`X011` alone passed — Task 7b's model was
already correct for a lone `X`; the two chained cases with distinguishable
mutation, `X011 X021` and `X334 X444`, failed).

## Step 3: Implementation

Modified only the `X` branch in `hashcat_rosetta/cli.py` (the `M`, `4`, `6`,
`Q` branches needed **no code changes** — see below for why). After
computing `current` exactly as before (the substring-insert formula was
never wrong), added a mutation of `memorized` using the same-length
piecewise formula:

```python
mem_len = len(memorized)
shifted = memorized[n:mem_len]
new_mem = list(shifted) + list(memorized[len(shifted):])
tail = prev[l_pos:]
write_end = min(m + len(tail), mem_len)
write_n = max(0, write_end - m)
new_mem[m : m + write_n] = list(tail[:write_n])
memorized = "".join(new_mem)
```

This keeps `memorized` a plain string of unchanged length `mem_len` (X never
changes `mem_len`, only `M` does, matching hashcat's C: `mem_len` is only
reassigned by `RULE_OP_MEMORIZE_WORD`).

**Why `M`, `4`, `6`, `Q` needed no changes:** `M` already does
`memorized = current` (a fresh full-length reset, matching hashcat's
`memcpy(mem, out, out_len); mem_len = out_len;`). `4`/`6`/`Q` already just
read the `memorized` variable directly (`current + memorized`,
`memorized + current`, `current == memorized`) — since `memorized` is a
single Python variable reassigned in-place by the fixed `X` branch (not a
separate cache), every later read of `memorized` automatically observes
whatever the most recent `X` mutation produced. No separate representation
change (e.g. adding a `mem_len` register distinct from `len(memorized)`) was
necessary because the model keeps `len(memorized) == mem_len` as an
invariant at all times.

## Step 4: Tests pass

`uv run pytest tests/test_missing_opcodes.py -v` — **30 passed**, 0 failed
(all four `TestChainedXMemoryMutation` cases, plus all pre-existing memory
opcode tests: `TestMemoryOpcodes`, `TestMemoryInitialization`,
`TestMFormatAndXBounds`, etc.).

## Step 5: Confirmation gates

**Opcode sweep:**
```
uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task7d.md
```
Output:
```
Opcode sweep: 253 rules x 24 basewords (16 workers)...
Summary: pass=60 regression=0 latent=0 unverifiable=0 untracked=0
RESULT: PASS
EXIT:0
```
`X` row in the report: `| X | 207 | 207 | 0 | 0 | — | PASS |` — unchanged
from before, no regression (the sweep's single-opcode-per-rule design
doesn't exercise chaining, as expected).

**Full integration test (the real acceptance gate):**
```
uv run pytest tests/test_rule_matrix.py::TestGenerateRulesIntegration::test_hashcat_vs_explain -v
```
Output:
```
tests/test_rule_matrix.py::TestGenerateRulesIntegration::test_hashcat_vs_explain PASSED [100%]
1 passed in 1153.31s (0:19:13)
```
**Mismatch count: 0/6573, down from the pre-existing 6/6573.** This is the
exact test that originally surfaced the bug and is this task's acceptance
gate — it now passes cleanly.

**Full test suite** (extra verification beyond the brief's required steps):
```
uv run pytest -q
```
Output: `825 passed in 321.96s (0:05:21)` — no regressions anywhere else in
the suite.

## Commit

```
git add hashcat_rosetta/cli.py tests/test_missing_opcodes.py
git commit -m "fix: X mutates the memory buffer, not just the current word ..."
```
Pre-commit hooks (ruff, ruff format, mypy, pytest) all passed. Commit hash:
**`5dbd456`**.

Note: there was a pre-existing unrelated unstaged modification to
`docs/superpowers/plans/2026-07-31-oracle-every-opcode.md` in the worktree
when I started (not made by me during this task). Per the brief's exact
`git add` list, I did not stage or commit that file — it remains unstaged,
exactly as I found it.

## Deviations from the brief

None. Followed Step 0 through Step 6 as written, including using the exact
commit message provided. The only addition beyond the brief's explicit
steps was running the full `uv run pytest -q` suite as a final sanity check
(825 passed), which is not itself part of the brief's Step 5 gates but adds
confidence that the `X`-branch change didn't regress anything else in the
codebase.

## Fix Round 1: Correct documentation and test placement

A reviewer independently verified the shipped code against 880 randomized
test cases against real hashcat and confirmed it was fully correct (zero
mismatches). However, the reviewer identified two issues:

**Documentation fix:** The written derivation in Step 0 incorrectly stated
a two-way split for the residual memory buffer update, when the actual
code (and hashcat) implement a three-way split. The piecewise formula should
be:
- `m <= p < m+write_len` → splice from current's tail
- else if `p < mem_len - n` → shift in from `old_mem[n+p]`
- else → unchanged (only for `p >= mem_len - n` and `p < m`)

The reviewer's counterexample `M X118 X014` on `abcdefgh` demonstrated the
error: position 0 becomes 'b' (shifted in from `old_mem[1]`), not 'a',
confirming the shift-in is gated by `p < mem_len - n`, not `p < m`.

**Test structure fix:** `TestChainedXMemoryMutation` was inadvertently
inserted inside `TestNoOpOpcode` during implementation, which orphaned
`test_a_still_emits_a_step` into the wrong class. The method was moved
back to `TestNoOpOpcode` where it belongs, restoring proper class
boundaries.

All 30 tests in `test_missing_opcodes.py` pass after both fixes.

Commit: **`ede5718`**
