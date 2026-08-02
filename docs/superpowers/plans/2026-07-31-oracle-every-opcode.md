# Oracle Every Opcode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put every hashcat rule opcode under an automated oracle, so no opcode is simulated on documentation alone.

**Architecture:** Today the harness has exactly one oracle, `hashcat --stdout -a0 -r <file>`, which is the GPU rule engine. Thirteen opcodes are categorically invalid in `-r` rule files, so they are skipped rather than compared, and **five real bugs have been hiding in that blind spot, two of them in code that shipped in 0.4.0 marked as implemented.** This plan adds a second oracle, `hashcat --stdout -a0 -j <rule>`, which is the CPU rule engine (`src/rp_cpu.c`) and does accept those thirteen. Each opcode is then routed to whichever engine actually implements it. The two engines are never treated as interchangeable, because they demonstrably disagree on at least one opcode. A coverage gate then makes "simulated but never compared" a build failure.

**Tech Stack:** Python 3.10+, pytest, `uv`, hashcat v7.1.2+ binary, hashcat-utils `generate-rules.bin`.

## Global Constraints

- hashcat binary must be v7.1.2 or newer. Verified against `v7.1.2-386-g8000b3e60`.
- Never use `-j` output as the oracle for an opcode that `-r` accepts. See "The 3NX divergence" below. Crossing them silently changes what "correct" means.
- Every entry added to `KNOWN_LATENT` must cite a tracked issue. No bare `# TODO`. This is an existing repo rule in `scripts/sweep_opcodes.py:81`.
- No opcode may be dropped from an `explain_rule()` result without the returned step list saying so. Silent skipping is the root cause of the bugs below.
- Existing public API shapes stay put: `VerifyResult`, `CorpusReport`, and the round-dict format that `scripts/verify_rules.py` renders.

---

## Findings this plan is built on

All of the following were verified empirically against `v7.1.2-386-g8000b3e60`, not read from documentation.

**1. Filter and memory opcodes are invalid in `-r` rule files, in every mode.** Not just under `--stdout`. A real attack rejects them too:

```
$ hashcat -m 0 -a 0 -r <(echo '$1')    ph.txt pw.txt   # control
CRACKED
$ hashcat -m 0 -a 0 -r <(echo '>4 $1') ph.txt pw.txt
No valid rules left.
```

This affects `M X ! < > % ( ) =` (currently in `_HASHCAT_STDOUT_UNSUPPORTED`, `_verify.py:96`), `4 6 Q` (not implemented at all), and `a`. Thirteen opcodes total. The existing code comment at `_verify.py:89-93` explains the exclusion as "`--stdout` only emits *modified* candidates," but the real cause is rule compilation failure, which is why adding a transform to the rule does not rescue it: `>4 $1` fails identically to `>4`.

**2. `-j` accepts all thirteen and distinguishes pass from reject cleanly.** A passing filter emits the unmodified word; a rejecting filter emits nothing:

```
$ printf 'ab\nabcd\nabcdef\nabcdefgh\n' > lens.txt
$ hashcat --stdout -a0 -j '>4' lens.txt
abcd
abcdef
abcdefgh
```

**3. The 3NX divergence. hashcat's CPU and GPU engines disagree with each other.** Across 43 transform opcodes tested both ways, 42 agree and one does not:

| | `30s` on `Password1` |
|---|---|
| `-r` (GPU) | `PasSword1` |
| `-j` (CPU) | `PassWord1` |
| `explain_rule()` | `PasSword1` |

The simulator matches the GPU, which is correct for rule files. This is the reason the two oracles must stay separated by opcode rather than merged.

**4. Five confirmed bugs, all inside the never-compared set.** This is the evidence that the blind spot is not theoretical. Findings 4 through 6 below cover the first three; findings 8 and 10 cover the two in shipped code.

`>` and `<` are inverted, in both the description and the logic. hashcat's `>N` rejects plains *shorter* than N; `<N` rejects plains *longer* than N. `formatting.py:64-65` and `cli.py:330,345` have both backwards:

| Rule | Baseword | hashcat | `explain_rule()` |
|---|---|---|---|
| `>4` | `ab` (len 2) | reject | "Length 2 <= 4 (filter passed)" |
| `>4` | `abcdefgh` (len 8) | keep | rejects (reported as "Unknown rule") |
| `<4` | `abcdefgh` (len 8) | reject | "Length 8 >= 4 (filter passed)" |
| `<4` | `ab` (len 2) | keep | rejects (reported as "Unknown rule") |

`%` has the wrong arity. hashcat's `%` is two-arg, `%NX`, "reject unless the word contains char X at least N times." It is classified one-arg in `_verify.py:81`, `parser.py:441`, and implemented one-arg at `cli.py:432`. Ground truth on `password`: `%1s` keep, `%2s` keep (two s's), `%3s` reject. `explain_rule('%2s')` returns "Unknown rule" for all three because it tests `'2' in current`. Because the arity is also wrong in the tokenizer, every rule containing `%` mis-tokenizes from that point on, which additionally corrupts `--analyze-rules` opcode statistics for any rule file containing `%`.

**5. Six opcodes are not implemented at all:** `S h H 4 6 Q`. Tracked as issue #37. `S`, `h`, `H` are oracle-comparable via `-r` today. `4`, `6`, `Q` need the `-j` oracle from this plan.

**6. Two opcodes are exempted from CI:** `B` and `v`, via `KNOWN_LATENT` in `scripts/sweep_opcodes.py:82-96`. They are verified on local Apple OpenCL but produce no output on CI's Linux/POCL backend. This plan does not fix that (it is an oracle-environment problem, not a correctness problem) but Task 8 makes the exemption visible in the coverage report instead of implicit.

**7. `_hashcat_output` misinterprets exit 255.** The docstring at `_verify.py:375-379` says exit 255 means "the filter rule rejected all candidates," and returns `("", False)`. Exit 255 is actually "No valid rules left," a compilation failure. Today this is harmless because those opcodes are skipped upstream. Task 2 changes the skip list, so Task 1 must fix this first or invalid rules will silently read as clean rejections.

**8. A fourth bug: `a` is simulated as append-memorized, but hashcat's `a` is a no-op.** `cli.py:525-529` does `current = _cap(prev, current + memorized)`, and its comment claims this matches "CPU-mode behavior." It does not. `a` is also CPU-only, and on the CPU engine it changes nothing:

```
$ hashcat --stdout -a0 -j 'a'  <(echo abc)   ->  abc
$ hashcat --stdout -a0 -j 'ca' <(echo abc)   ->  Abc     # the c applied, the a did not
$ hashcat --stdout -a0 -r <(echo 'a') ...    ->  No valid rules left.
$ hashcat-rosetta --explain 'a' --baseword abc  ->  abcabc
```

`docs/unimplemented-opcodes.md:107,114-115` has this right: hashcat declares `RULE_OP_MANGLE_TOGGLECASE_REC` but its body is a `/* todo */ break;` stub. The code is what is wrong. Task 7a fixes it. `a` therefore belongs in `_CPU_ONLY_OPCODES`, not in `KNOWN_LATENT`: it is fully oracle-comparable via `-j`, and the correct expected value is "unchanged."

**9. The two arity tables disagree with each other, and `_ALL_KNOWN_OPCODES` is the real gate.** `parser.py:437` lists no-arg ops as `":lucCtdfr{}[]kKqEMmSwWhH4579a"` while `_verify.py:82` has `":culdrt[]{}fkKqCEMa"`. The verify table omits `S h H 4` (and the legacy `m w W 5 7 9`), so `_ALL_KNOWN_OPCODES` omits them too, and `verify_rule` skips any rule containing them via the `op not in _ALL_KNOWN_OPCODES` test at `_verify.py:472`.

**Consequence for Tasks 5 through 7: adding an opcode to `_DEFAULT_IMPLEMENTED` is not enough to get it oracled.** It must also be in the right arity set so it lands in `_ALL_KNOWN_OPCODES`. Every implementation task below does both.

**10. A fifth bug, in already-shipped code: the memory buffer starts zero-filled, not seeded with the baseword.** `cli.py:148` does `memorized = baseword`. hashcat zero-fills the buffer to the plain's length instead, so any memory op used without a preceding `M` reads NUL bytes:

```
$ hashcat --stdout -a0 -j '4' <(echo abc)     | od -c   ->  a b c \0 \0 \0
$ hashcat --stdout -a0 -j '6' <(echo abc)     | od -c   ->  \0 \0 \0 a b c
$ hashcat --stdout -a0 -j '4' <(echo abcdef)  | od -c   ->  a b c d e f \0 \0 \0 \0 \0 \0
$ hashcat --stdout -a0 -j 'X012' <(echo abc)  | od -c   ->  a b \0 c
```

It is deterministic, not random: the buffer is always `len(word)` NUL bytes. Once `M` has run, everything agrees, and `MX012` gives `abac` from both. But bare `X012` gives `ab\0c` from hashcat and `abac` from `explain_rule()`, so **`X` has been wrong since it shipped in 0.4.0** for any rule that uses it without `M` first. Task 7b fixes the initialization. This one is the strongest argument for the whole plan: `M` and `X` were implemented, marked as implemented, and never once compared against hashcat.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `hashcat_rosetta/_verify.py` | Oracle invocation, opcode arity tables, skip logic | Modify: add CPU oracle, add `_CPU_ONLY_OPCODES`, fix `%` arity, fix exit-255 handling, route per opcode |
| `hashcat_rosetta/cli.py` | `explain_rule()` simulator | Modify: fix `<`/`>`/`%`, implement `S h H 4 6 Q` |
| `hashcat_rosetta/formatting.py` | Opcode descriptions | Modify: fix `<`/`>`/`%` text |
| `hashcat_rosetta/parser.py` | Tokenizer arity | Modify: `%` to two-arg |
| `scripts/sweep_opcodes.py` | Per-opcode sweep and coverage gate | Modify: cover all opcodes, fail on any unoracled opcode |
| `tests/test_oracle_routing.py` | Oracle selection unit tests | Create |
| `tests/test_filter_opcodes.py` | `< > % ! ( ) =` behavior tests | Create |
| `tests/test_missing_opcodes.py` | `S h H 4 6 Q` behavior tests | Create |
| `docs/unimplemented-opcodes.md` | Running list of gaps | Modify: rewrite to match reality |

Tasks 3 through 7 each touch `cli.py` and are ordered so no two tasks edit the same function. Run them serially, not in parallel.

---

### Task 1: CPU oracle via `-j`

**Files:**
- Modify: `hashcat_rosetta/_verify.py:372-425` (`_hashcat_output`)
- Test: `tests/test_oracle_routing.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `_hashcat_output(rule: str, baseword: str, engine: str = "gpu") -> tuple[str | None, bool]`. `engine` is `"gpu"` (uses `-r`) or `"cpu"` (uses `-j`). Return contract is unchanged: `(stdout_or_None, hashcat_failed)`. A new third state matters: for `engine="cpu"`, empty stdout with exit 0 means the filter rejected the candidate, which is a real answer and not a failure.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oracle_routing.py
import pytest
from hashcat_rosetta._verify import _hashcat_output

pytestmark = pytest.mark.integration


def test_cpu_engine_runs_filter_rule_that_gpu_rejects():
    """-j accepts '>4', which -r refuses to compile at all."""
    gpu_out, gpu_failed = _hashcat_output(">4", "abcdefgh", engine="gpu")
    cpu_out, cpu_failed = _hashcat_output(">4", "abcdefgh", engine="cpu")
    assert gpu_out is None or gpu_out == "", "GPU cannot compile filter rules"
    assert cpu_failed is False
    assert cpu_out == "abcdefgh", "len 8 >= 4 passes, word emitted unmodified"


def test_cpu_engine_reports_rejection_as_empty_string():
    cpu_out, cpu_failed = _hashcat_output(">4", "ab", engine="cpu")
    assert cpu_failed is False
    assert cpu_out == "", "len 2 < 4 is rejected by hashcat"


def test_invalid_rule_is_a_failure_not_a_clean_rejection():
    """Exit 255 is 'No valid rules left', a compile error, not a rejection."""
    out, failed = _hashcat_output(">4", "abcdefgh", engine="gpu")
    assert failed is True, "an uncompilable rule must not read as empty output"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_oracle_routing.py -v`
Expected: FAIL. `_hashcat_output() got an unexpected keyword argument 'engine'`.

- [ ] **Step 3: Implement the engine parameter**

In `hashcat_rosetta/_verify.py`, replace the `_hashcat_output` signature and the subprocess construction. Keep the tempfile path only for the GPU branch; `-j` takes the rule as an argument, so the CPU branch needs no file.

```python
def _hashcat_output(
    rule: str, baseword: str, engine: str = "gpu"
) -> tuple[str | None, bool]:
    """Run a rule through hashcat. Returns (stdout-or-None, hashcat_failed).

    engine="gpu" uses `-r <file>`, the OpenCL/Metal rule engine. This is the
    authoritative semantics for rule files and the default.

    engine="cpu" uses `-j <rule>`, the host-side engine in src/rp_cpu.c. It is
    the only engine that accepts filter and memory opcodes, which hashcat
    refuses to compile into a `-r` rule file in any mode. Under `-j` a passing
    filter emits the unmodified word and a rejecting filter emits nothing, so
    "" is a real answer here rather than a failure.

    The two engines are not interchangeable: they disagree on `3NX`. Route by
    opcode via _CPU_ONLY_OPCODES; never substitute one for the other.

    hashcat_failed=True for timeout, missing binary, or any non-zero exit
    including 255. Exit 255 is "No valid rules left", a rule-compilation
    failure, not a filter rejection.
    """
    session = f"rosetta-{os.getpid()}-{abs(hash((rule, baseword, engine)))}"
    common = [
        "hashcat",
        "-a0",
        "--stdout",
        "-d1",
        "--session",
        session,
        "--potfile-disable",
        "--restore-disable",
    ]
    tmp: str | None = None
    try:
        if engine == "cpu":
            argv = common + ["-j", rule]
        else:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".rule", delete=False
            ) as f:
                f.write(rule)
                tmp = f.name
            argv = common + ["-r", tmp]
        try:
            result = subprocess.run(
                argv,
                input=baseword.encode(),
                capture_output=True,
                timeout=30,
            )
        finally:
            if tmp is not None and os.path.exists(tmp):
                os.unlink(tmp)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, True
    if result.returncode != 0:
        return None, True
    return result.stdout.decode(errors="replace").rstrip("\n"), False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_oracle_routing.py -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Confirm nothing regressed**

Run: `uv run pytest -q && uv run python scripts/verify_rules.py --count 200 --seed 1`
Expected: existing suite green; sweep reports `0 mismatches`. If the sweep now reports failures on filter opcodes, that is Task 2's job, not a regression here.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/_verify.py tests/test_oracle_routing.py
git commit -m "feat(verify): add CPU rule engine oracle via -j

hashcat refuses to compile filter and memory opcodes into -r rule files in
any mode, so they have never been oracle-compared. -j accepts them and
distinguishes filter pass from reject. Also fixes exit 255 being read as a
clean rejection when it is a compile failure."
```

---

### Task 2: Route each opcode to the engine that implements it

**Files:**
- Modify: `hashcat_rosetta/_verify.py:96` (replace `_HASHCAT_STDOUT_UNSUPPORTED`), `:441-525` (`verify_rule`)
- Test: `tests/test_oracle_routing.py`

**Interfaces:**
- Consumes: `_hashcat_output(rule, baseword, engine=...)` from Task 1.
- Produces: `_CPU_ONLY_OPCODES: set[str]` and `_select_engine(rule: str) -> str` returning `"cpu"` or `"gpu"`. `verify_rule` keeps its signature; the `skipped_hashcat_unsupported` status stays in the `VerifyStatus` union for empty basewords and out-of-bounds cases but is no longer returned merely because an opcode is a filter.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_oracle_routing.py
from hashcat_rosetta._verify import _CPU_ONLY_OPCODES, _select_engine, verify_rule


def test_cpu_only_set_is_exactly_the_thirteen():
    assert _CPU_ONLY_OPCODES == set("MX!<>%()=46Qa")


def test_select_engine_routes_by_opcode():
    assert _select_engine("$1") == "gpu"
    assert _select_engine(">4") == "cpu"
    assert _select_engine("M4") == "cpu"
    # A rule mixing a filter with a transform still needs the CPU engine,
    # because -r refuses the whole rule: '>4 $1' fails exactly like '>4'.
    assert _select_engine(">4 $1") == "cpu"


def test_filter_opcodes_are_now_compared_not_skipped():
    r = verify_rule(">4", "abcdefgh")
    assert r.status != "skipped_hashcat_unsupported"
    assert r.hashcat == "abcdefgh"


def test_3nx_still_uses_the_gpu_oracle():
    """CPU and GPU disagree on 3NX; rule-file semantics are GPU."""
    assert _select_engine("30s") == "gpu"
    r = verify_rule("30s", "Password1")
    assert r.hashcat == "PasSword1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_oracle_routing.py -v -k "cpu_only or select_engine or now_compared or 3nx"`
Expected: FAIL with `ImportError: cannot import name '_CPU_ONLY_OPCODES'`.

- [ ] **Step 3: Implement routing**

Replace `_HASHCAT_STDOUT_UNSUPPORTED` at `_verify.py:85-96` with:

```python
# Opcodes hashcat refuses to compile into a `-r` rule file, in every mode
# (verified: `hashcat -m 0 -a 0 -r <(echo '>4 $1')` returns "No valid rules
# left" in a real attack, not only under --stdout).
#   M, X, 4, 6, Q: memory operations, host-side only.
#   !, <, >, %, (, ), =: filter/reject operations, host-side only.
#   a: RULE_OP_MANGLE_TOGGLECASE_REC, a `/* todo */ break;` stub upstream.
#      Host-side only and a genuine no-op there, so "unchanged" is the
#      expected value rather than something unverifiable.
# These are reachable through `-j`/`-k`, so the CPU engine is their oracle.
# It is also their only semantics: there is no GPU implementation to differ
# from. Everything else is oracled on GPU, which is what rule files run.
_CPU_ONLY_OPCODES: set[str] = set("MX!<>%()=46Qa")


def _select_engine(rule: str) -> str:
    """Return "cpu" if any opcode in `rule` is host-side only, else "gpu".

    One CPU-only opcode taints the whole rule, because hashcat rejects the
    entire rule file rather than the individual operation.
    """
    return "cpu" if any(op in _CPU_ONLY_OPCODES for op in _extract_opcodes(rule)) else "gpu"
```

In `verify_rule`, delete the `unsupported` branch that tests `_HASHCAT_STDOUT_UNSUPPORTED` (`_verify.py:470-490`), keep the `_has_truncated_opcode` / `_has_oob_position` / `_has_invalid_position_arg` / empty-baseword skips, and pass the engine through:

```python
    engine = _select_engine(rule)
    hc_out, hc_failed = _hashcat_output(rule, baseword, engine=engine)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_oracle_routing.py -v`
Expected: PASS. `test_filter_opcodes_are_now_compared_not_skipped` will pass on the oracle side; the `<`/`>` mismatches it exposes are fixed in Task 3.

- [ ] **Step 5: Record the newly-exposed mismatches**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task2.md`
Expected: nonzero exit, with mismatches on `<`, `>`, `%`. Read the report and confirm those three and only those three are newly failing. This is the bug list Tasks 3 and 4 close.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/_verify.py tests/test_oracle_routing.py
git commit -m "feat(verify): route CPU-only opcodes to the -j oracle

Filter and memory opcodes are no longer skipped. Immediately surfaces
inverted < and > logic and wrong % arity, which the GPU-only oracle could
never have caught."
```

---

### Task 3: Fix inverted `<` and `>`

**Files:**
- Modify: `hashcat_rosetta/cli.py:330-357`, `hashcat_rosetta/formatting.py:64-65`
- Test: `tests/test_filter_opcodes.py` (create)

**Interfaces:**
- Consumes: the CPU oracle from Tasks 1 and 2.
- Produces: no new symbols. Behavior change only.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_filter_opcodes.py
import pytest
from hashcat_rosetta.cli import explain_rule


def _final(rule, word):
    """Return the final candidate, or None if the rule rejected the word."""
    steps = explain_rule(rule, word)
    return None if not steps else steps[-1].rsplit(" → ", 1)[-1]


class TestLengthFilters:
    """hashcat: >N rejects shorter than N; <N rejects longer than N.
    Both are inclusive at N. Verified against v7.1.2.
    """

    @pytest.mark.parametrize(
        "rule,word,kept",
        [
            (">4", "ab", False),        # len 2 < 4 -> reject
            (">4", "abcd", True),       # len 4 -> keep
            (">4", "abcdefgh", True),   # len 8 -> keep
            ("<4", "ab", True),         # len 2 -> keep
            ("<4", "abcd", True),       # len 4 -> keep
            ("<4", "abcdefgh", False),  # len 8 > 4 -> reject
        ],
    )
    def test_length_filter_matches_hashcat(self, rule, word, kept):
        result = _final(rule, word)
        if kept:
            assert result == word
        else:
            assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_filter_opcodes.py -v`
Expected: FAIL on all six cases, since the current logic is exactly inverted.

- [ ] **Step 3: Fix the logic**

In `cli.py`, the `>` branch currently reads `if len(current) > n: return None`. Invert both branches and correct the step text.

```python
        elif char == ">" and i + 1 < len(rule_str):
            # hashcat: reject if word length is LESS than N (inclusive keep at N)
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
            except ValueError:
                i += 1
                continue
            if len(current) < n:
                return None
            steps.append(
                f">{n_char}: Length {len(current)} >= {n} (filter passed) → {current} → {current}"
            )
            i += 2

        elif char == "<" and i + 1 < len(rule_str):
            # hashcat: reject if word length is GREATER than N (inclusive keep at N)
            n_char = rule_str[i + 1]
            try:
                n = _hashcat_pos(n_char)
            except ValueError:
                i += 1
                continue
            if len(current) > n:
                return None
            steps.append(
                f"<{n_char}: Length {len(current)} <= {n} (filter passed) → {current} → {current}"
            )
            i += 2
```

In `formatting.py`, swap lines 64-65:

```python
    ">": "Reject plains if length is less than N",
    "<": "Reject plains if length is greater than N",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_filter_opcodes.py -v`
Expected: PASS, 6 cases.

- [ ] **Step 5: Confirm against the oracle**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task3.md`
Expected: `<` and `>` no longer appear as mismatching opcodes. `%` still does.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py hashcat_rosetta/formatting.py tests/test_filter_opcodes.py
git commit -m "fix: < and > length filters were inverted

hashcat's >N rejects plains SHORTER than N and <N rejects LONGER, the
opposite of both our descriptions and our logic. explain_rule reported
'filter passed' for candidates hashcat drops and refused to explain rules
hashcat runs."
```

---

### Task 4: Fix `%` arity

**Files:**
- Modify: `hashcat_rosetta/cli.py:432-440`, `hashcat_rosetta/formatting.py:72`, `hashcat_rosetta/parser.py:441-443`, `hashcat_rosetta/_verify.py:80-81`
- Test: `tests/test_filter_opcodes.py`

**Interfaces:**
- Consumes: the CPU oracle.
- Produces: `%` becomes two-arg everywhere. `_TWO_ARG_OPCODES` gains `%`; `_ONE_ARG_OPCODES` loses it. Any code branching on arity picks this up automatically.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_filter_opcodes.py
from hashcat_rosetta.parser import RuleParser


class TestContainsCountFilter:
    """hashcat's % is %NX: reject unless word contains char X at least N times.
    Ground truth on 'password' (two s's): %1s keep, %2s keep, %3s reject.
    """

    @pytest.mark.parametrize(
        "rule,word,kept",
        [
            ("%1s", "password", True),
            ("%2s", "password", True),
            ("%3s", "password", False),
            ("%1z", "password", False),
        ],
    )
    def test_percent_matches_hashcat(self, rule, word, kept):
        result = _final(rule, word)
        assert (result == word) if kept else (result is None)

    def test_percent_consumes_two_argument_bytes(self):
        """Wrong arity shifts every later opcode by one byte, which corrupts
        --analyze-rules statistics for any file containing a %."""
        tokens = RuleParser()._tokenize_rule("%2s$1")
        assert len(tokens) == 2, f"expected ['%2s', '$1'], got {tokens}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_filter_opcodes.py -v -k percent`
Expected: FAIL. `%2s` returns None (it tests `'2' in word`), and the tokenizer yields three tokens instead of two.

- [ ] **Step 3: Fix arity in all four places**

`cli.py`, replace the `%` branch:

```python
        elif char == "%" and i + 2 < len(rule_str):
            # hashcat %NX: reject unless `current` contains X at least N times
            n_char = rule_str[i + 1]
            check_char = rule_str[i + 2]
            try:
                n = _hashcat_pos(n_char)
            except ValueError:
                i += 1
                continue
            if current.count(check_char) < n:
                return None
            steps.append(
                f"%{n_char}{check_char}: Contains '{check_char}' "
                f"{current.count(check_char)} >= {n} times (filter passed) "
                f"→ {current} → {current}"
            )
            i += 3
```

`formatting.py:72` is already correct in wording; leave the text and confirm it reads:

```python
    "%": "Reject plains which contain char X less than N times",
```

`parser.py:438-440`, move `%` from one-arg to two-arg, and update the docstring arity list at `parser.py:426-427` to match:

```python
        one_arg_ops = set("TDpyYezZ^$@!><'+-.,LR()")
        two_arg_ops = set("soi3x*=vOB%")
```

`_verify.py:80-81`, same move (and drop the duplicated `e` while here):

```python
_TWO_ARG_OPCODES: set[str] = set("soix*=vOB3%")
_ONE_ARG_OPCODES: set[str] = set("TDpyYezZ^$@!><'+-.,LR()")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_filter_opcodes.py -v`
Expected: PASS, all cases.

- [ ] **Step 5: Confirm the tokenizer fix did not shift analyze-rules output**

Run: `uv run hashcat-rosetta ~/projects/hashcat/rules/best64.rule --analyze-rules`
Expected: still `Total rules analyzed: 77`, `Total opcode tokens: 215`. best64 contains no `%`, so this is a no-change control proving the arity edit did not disturb unrelated tokenization.

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task4.md`
Expected: exit 0. Every mismatch is now either absent or in `KNOWN_LATENT` (`B`, `v`).

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py hashcat_rosetta/parser.py hashcat_rosetta/_verify.py tests/test_filter_opcodes.py
git commit -m "fix: % is %NX (two-arg), not %X

Wrong arity made explain_rule reject every % rule and, worse, mis-tokenized
every opcode after a % in analyze-rules statistics."
```

---

### Task 5: Implement `h` and `H`

**Files:**
- Modify: `hashcat_rosetta/cli.py` (add branches near the other zero-arg case ops), `hashcat_rosetta/_verify.py:82` (`_ZERO_ARG_OPCODES`) and `:101` (`_DEFAULT_IMPLEMENTED`)
- Test: `tests/test_missing_opcodes.py` (create)

**Interfaces:**
- Consumes: `_cap(prev: str, candidate: str) -> str` and `_RP_PASSWORD_SIZE` (existing, `cli.py:43-48`). `_cap` returns `prev` unchanged when `candidate` would reach the 256-byte buffer, matching hashcat's no-op-rather-than-truncate behavior. Use it for every length-expanding op.
- Produces: `h` and `H` added to both `_ZERO_ARG_OPCODES` and `_DEFAULT_IMPLEMENTED`. Both are required: the first puts them in `_ALL_KNOWN_OPCODES` so `verify_rule` stops skipping them, the second tells the harness they are simulated.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_missing_opcodes.py
import pytest
from hashcat_rosetta.cli import explain_rule


def _final(rule, word):
    steps = explain_rule(rule, word)
    return None if not steps else steps[-1].rsplit(" → ", 1)[-1]


class TestHexEncoding:
    """Verified against hashcat v7.1.2."""

    def test_h_is_lowercase_hex(self):
        assert _final("h", "password") == "70617373776f7264"

    def test_H_is_uppercase_hex(self):
        assert _final("H", "password") == "70617373776F7264"

    def test_h_operates_on_the_current_word_not_the_baseword(self):
        # hashcat: `uh` on password -> 50415353574f5244
        assert _final("uh", "password") == "50415353574f5244"

    def test_hex_respects_the_256_byte_cap(self):
        """hashcat no-ops a growing op when the result would reach 256."""
        long_word = "a" * 200
        assert _final("h", long_word) == long_word
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k Hex`
Expected: FAIL, all four. `explain_rule` returns None for `h`.

- [ ] **Step 3: Implement**

In `cli.py`, add alongside the other zero-arg operations. Reuse the existing 256-byte cap helper that `p`, `d`, `f`, `z`, `Z`, `y`, `Y`, `q`, `a`, `X`, `v` already use (grep for the cap constant; if it is a bare literal, use `256`).

```python
        elif char == "h":
            prev = current
            current = _cap(prev, current.encode("latin-1", errors="replace").hex())
            steps.append(f"h: Hex encode lowercase → {prev} → {current}")
            i += 1

        elif char == "H":
            prev = current
            current = _cap(prev, current.encode("latin-1", errors="replace").hex().upper())
            steps.append(f"H: Hex encode uppercase → {prev} → {current}")
            i += 1
```

In `_verify.py`, add `h` and `H` to `_ZERO_ARG_OPCODES` (`set(":culdrt[]{}fkKqCEMahH")`) and `"h"`, `"H"` to `_DEFAULT_IMPLEMENTED`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k Hex`
Expected: PASS, 4 tests.

- [ ] **Step 5: Verify against the oracle**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task5.md`
Expected: exit 0, and `h`/`H` now appear as covered rows rather than absent.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py hashcat_rosetta/_verify.py tests/test_missing_opcodes.py
git commit -m "feat: implement h and H hex-encoding opcodes (#37)"
```

---

### Task 6: Implement `S` keyboard shift

**Files:**
- Modify: `hashcat_rosetta/cli.py`, `hashcat_rosetta/_verify.py:82,101`
- Test: `tests/test_missing_opcodes.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `_CSHIFT_MASK_33_126: tuple[int, ...]` (94 entries, index 0 is codepoint 33) and `_shift_char(ch: str) -> str`, both module-level in `cli.py`. `S` added to `_ZERO_ARG_OPCODES` and `_DEFAULT_IMPLEMENTED`. `S` is length-preserving, so it needs no `_cap` call.

`S` is not `t`. hashcat implements it as an XOR against a 256-byte mask table (`OpenCL/inc_rp_common.cl:42`, and note the file is `.cl`, not the `.h` that `docs/unimplemented-opcodes.md:62` claims). The mask is zero outside codepoints 33 to 126, so those bytes pass through unchanged. The algorithm below was verified byte-for-byte against hashcat across all 94 printable ASCII characters.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_missing_opcodes.py
class TestKeyboardShift:
    def test_S_shifts_letters_like_case_toggle(self):
        assert _final("S", "password") == "PASSWORD"

    def test_S_also_shifts_non_alpha(self):
        """This is what makes S different from t. Verified on v7.1.2."""
        assert _final("S", "pass1;[a") == "PASS!:{A"

    def test_S_covers_all_printable_ascii(self):
        printable = "".join(chr(c) for c in range(33, 127))
        expected = (
            "1'3457\"908=<_>?)!@#$%^&*(;:,+./2"
            "abcdefghijklmnopqrstuvwxyz{|}6-~"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]`"
        )
        assert _final("S", printable) == expected

    def test_S_leaves_bytes_outside_33_126_alone(self):
        assert _final("S", "a b") == "A B"  # space (32) is unmasked
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k Shift`
Expected: FAIL, all four.

- [ ] **Step 3: Implement**

Add at module level in `cli.py`:

```python
# hashcat's cshift_lookup, transcribed from OpenCL/inc_rp_common.cl:42.
# It is an XOR mask, not a substitution map: S(c) = chr(ord(c) ^ mask[ord(c)]).
# The upstream table is 256 bytes but zero outside 33..126, so only that
# window is stored here; index 0 corresponds to codepoint 33.
_CSHIFT_MASK_33_126: tuple[int, ...] = (
    16, 5, 16, 16, 16, 17, 5, 17, 25, 18, 22, 16, 114, 16, 16, 25, 16, 114, 16, 16, 16, 104,
    17, 18, 17, 1, 1, 16, 22, 16, 16, 114, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 104, 114, 30, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 30,
)


def _shift_char(ch: str) -> str:
    """Apply hashcat's `S` keyboard-shift to one character."""
    code = ord(ch)
    if 33 <= code <= 126:
        return chr(code ^ _CSHIFT_MASK_33_126[code - 33])
    return ch
```

And the opcode branch:

```python
        elif char == "S":
            prev = current
            current = "".join(_shift_char(ch) for ch in current)
            steps.append(f"S: Keyboard shift → {prev} → {current}")
            i += 1
```

In `_verify.py`, add `S` to `_ZERO_ARG_OPCODES` and `"S"` to `_DEFAULT_IMPLEMENTED`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k Shift`
Expected: PASS, 4 tests.

- [ ] **Step 5: Verify the table against source rather than trusting the transcription**

Run:

```bash
uv run python - <<'PY'
import re
from hashcat_rosetta.cli import _CSHIFT_MASK_33_126
src = open("/Users/justinbollinger/projects/hashcat/OpenCL/inc_rp_common.cl").read()
body = re.search(r"cshift_lookup\[256\]\s*=\s*\{(.*?)\};", src, re.S).group(1)
nums = [int(x) for x in re.findall(r"\d+", re.sub(r"//[^\n]*", "", body))]
assert len(nums) == 256
assert all(v == 0 for v in nums[:33]) and all(v == 0 for v in nums[127:])
assert tuple(nums[33:127]) == _CSHIFT_MASK_33_126
print("table matches hashcat source")
PY
```

Expected: `table matches hashcat source`. A hand-transcribed 94-integer table is exactly the kind of thing that is wrong by one entry, so do not skip this.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py hashcat_rosetta/_verify.py tests/test_missing_opcodes.py
git commit -m "feat: implement S keyboard-shift opcode (#37)

XOR against hashcat's cshift_lookup mask, transcribed from
OpenCL/inc_rp_common.cl and verified across all printable ASCII."
```

---

### Task 7: Implement `4`, `6`, and `Q`

**Files:**
- Modify: `hashcat_rosetta/cli.py` (memory branches, near existing `M` at `:534` and `X` at `:539`), `hashcat_rosetta/_verify.py:82,101`
- Test: `tests/test_missing_opcodes.py`

**Interfaces:**
- Consumes: the CPU oracle from Tasks 1 and 2, `_cap`, and the existing memory buffer variable, which is named `memorized` and is **initialized to `baseword`, not to the empty string** (`cli.py:148`). Every expected value below follows from that default, so do not assume an empty buffer.
- Produces: `4`, `6`, `Q` added to `_ZERO_ARG_OPCODES` and `_DEFAULT_IMPLEMENTED`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_missing_opcodes.py
class TestMemoryOpcodes:
    """Memory ops are host-side only; oracle is `hashcat -j`.
    Every expected value below was read off hashcat v7.1.2, not reasoned out.
    """

    def test_4_appends_memory(self):
        assert _final("M4", "abc") == "abcabc"

    def test_6_prepends_memory(self):
        assert _final("cM6", "abc") == "AbcAbc"

    def test_Q_rejects_when_word_equals_memory(self):
        assert _final("MQ", "abc") is None

    def test_Q_passes_when_word_differs_from_memory(self):
        assert _final("Mc Q", "abc") == "Abc"
        assert _final("MuQ", "abc") == "ABC"

    def test_4_without_M_appends_the_zeroed_buffer(self):
        """hashcat: bare '4' on abc gives 'abc\\0\\0\\0'. See Task 7b."""
        assert _final("4", "abc") == "abc\x00\x00\x00"

    def test_6_without_M_prepends_the_zeroed_buffer(self):
        assert _final("6", "abc") == "\x00\x00\x00abc"

    def test_step_is_emitted_even_when_nothing_changes(self):
        """A no-op must still produce a step, so a reader never mistakes a
        silently-skipped opcode for one that legitimately did nothing."""
        steps = explain_rule("MQ4", "abc")
        assert steps is None or any(s.startswith("4:") for s in steps)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k Memory`
Expected: FAIL. `M4` yields only the `M` step, so the final candidate is `abc`.

- [ ] **Step 3: Implement**

Locate the existing memory variable in `explain_rule` (the one `M` writes and `X` reads) and add:

```python
        elif char == "4":
            prev = current
            if len(current) + len(memory) < 256:
                current = current + memory
            steps.append(f"4: Append memorized '{memory}' → {prev} → {current}")
            i += 1

        elif char == "6":
            prev = current
            if len(current) + len(memory) < 256:
                current = memory + current
            steps.append(f"6: Prepend memorized '{memory}' → {prev} → {current}")
            i += 1

        elif char == "Q":
            if current == memory:
                return None
            steps.append(
                f"Q: Differs from memorized '{memory}' (filter passed) → {current} → {current}"
            )
            i += 1
```

Add `"4"`, `"6"`, `"Q"` to `_DEFAULT_IMPLEMENTED`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v`
Expected: PASS, all classes.

- [ ] **Step 5: Verify against the CPU oracle**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task7.md`
Expected: exit 0, with `4`, `6`, `Q`, `M`, `X` all showing as compared via the CPU engine.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py hashcat_rosetta/_verify.py tests/test_missing_opcodes.py
git commit -m "feat: implement 4, 6, Q memory opcodes (#37)

Closes the memory family; M and X were already simulated, so the buffer
they share was already present."
```

---

### Task 7a: `a` is a no-op

**Files:**
- Modify: `hashcat_rosetta/cli.py:525-529`
- Test: `tests/test_missing_opcodes.py`

**Interfaces:**
- Consumes: the CPU oracle. `a` is already in `_ZERO_ARG_OPCODES` and `_DEFAULT_IMPLEMENTED`, so no table changes.
- Produces: no new symbols. `a` stops mutating `current`.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_missing_opcodes.py
class TestNoOpOpcode:
    """hashcat declares RULE_OP_MANGLE_TOGGLECASE_REC for `a` but the body is
    a `/* todo */ break;` stub, so it changes nothing. Verified: `-j 'a'` on
    abc gives abc, and `-j 'ca'` gives Abc.
    """

    def test_a_changes_nothing(self):
        assert _final("a", "abc") == "abc"

    def test_a_does_not_interfere_with_neighbouring_opcodes(self):
        assert _final("ca", "abc") == "Abc"

    def test_a_still_emits_a_step(self):
        steps = explain_rule("a", "abc")
        assert steps is not None
        assert any(s.startswith("a:") for s in steps)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k NoOp`
Expected: FAIL. `_final("a", "abc")` currently returns `abcabc`.

- [ ] **Step 3: Replace the append-memorized behavior with a no-op**

```python
        elif char == "a":
            # RULE_OP_MANGLE_TOGGLECASE_REC. hashcat declares the opcode but
            # its implementation body is `/* todo */ break;`, so it is a no-op
            # upstream. Verified against 7.1.2: `-j 'a'` on abc gives abc.
            # This previously appended the memory buffer, which nothing in
            # hashcat does.
            steps.append(f"a: No-op (unimplemented in hashcat) → {current} → {current}")
            i += 1
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k NoOp`
Expected: PASS, 3 tests.

- [ ] **Step 5: Confirm against the oracle**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task7a.md`
Expected: exit 0, `a` compared via the CPU engine with no mismatch.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py tests/test_missing_opcodes.py
git commit -m "fix: 'a' is a no-op upstream, not append-memorized

hashcat's RULE_OP_MANGLE_TOGGLECASE_REC body is a todo stub. We were
appending the memory buffer, which no hashcat version does."
```

---

### Task 7b: Zero-fill the memory buffer

**Files:**
- Modify: `hashcat_rosetta/cli.py:148`
- Test: `tests/test_missing_opcodes.py`

**Interfaces:**
- Consumes: the CPU oracle.
- Produces: no new symbols. `memorized` is initialized to `"\x00" * len(baseword)` rather than to `baseword`.

This corrects `X`, which has been wrong since 0.4.0 for any rule using it without a preceding `M`. Do this task after Task 7 so all five memory opcodes are present and get fixed by one change.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_missing_opcodes.py
class TestMemoryInitialization:
    """hashcat zero-fills the memory buffer to the plain's length. It does not
    seed it with the plain. Verified with od -c against v7.1.2.
    """

    def test_X_without_M_reads_nul_bytes(self):
        # hashcat: 'X012' on abc -> a b \0 c
        assert _final("X012", "abc") == "ab\x00c"

    def test_X_after_M_reads_the_memorized_word(self):
        assert _final("MX012", "abc") == "abac"

    def test_buffer_length_tracks_the_baseword(self):
        # hashcat: bare '4' on abcdef appends six NULs
        assert _final("4", "abcdef") == "abcdef" + "\x00" * 6
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k Initialization`
Expected: FAIL. `_final("X012", "abc")` returns `abac`, because the buffer is seeded with the baseword.

- [ ] **Step 3: Fix the initialization**

At `cli.py:148`, replace:

```python
    memorized = baseword  # Default memorized word is the original input
```

with:

```python
    # hashcat zero-fills the memory buffer to the plain's length rather than
    # seeding it with the plain, so a memory op used without a preceding `M`
    # reads NUL bytes. Verified against 7.1.2: bare `4` on "abcdef" yields
    # "abcdef" + six NULs, and bare `X012` on "abc" yields "ab\0c".
    memorized = "\x00" * len(baseword)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v`
Expected: PASS, all classes including the Task 7 memory tests.

- [ ] **Step 5: Check the blast radius**

Run: `uv run pytest -q`
Expected: green. If an existing test asserted the old seeded-buffer behavior, that test encoded the bug; update it and note the change in the commit message rather than reverting this fix.

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task7b.md`
Expected: exit 0, with `M`, `X`, `4`, `6`, `Q` all compared and matching.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py tests/test_missing_opcodes.py
git commit -m "fix: zero-fill the memory buffer instead of seeding it

hashcat fills the memory buffer with len(plain) NUL bytes; we seeded it with
the plain itself. X has been wrong since 0.4.0 for any rule that uses it
without a preceding M. Found only because M and X were finally oracled."
```

---

### Task 7c: Fix `M`'s step-format bug and `X`'s missing OOB check

**Added mid-execution.** Task 2's sweep surfaced these two the moment `M`/`X` were routed to the CPU oracle for the first time (they were in the old `_HASHCAT_STDOUT_UNSUPPORTED` skip set, so they had never been compared before). Confirmed real by direct read of `cli.py` during Task 2's review. Neither is in `KNOWN_LATENT`. They must be fixed before Task 9, which requires 0 mismatches on the full BARRAGE sweep.

**Files:**
- Modify: `hashcat_rosetta/cli.py:532-536` (`M` branch), `:538-559` (`X` branch)
- Test: `tests/test_missing_opcodes.py`

**Interfaces:**
- Consumes: the CPU oracle from Tasks 1 and 2.
- Produces: no new symbols.

**Bug 1 — `M`'s step string breaks `_extract_final`.** `cli.py:535` is:

```python
steps.append(f"M: Memorize current word '{current}'")
```

`_extract_final` (`_verify.py:437-446`) isolates the candidate by splitting the last step on `" → "`. This string has no such separator, so `_extract_final` falls through to `return last`, handing back the entire sentence as the "final candidate" whenever `M` is the last opcode in a rule. Fix: give it the same `"<desc> → <prev> → <current>"` shape every other step uses (`M` doesn't change `current`, so prev and current are identical):

```python
        elif char == "M":
            # Memorize current word for later use with X opcode
            memorized = current
            steps.append(f"M: Memorize current word '{current}' → {current} → {current}")
            i += 1
```

**Bug 2 — `X` silently no-ops out-of-bounds instead of rejecting.** `cli.py:549`:

```python
                if n < len(memorized) and n + m <= len(memorized) and l_pos <= len(current):
                    substring = memorized[n : n + m]
                    current = _cap(prev, current[:l_pos] + substring + current[l_pos:])
                steps.append(...)
```

When the bounds check fails, `current` is left unchanged and a step is still appended — reported as "nothing happened" rather than "rejected." hashcat disagrees: `X013` on baseword `a` (before Task 7b: `memorized = "a"`, so `n=0 < 1` and `n+m=1 <= 1` both hold, but `l_pos=3 <= len(current)=1` fails) produces empty `--stdout`, confirmed with `od -c` showing zero bytes, not `a` unchanged:

```
$ hashcat --stdout -a0 -j 'X013' <(echo a)   ->   (empty output)
```

`_has_oob_position` (`_verify.py:219-297`, `_POS_1ARG_FIRST`/`_POS_2ARG_FIRST`/`_POS_2ARG_SECOND`, `:193-199`) never covers `X`, the sole `_THREE_ARG_OPCODES` member — it has no position-argument set of its own. Rather than teaching the shared OOB-detection helper about `X`'s two-position-space shape (memorized-word bounds vs current-word bounds), reject directly in `explain_rule` where the check already lives:

```python
        elif char == "X" and i + 3 < len(rule_str):
            n_char = rule_str[i + 1]
            m_char = rule_str[i + 2]
            l_char = rule_str[i + 3]
            try:
                n = _hashcat_pos(n_char)
                m = _hashcat_pos(m_char)
                l_pos = _hashcat_pos(l_char)
                if not (n < len(memorized) and n + m <= len(memorized) and l_pos <= len(current)):
                    return None
                prev = current
                substring = memorized[n : n + m]
                current = _cap(prev, current[:l_pos] + substring + current[l_pos:])
                steps.append(
                    f"X{n_char}{m_char}{l_char}: Insert {m} chars from memorized word"
                    f" at pos {n} into pos {l_pos} → {prev} → {current}"
                )
                i += 4
            except (ValueError, IndexError):
                i += 1
```

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_missing_opcodes.py
class TestMFormatAndXBounds:
    """Both confirmed against hashcat v7.1.2 during Task 2's review."""

    def test_bare_M_final_candidate_is_the_word_not_the_description(self):
        assert _final("M", "abc") == "abc"

    def test_M_followed_by_another_opcode_still_works(self):
        assert _final("Mc", "abc") == "Abc"

    def test_X_rejects_when_insert_position_exceeds_current_length(self):
        # hashcat: X013 on 'a' (memorized == 'a' pre-Task-7b) -> empty output
        assert _final("X013", "a") is None

    def test_X_still_succeeds_within_bounds(self):
        assert _final("MX012", "abc") == "abac"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k "MFormatAndXBounds"`
Expected: FAIL. `test_bare_M_final_candidate_is_the_word_not_the_description` gets the full sentence back; `test_X_rejects_when_insert_position_exceeds_current_length` gets `"a"` instead of `None`.

- [ ] **Step 3: Apply both fixes**

Exactly the two code blocks shown above.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v`
Expected: PASS, all classes including Task 7's and Task 7b's.

- [ ] **Step 5: Confirm against the oracle**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task7c.md`
Expected: exit 0. `M` and `X` no longer appear as REGRESSION rows.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py tests/test_missing_opcodes.py
git commit -m "fix: M's step string breaks final-candidate extraction; X doesn't reject OOB

M's step lacked the ' → prev → current' shape every other step uses, so
_extract_final returned the whole sentence when M was a rule's last opcode.
X silently no-op'd out-of-bounds inserts instead of rejecting, which is what
hashcat actually does. Both surfaced only once Task 2 routed M/X to a real
oracle for the first time."
```

---

### Task 7d: `X` mutates the memory buffer as a side effect

**Added mid-execution.** Task 7c's report flagged that chained `X` opcodes without an intervening `M` (e.g. `X334 X444` in one rule) mismatch real hashcat, confirmed pre-existing via `git stash` and surfaced by `tests/test_rule_matrix.py::test_hashcat_vs_explain` (6/6573 mismatches). The controller (me) traced the root cause to hashcat's actual C implementation and verified it against four reproducer cases. This is real, not speculative, but the fix needs care: what's verified below is a *simplified* model that happens to match every case tried so far, not a proven-general translation.

**Root cause, read directly from hashcat source** (`src/rp_cpu.c`):

```c
static int mangle_insert_multi (char arr[RP_PASSWORD_SIZE], int arr_len, int arr_pos, char arr2[RP_PASSWORD_SIZE], int arr2_len, int arr2_pos, int arr2_cpy)
{
  if ((arr_len + arr2_cpy) > RP_PASSWORD_SIZE) return (RULE_RC_REJECT_ERROR);
  if (arr_pos > arr_len) return (RULE_RC_REJECT_ERROR);
  if (arr2_pos > arr2_len) return (RULE_RC_REJECT_ERROR);
  if ((arr2_pos + arr2_cpy) > arr2_len) return (RULE_RC_REJECT_ERROR);
  if (arr2_cpy < 1) return (RULE_RC_SYNTAX_ERROR);

  memmove (arr2, arr2 + arr2_pos, arr2_len - arr2_pos);
  memcpy  (arr2 + arr2_cpy, arr + arr_pos, arr_len - arr_pos);
  memcpy  (arr + arr_pos, arr2, arr_len - arr_pos + arr2_cpy);

  return (arr_len + arr2_cpy);
}

case RULE_OP_MANGLE_EXTRACT_MEMORY:
  if (mem_len < 1) HCFREE_AND_RETURN (RULE_RC_REJECT_ERROR);
  ...
  if ((out_len = mangle_insert_multi (out, out_len, upos2, mem, mem_len, upos, ulen)) < 1) HCFREE_AND_RETURN (out_len);
  break;
```

`arr` is `out` (the current word buffer), `arr2` is `mem` (the memory buffer). `X`'s call is `mangle_insert_multi(out, out_len, l_pos, mem, mem_len, n, m)`. **The function mutates `arr2` (the memory buffer) in place** via `memmove`/`memcpy`, using bytes copied from `arr` (the current word) — this is not documented anywhere, and every prior task in this plan (including Task 7b's zero-fill fix) assumed `memorized` is read-only after `M` sets it. It isn't: `X` rewrites it as a side effect, which is exactly why a second `X` with no intervening `M` reads different bytes than the first one did. Both `arr` and `arr2` are real, fixed-size `RP_PASSWORD_SIZE` (256-byte, `include/rp.h:12`) buffers in hashcat — `mem_len` and `out_len` are logical length registers into those buffers, not the buffers' actual allocated size.

**What the controller already verified** (a direct Python translation of the three C lines above, operating on Python bytes/bytearrays sized to exactly `mem_len`/`out_len` rather than the full 256-byte buffer) matches all four known cases exactly:

```
X011 on 'abcdefgh' (mem zero-filled len 8)     -> current='a\x00bcdefgh'   (unchanged from Task 7b's model)
X011 X011 on 'abcdefgh'                        -> current='a\x00\x00bcdefgh'
X011 X021 on 'abcdefgh'                        -> current='a\x00b\x00bcdefgh'
X334 X444 on 'password'                        -> current='passord\x00\x00\x00\x00word'
```

All four were confirmed against real hashcat `v7.1.2-386-g8000b3e60` via `hashcat --stdout -a0 -j '<rule>' <(echo '<baseword>')`.

**Why this is not simply "apply the fix":** the controller's translation used bytearrays sized to exactly the *logical* length (`mem_len` / `out_len`), not the real 256-byte physical buffer. That happened to work for these four cases because the byte ranges involved never needed room beyond the logical length. hashcat's real buffers have 256 bytes of physical room regardless of logical length, so a case where `arr2_cpy` (m) plus the copied region would exceed the *logical* `mem_len` but still fit inside the real 256-byte buffer could behave differently from a naive same-length-bytearray translation. **This task's job is to determine whether that distinction ever matters in practice for this codebase's `_RP_PASSWORD_SIZE = 256` model** (which already exists, `cli.py:47`, for the length-cap logic) and implement accordingly — modeling `memorized` as a full 256-byte buffer (like hashcat's real `mem` array) rather than a same-length slice, if the oracle shows daylight between the two models.

**Files:**
- Modify: `hashcat_rosetta/cli.py` (the `M` and `X` branches, and likely the `memorized` initialization Task 7b touched)
- Test: `tests/test_missing_opcodes.py`

**Interfaces:**
- Consumes: the CPU oracle from Tasks 1 and 2. `_RP_PASSWORD_SIZE = 256` (`cli.py:47`) already exists for the length-cap helper `_cap` — this task's `memorized` model should very likely be sized against this same constant, since it's the same physical buffer hashcat uses.
- Produces: no new public symbols required, but `memorized`'s representation may change from "a string exactly as long as the logical memory length" to "a 256-byte buffer with a separate logical-length register" if the investigation in Step 0 shows that distinction matters. If it does, every existing memory-opcode branch (`M`, `X`, `4`, `6`, `Q`) needs updating consistently — do not leave some branches on the old model and others on the new one.

- [ ] **Step 0: Determine whether the 256-byte-buffer distinction actually matters here**

Before writing any fix, construct a handful of oracle test cases specifically designed to probe whether logical-length-sized buffers diverge from a full 256-byte model. A good starting point: rules with a large `m` (extract length) relative to a short baseword, chained across two or more `X` calls, where the "logical mem_len" runs out of room but 256 bytes wouldn't. For example, try `X0X0` -style cases where `arr2_cpy` (m) is deliberately large against a short baseword's `mem_len`, both alone and chained, and diff against `hashcat --stdout -a0 -j '<rule>' <(echo '<baseword>')`. Report what you find before proceeding — if a same-length-buffer model already matches hashcat in every case you can construct, that is sufficient and simpler than modeling the full 256 bytes; only reach for the full-buffer model if you can demonstrate a real divergence.

- [ ] **Step 1: Write failing tests from the four already-verified reproducer cases**

```python
# append to tests/test_missing_opcodes.py
class TestChainedXMemoryMutation:
    """X mutates the memory buffer as a side effect (src/rp_cpu.c's
    mangle_insert_multi). All four cases verified against hashcat v7.1.2
    via `hashcat --stdout -a0 -j '<rule>' <(echo '<baseword>')`.
    """

    def test_X011_alone_unchanged_from_task_7b_model(self):
        assert _final("X011", "abcdefgh") == "a\x00bcdefgh"

    def test_chained_X011_X011_reads_the_mutated_buffer(self):
        assert _final("X011 X011", "abcdefgh") == "a\x00\x00bcdefgh"

    def test_chained_X011_X021_reads_the_mutated_buffer(self):
        assert _final("X011 X021", "abcdefgh") == "a\x00b\x00bcdefgh"

    def test_chained_X334_X444_reads_the_mutated_buffer(self):
        assert _final("X334 X444", "password") == "passord\x00\x00\x00\x00word"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_missing_opcodes.py -v -k ChainedX`
Expected: FAIL on the three chained cases (single `X011` alone should already pass, since Task 7b's model is correct for a lone `X`).

- [ ] **Step 3: Implement, informed by Step 0's finding**

Update the `X` branch so it mutates `memorized`, not just `current`, following the three-line C translation above (`memmove`-equivalent shift, then `memcpy`-equivalent splice from `current`'s tail, then the actual insert into `current`). Reuse `_RP_PASSWORD_SIZE` if Step 0 showed the physical-buffer distinction matters; otherwise a same-logical-length translation is sufficient. Whichever model you land on, apply it consistently to `M` (which resets `memorized` to `current` — confirm this still zeroes out any prior mutation correctly) and to `4`/`6`/`Q` (which read `memorized` but don't mutate it — confirm they still work against a `memorized` that may now change mid-rule from a prior `X`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_missing_opcodes.py -v`
Expected: PASS, all classes.

- [ ] **Step 5: Confirm against both the opcode sweep and the full rule-matrix integration test**

Run: `uv run python scripts/sweep_opcodes.py --report /tmp/sweep-task7d.md`
Expected: exit 0, `X` still shown as PASS (the sweep's single-opcode-per-rule design won't exercise chaining, but must not regress).

Run: `uv run pytest tests/test_rule_matrix.py::TestGenerateRulesIntegration::test_hashcat_vs_explain -v`
Expected: PASS (0/6573 mismatches, down from the pre-existing 6/6573). This is the test that originally surfaced the bug and is the actual acceptance gate for this task.

- [ ] **Step 6: Commit**

```bash
git add hashcat_rosetta/cli.py tests/test_missing_opcodes.py
git commit -m "fix: X mutates the memory buffer, not just the current word

hashcat's mangle_insert_multi (src/rp_cpu.c) rewrites the memory buffer as
a side effect of every X call, using bytes from the current word. A second
X in the same rule with no intervening M therefore reads a different
buffer than the first one did. Verified against hashcat 7.1.2 across four
chained-X reproducer cases; found via test_rule_matrix.py's full-corpus
integration sweep, not the single-opcode sweep, since it only manifests
across multiple opcode applications in one rule."
```

---

### Task 8: Coverage gate, so this cannot regress

**Files:**
- Modify: `scripts/sweep_opcodes.py`
- Test: `tests/test_oracle_routing.py`

**Interfaces:**
- Consumes: `_ALL_KNOWN_OPCODES`, `_DEFAULT_IMPLEMENTED`, `_CPU_ONLY_OPCODES`, `KNOWN_LATENT`.
- Produces: `unoracled_opcodes() -> dict[str, str]` in `scripts/sweep_opcodes.py`, mapping each opcode with no oracle coverage to the reason. The sweep exits nonzero if that dict has any entry not in `KNOWN_LATENT`.

The point of this task is that Tasks 3 and 4 found real bugs only because someone went looking. The gate makes "an opcode is simulated but never compared" a build failure instead of a thing to notice later.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_oracle_routing.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def test_every_known_opcode_is_either_oracled_or_explicitly_excused():
    from sweep_opcodes import KNOWN_LATENT, unoracled_opcodes

    gaps = unoracled_opcodes()
    unexcused = {op: why for op, why in gaps.items() if op not in KNOWN_LATENT}
    assert unexcused == {}, f"opcodes with no oracle and no excuse: {unexcused}"


def test_the_previously_unoracled_thirteen_are_now_covered():
    from sweep_opcodes import unoracled_opcodes

    gaps = unoracled_opcodes()
    for op in "MX!<>%()=46Qa":
        assert op not in gaps, f"{op} should now be oracled via the CPU engine"


def test_only_the_oracle_environment_exemptions_remain():
    """B and v are excused because CI's POCL backend emits nothing for them,
    not because we are unsure what they do. Nothing else may be excused.
    'a' is NOT here: it is oracled via -j and its expected value is
    'unchanged'.
    """
    from sweep_opcodes import KNOWN_LATENT

    assert set(KNOWN_LATENT) == {"B", "v"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_oracle_routing.py -v -k oracled`
Expected: FAIL with `ImportError: cannot import name 'unoracled_opcodes'`.

- [ ] **Step 3: Implement the gate**

Add to `scripts/sweep_opcodes.py`:

```python
def unoracled_opcodes() -> dict[str, str]:
    """Return {opcode: reason} for every known opcode with no oracle coverage.

    An opcode is oracled when it is simulated (in _DEFAULT_IMPLEMENTED) and an
    engine accepts it. Every known opcode is accepted by exactly one engine:
    _CPU_ONLY_OPCODES go to `-j`, everything else to `-r`. So the only real
    gap left is "recognized by the tokenizer but not simulated".
    """
    gaps: dict[str, str] = {}
    for op in sorted(_ALL_KNOWN_OPCODES):
        if op not in _DEFAULT_IMPLEMENTED:
            gaps[op] = "tokenized and described, but not simulated by explain_rule()"
    return gaps
```

Leave `KNOWN_LATENT` at exactly `B` and `v`. Do not add `a`: Task 7a makes it a correctly-simulated no-op that the CPU oracle can confirm.

Wire the gate into the exit path, next to the existing mismatch check:

```python
    gaps = {op: why for op, why in unoracled_opcodes().items() if op not in KNOWN_LATENT}
    if gaps:
        print(f"\nFAIL: {len(gaps)} opcode(s) have no oracle coverage:", file=sys.stderr)
        for op, why in gaps.items():
            print(f"  {op!r}: {why}", file=sys.stderr)
        exit_code = 1
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_oracle_routing.py -v`
Expected: PASS. If `test_every_known_opcode_is_either_oracled_or_explicitly_excused` fails, the failure message names the opcodes still missing; that is the gate doing its job, and each one needs either an implementation or a cited `KNOWN_LATENT` entry.

- [ ] **Step 5: Run the whole gate**

Run: `uv run pytest -q && uv run python scripts/sweep_opcodes.py --report reports/opcode-sweep.md --json reports/opcode-sweep.json`
Expected: exit 0. Commit the regenerated reports.

- [ ] **Step 6: Commit**

```bash
git add scripts/sweep_opcodes.py tests/test_oracle_routing.py reports/opcode-sweep.md reports/opcode-sweep.json
git commit -m "feat(sweep): fail the build on any opcode with no oracle

Three bugs hid for two releases in opcodes that were simulated but never
compared. Make that state impossible to reach without an explicit,
issue-citing excuse."
```

---

### Task 9: Re-run the full BARRAGE sweep and correct the published numbers

**Files:**
- Modify: `CHANGELOG.md`, `docs/unimplemented-opcodes.md`, `README.md:177,183`, `reports/barrage-opcode-report.json`
- Test: none. This task is measurement and documentation.

**Interfaces:**
- Consumes: everything above.
- Produces: the new oracle-comparable count, which the blog post also quotes.

- [ ] **Step 1: Re-run the full sweep**

```bash
uv run python scripts/verify_rules.py --rules ~/projects/hashcat/rules/BARRAGE.rule \
  --report reports/barrage-opcode-report.md --json reports/barrage-opcode-report.json
```

Expected: `0 mismatches`. The oracle-comparable count must rise: the previous run compared 32,331,257 of 32,467,184 rules, a gap of 135,927, and the thirteen newly-routed opcodes plus `S`/`h`/`H` live in that gap. Record the new numbers. If mismatches appear, stop and treat each as a bug in Tasks 3 through 7 rather than editing the number to match. Tasks 7a and 7b in particular change already-published behavior, so expect the count to move for `X` rules too.

- [ ] **Step 2: Fix the inverted README documentation**

`README.md:177` describes debug-mode 4 output as "three **space-separated** fields" and `:183` calls colon-separated the "older hashcat versions" format. Both are backwards. hashcat has always emitted colons (`src/debugfile.c` writes `orig`, `:`, `rule`, `:`, `mod`); the space-separated form is the legacy one this parser also accepts. Correct both lines, and describe the real distinction as mode 4 (three fields) versus mode 5 (four fields, trailing wordlist).

- [ ] **Step 3: Rewrite `docs/unimplemented-opcodes.md`**

It is now substantially wrong. Remove `B` and `v` (implemented in 0.4.0), remove `M` and `X` (implemented), remove `S`, `h`, `H`, `4`, `6`, `Q` (implemented by this plan). Fix the `cshift_lookup` path from `OpenCL/inc_rp_common.h` to `OpenCL/inc_rp_common.cl:42`. What should remain is `a` and its upstream-stub explanation. If nothing else remains, retitle the file to reflect that it now records opcode semantics and oracle routing rather than gaps, or delete it and fold the content into `CLAUDE.md`.

- [ ] **Step 4: Write the CHANGELOG entry**

```markdown
## [Unreleased]

### Fixed

- **`<` and `>` length filters were inverted.** hashcat's `>N` rejects plains
  shorter than N and `<N` rejects longer; both the descriptions and the
  simulation had it backwards, so `--explain` reported "filter passed" for
  candidates hashcat drops and refused to explain rules hashcat runs.
- **`%` is `%NX`, not `%X`.** The wrong arity made every `%` rule unexplainable
  and mis-tokenized every opcode following a `%`, which corrupted
  `--analyze-rules` statistics for any rule file containing one.
- **`a` is a no-op.** hashcat declares `RULE_OP_MANGLE_TOGGLECASE_REC` but its
  body is a `/* todo */ break;` stub. We were appending the memory buffer,
  which no hashcat version does.
- **The memory buffer is zero-filled, not seeded with the plain.** hashcat
  fills it with `len(plain)` NUL bytes, so a memory op with no preceding `M`
  reads NULs. `X` had been wrong since 0.4.0 for exactly that case: bare
  `X012` on `abc` is `ab\0c`, and we produced `abac`.

### Added

- **A second oracle: the host-side rule engine via `hashcat -j`.** Filter and
  memory opcodes (`! < > % ( ) = M X 4 6 Q`) are invalid in `-r` rule files in
  every mode, so they had never been compared against hashcat at all. They are
  now oracled against the engine that actually implements them. The two engines
  are routed per opcode and never interchanged, because they disagree on `3NX`.
- **`S`, `h`, `H`, `4`, `6`, and `Q` are implemented** (#37), closing the last
  simulator gaps. `S` is an XOR against hashcat's `cshift_lookup` mask, not a
  case toggle.
- **The sweep now fails on any opcode with no oracle coverage,** so a
  simulated-but-unverified opcode cannot ship again without a cited excuse.
```

- [ ] **Step 5: Close the issue**

```bash
gh issue close 37 --comment "Fixed across the oracle-every-opcode plan. S, h, H, 4, 6, and Q are implemented; the silent-skip path is gone; and the sweep now fails the build on any opcode without oracle coverage. Also caught two bugs that were hiding in the never-compared set: inverted < and > filters, and % having the wrong arity."
```

- [ ] **Step 6: Commit**

```bash
git add CHANGELOG.md README.md docs/unimplemented-opcodes.md reports/
git commit -m "docs: correct oracle coverage claims and debug-format description

The oracle-comparable count moves now that filter and memory opcodes are
actually compared. README had the debug-mode delimiter backwards: hashcat
emits colons and always has; spaces are the legacy form."
```

---

## Notes for whoever executes this

**Run the tasks in order and serially.** Tasks 3 through 7 all edit `cli.py`, and Task 2 deliberately turns the sweep red so Tasks 3 and 4 have a failing oracle to fix. Parallelizing will produce conflicts and confusing sweep output.

**Two things need a real hashcat binary,** so mark the oracle tests with the repo''s existing `@pytest.mark.integration` (registered in pyproject.toml, used throughout tests/test_rule_matrix.py) and keep them out of the unit-only path: Task 1's engine tests and every sweep invocation.

**If the CPU oracle disagrees with the simulator on an opcode not listed in the findings above, believe the oracle and stop.** That is a new bug, and it means the blind spot was hiding more than the three found so far. Add it to this plan rather than patching around it.

**One gap this plan does not close, stated so it is not mistaken for covered.** Opcode identity is not the only reason `verify_rule` skips a rule. Four other conditions do too: `_has_truncated_opcode`, `_has_oob_position`, `_has_invalid_position_arg`, and an empty baseword (`_verify.py:445-480`). Each is a judgment about what hashcat would reject, and each is itself unverified against hashcat. They are out of scope here because they are rule-shape predicates rather than opcodes, but they are the same species of assumption as `_HASHCAT_STDOUT_UNSUPPORTED` was, and that one turned out to be hiding five bugs. Worth its own pass afterward.

**Do not widen `KNOWN_LATENT` to make the gate pass.** The gate exists because the previous exclusion mechanism was load-bearing and invisible. Every entry needs an issue number and a reason that is about the oracle environment, not about the simulator being wrong.
