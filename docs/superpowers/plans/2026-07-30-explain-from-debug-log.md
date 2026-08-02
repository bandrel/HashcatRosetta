# Explain-From-Debug-Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--explain` work against a hashcat debug log, explaining the rules
the log actually contains using the basewords the log actually pairs them with,
and flagging where the simulation disagrees with hashcat's real candidate.

**Architecture:** `--explain` becomes a Click option with an optional value: with
a value it behaves exactly as today (rule string or rule-file path); bare, with a
debug FILE, it decorates the `--rules` / `--basewords` listings with per-rule
explanation blocks. The simulation loop inside `explain_rule` is first extracted
into `_simulate_rule`, which returns both the step list and the true final word,
so the new match check does not have to string-parse step text.

**Tech Stack:** Python 3.10+, Click, pytest, ruff, mypy, uv.

**Spec:** `docs/superpowers/specs/2026-07-30-explain-from-debug-log-design.md`

## Global Constraints

- Line length 100 (ruff, configured in `pyproject.toml`). Run
  `uv run ruff format hashcat_rosetta/ tests/` and
  `uv run ruff check hashcat_rosetta/ tests/` before every commit.
- `uv run mypy hashcat_rosetta/` must pass.
- `explain_rule(rule_str: str, baseword: str = "password") -> list | None` keeps
  its exact signature and behavior. `_verify.py`, `scripts/verify_rules.py`, and
  ~190 test assertions depend on it.
- Explanations are display-only. They never enter `--export` output.
- No silent truncation: any cap on how much is printed must print how much was
  dropped.
- All new output goes to stdout via `click.echo`; the banner stays on stderr.
- Every rendered explanation string passes through the existing `_escape_bytes`
  before being echoed.

## File Structure

- `hashcat_rosetta/cli.py` — all changes live here: the `_simulate_rule`
  extraction, the option definition, dispatch, and the rendering helpers. The
  file is already the home of both `explain_rule` and the debug-listing output,
  so the feature does not warrant a new module.
- `hashcat_rosetta/_verify.py` — one-line switch to the accurate final word.
- `tests/test_cli.py` — all new tests; it already holds the `--explain` and
  debug-listing CLI tests plus the `debug_file` fixture.

---

### Task 1: Extract `_simulate_rule` and give `_verify` an accurate final word

**Files:**
- Modify: `hashcat_rosetta/cli.py:103-726` (the `explain_rule` function)
- Modify: `hashcat_rosetta/_verify.py:427-438,487-488`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `_simulate_rule(rule_str: str, baseword: str = "password") ->
  tuple[list[str], str] | None` in `hashcat_rosetta/cli.py`. Returns
  `(steps, final_word)` on success and `None` in exactly the cases
  `explain_rule` returns `None` today (empty rule, filter opcode rejected the
  word, no steps produced). `explain_rule` becomes a wrapper over it.

**Background:** `_verify._extract_final` recovers the final word by splitting the
last step string on `" → "`. Steps with no arrow break it — `explain_rule("M",
"x")` yields `["M: Memorize current word 'x'"]`, and the parse hands back that
whole sentence as the "final word". Task 3's match check would render a
guaranteed false `[MISMATCH]` for any rule ending in `M`. Fix it at the source.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py`, in the `# --- explain_rule() edge cases ---` section:

```python
class TestSimulateRule:
    """_simulate_rule returns both the steps and the true final word."""

    def test_steps_match_explain_rule(self):
        from hashcat_rosetta.cli import _simulate_rule

        for rule in ("c", "u$1", "sa@", "^!d", "i74", "31s$1"):
            simulated = _simulate_rule(rule, "password")
            assert simulated is not None, rule
            steps, _final = simulated
            assert steps == explain_rule(rule, "password"), rule

    def test_final_word_is_the_transformed_word(self):
        from hashcat_rosetta.cli import _simulate_rule

        simulated = _simulate_rule("c$1", "admin")
        assert simulated is not None
        _steps, final = simulated
        assert final == "Admin1"

    def test_final_word_correct_when_last_step_has_no_arrow(self):
        """A trailing M step prints no ' -> ' arrow; the final word is still the word.

        The old string-parsing recovery returned the whole step sentence here.
        """
        from hashcat_rosetta.cli import _simulate_rule

        simulated = _simulate_rule("c$1M", "admin")
        assert simulated is not None
        _steps, final = simulated
        assert final == "Admin1"

    def test_returns_none_where_explain_rule_returns_none(self):
        from hashcat_rosetta.cli import _simulate_rule

        assert _simulate_rule("") is None
        assert _simulate_rule("!s", "password") is None  # filter rejects
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::TestSimulateRule -v`
Expected: FAIL with `ImportError: cannot import name '_simulate_rule'`.

- [ ] **Step 3: Extract the function**

In `hashcat_rosetta/cli.py`, rename the existing `explain_rule` to
`_simulate_rule`, change its return type, and add a thin wrapper. Concretely:

1. Change the `def` line and docstring at line 103 to:

```python
def _simulate_rule(rule_str: str, baseword: str = "password") -> tuple[list[str], str] | None:
    """Simulate a hashcat rule, returning its steps and the resulting word.

    Returns ``(steps, final_word)``, or ``None`` when there is nothing to
    explain — an empty rule, a filter opcode that rejected the word, or a rule
    that produced no recognized steps. ``final_word`` is the transformed word
    itself, not a value re-parsed out of the step text: steps such as ``M:
    Memorize ...`` carry no ``->`` arrow, so text parsing is unreliable.
    """
```

2. Leave the entire body unchanged except the final line. Replace the closing
   `return steps if steps else None` (line 726) with:

```python
    return (steps, current) if steps else None
```

3. The three early `return None` statements inside the filter opcodes (`!`,
   `>`, `<`, `%`, `=`, `(`, `)`) stay exactly as they are — `None` already
   satisfies the new return type.

4. Immediately after `_simulate_rule`, add the wrapper:

```python
def explain_rule(rule_str: str, baseword: str = "password") -> list | None:
    """Explain what a hashcat rule does with examples.

    Thin wrapper over :func:`_simulate_rule` that drops the final word. Kept
    with an unchanged signature because the verification harness, the scripts,
    and the test suite all call it.
    """
    simulated = _simulate_rule(rule_str, baseword)
    return simulated[0] if simulated else None
```

- [ ] **Step 4: Run the new tests and the full suite**

Run: `uv run pytest tests/test_cli.py::TestSimulateRule -v`
Expected: PASS.

Run: `uv run pytest`
Expected: PASS, same count as before plus the 4 new tests. `explain_rule`'s
behavior is unchanged, so no existing test may change.

- [ ] **Step 5: Switch `_verify` to the accurate final word**

In `hashcat_rosetta/_verify.py`, change the import on line 21 to:

```python
from hashcat_rosetta.cli import _simulate_rule, explain_rule
```

Replace the body of `_extract_final` (lines 427-438) with a version that takes
the rule and baseword instead of the step list:

```python
def _extract_final(rule: str, baseword: str) -> str:
    """Return the word the simulator produces, or "" if it produced nothing.

    Reads the final word straight out of the simulation. The previous version
    string-parsed the last step on " -> ", which returned the step sentence
    itself for steps that carry no arrow (a rule ending in M, for example).
    """
    simulated = _simulate_rule(rule, baseword)
    return simulated[1] if simulated else ""
```

At line 487-488, replace:

```python
    explanation = explain_rule(rule, baseword)
    our_final = _extract_final(explanation)
```

with:

```python
    explanation = explain_rule(rule, baseword)
    our_final = _extract_final(rule, baseword)
```

Then grep for any other `_extract_final(` call site and update it the same way:

```bash
grep -rn "_extract_final" hashcat_rosetta/ tests/ scripts/
```

If a test calls `_extract_final` with a step list, update the call to pass
`(rule, baseword)`.

- [ ] **Step 6: Run the verification suite and the opcode sweep**

Run: `uv run pytest`
Expected: PASS.

Run: `uv run python scripts/sweep_opcodes.py`
Expected: exit code 0 — no mismatches outside `KNOWN_LATENT`. This is the gate
on the `_verify` change; if the sweep reports a new mismatch, the extraction
changed behavior and must be investigated before committing. Note: this sweep
needs the hashcat binary. If `hashcat` is not on PATH, report that the gate
could not be run rather than claiming it passed.

- [ ] **Step 7: Lint, type-check, and commit**

```bash
uv run ruff format hashcat_rosetta/ tests/
uv run ruff check hashcat_rosetta/ tests/
uv run mypy hashcat_rosetta/
git add hashcat_rosetta/cli.py hashcat_rosetta/_verify.py tests/test_cli.py
git commit -m "refactor: extract _simulate_rule so the final word is read, not parsed"
```

---

### Task 2: Give `--explain` an optional value and validate the new combinations

**Files:**
- Modify: `hashcat_rosetta/cli.py:731` (the `--explain` option), `:824-861`
  (the explain dispatch and the FILE-required check)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: nothing from Task 1 (independent of `_simulate_rule`).
- Produces: module constant `_EXPLAIN_FROM_LOG: str` in `hashcat_rosetta/cli.py`,
  the sentinel `--explain`'s `flag_value` is set to. Task 3 checks
  `explain == _EXPLAIN_FROM_LOG` to decide whether to render log-driven
  explanation blocks.

**Background:** today `--explain` is `type=str` and its handler at line 824
returns before any debug-file work. Click's `is_flag=False, flag_value=...`
makes the value optional: `--explain c$1` binds the string, bare `--explain`
(end of argv, or followed by another `-`-prefixed token) binds `flag_value`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py`, after the existing `# --- --explain flag ---`
class:

```python
class TestExplainOptionalValue:
    """--explain takes an optional value: bare with a FILE, or a rule string."""

    def test_bare_explain_before_another_flag_is_the_sentinel(self, runner, debug_file):
        """`--explain --rules` must not swallow --rules as the explain value."""
        result = runner.invoke(main, [debug_file, "--explain", "--rules"])
        assert result.exit_code == 0
        assert "Top 10 Rules" in result.output

    def test_bare_explain_at_end_of_argv(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--rules", "--explain"])
        assert result.exit_code == 0
        assert "Top 10 Rules" in result.output

    def test_explain_with_value_still_explains_one_rule(self, runner):
        result = runner.invoke(main, ["--explain", "c$1", "--baseword", "admin"])
        assert result.exit_code == 0
        assert "Rule Explanation" in result.output
        assert "Admin1" in result.output

    def test_bare_explain_without_file_errors(self, runner):
        result = runner.invoke(main, ["--explain"])
        assert result.exit_code != 0
        assert "--explain needs a rule" in result.output

    def test_bare_explain_with_analyze_rules_errors(self, runner, rule_file):
        result = runner.invoke(main, [rule_file, "--analyze-rules", "--explain"])
        assert result.exit_code != 0
        assert "--analyze-rules" in result.output

    def test_baseword_with_bare_explain_warns(self, runner, debug_file):
        """--baseword is meaningless in log mode; say so instead of ignoring it."""
        result = runner.invoke(
            main, [debug_file, "--rules", "--explain", "--baseword", "admin"]
        )
        assert result.exit_code == 0
        assert "--baseword is ignored" in result.output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::TestExplainOptionalValue -v`
Expected: FAIL — `--explain` currently requires a value, so
`test_bare_explain_at_end_of_argv` fails on a Click usage error and the others
fail on missing output.

- [ ] **Step 3: Add the sentinel constant**

In `hashcat_rosetta/cli.py`, just below `_BANNER` (after line 22), add:

```python
# --explain takes an optional value. Bare, it means "explain the rules found in
# the debug FILE"; with a value it means "explain this rule string or rule
# file". The sentinel holds a NUL byte so no real rule or path can collide.
_EXPLAIN_FROM_LOG = "\x00explain-from-log"
```

- [ ] **Step 4: Make the option's value optional**

Replace the `--explain` option at line 731:

```python
@click.option(
    "--explain",
    is_flag=False,
    flag_value=_EXPLAIN_FROM_LOG,
    default=None,
    help=(
        "Explain what a hashcat rule does. Pass a rule string or a rule file; "
        "or pass it bare alongside a debug FILE to explain the rules in that log."
    ),
)
```

- [ ] **Step 5: Split the dispatch**

In `main`, replace the `if explain:` guard at line 824 with a guard that only
covers the value form, and add the new validation. The block from line 824
becomes:

```python
    # Rule-string / rule-file explanation: unchanged behavior, returns early.
    if explain is not None and explain != _EXPLAIN_FROM_LOG:
        if os.path.isfile(explain):
            ...  # existing rule-file branch, unchanged
        else:
            ...  # existing single-rule branch, unchanged
        return

    if explain == _EXPLAIN_FROM_LOG:
        if not file:
            click.echo(
                "Error: --explain needs a rule, a rule file, or a debug file argument",
                err=True,
            )
            sys.exit(1)
        if analyze_rules:
            click.echo(
                "Error: --explain cannot be combined with --analyze-rules "
                "(--analyze-rules reads a rule file, not a debug log)",
                err=True,
            )
            sys.exit(1)
        if baseword != "password":
            click.echo(
                "Note: --baseword is ignored with --explain on a debug file; "
                "basewords come from the log.",
                err=True,
            )
```

Leave the existing "Require file for other operations" check (lines 857-861)
in place — it is now unreachable for the sentinel case but still guards every
other flag combination.

Note for the implementer: `CliRunner()` in these tests mixes stderr into
`result.output` by default, which is why the error assertions read from
`result.output`. Do not change the `err=True` writes to satisfy a test.

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/test_cli.py::TestExplainOptionalValue -v`
Expected: PASS.

Run: `uv run pytest`
Expected: PASS — in particular `TestErrorPaths::test_missing_file` and every
existing `--explain` test must still pass unchanged.

- [ ] **Step 7: Lint, type-check, and commit**

```bash
uv run ruff format hashcat_rosetta/ tests/
uv run ruff check hashcat_rosetta/ tests/
uv run mypy hashcat_rosetta/
git add hashcat_rosetta/cli.py tests/test_cli.py
git commit -m "feat: let --explain take an optional value for debug-log mode"
```

---

### Task 3: Render explanation blocks under `--rules` and `--basewords`

**Files:**
- Modify: `hashcat_rosetta/cli.py` — add helpers near `_escape_bytes`, and hook
  into the `if rules:` block (currently lines 922-936) and the
  `if basewords:` block (currently lines 939-956)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `_simulate_rule(rule_str, baseword) -> tuple[list[str], str] | None`
  (Task 1) and `_EXPLAIN_FROM_LOG` (Task 2).
- Produces: no new public API.

**Background:** `DebugAnalyzer` exposes `analyzer.entries`, a list of dicts with
keys `baseword`, `rule`, `candidate`, and (mode 5) `wordlist`, in log order.
`analyzer.rule_stats[rule]["basewords"]` is a `set`, so it cannot supply a
stable representative baseword — walk `entries` instead. `get_baseword_detail(bw)`
returns `{"occurrences": [{"rule":..., "candidate":..., "matched":...}], ...}`
with occurrences in log order.

- [ ] **Step 1: Write the failing tests**

Add these fixtures near the existing ones at the top of `tests/test_cli.py`:

```python
@pytest.fixture
def debug_file_mismatch(tmp_path):
    """A log whose candidate disagrees with what the simulator produces."""
    path = tmp_path / "mismatch.txt"
    path.write_text("password c WRONG\npassword c WRONG\n")
    return str(path)


@pytest.fixture
def debug_file_non_ascii(tmp_path):
    """A log with a non-ASCII candidate, where byte-vs-codepoint differs."""
    path = tmp_path / "nonascii.txt"
    path.write_text("café c Café\ncafé c Café\n", encoding="utf-8")
    return str(path)
```

Add this class after `TestExplainOptionalValue`:

```python
class TestExplainFromDebugLog:
    def test_rules_explain_shows_steps_and_match(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--rules", "--explain"])
        assert result.exit_code == 0
        assert "baseword 'password' (from log)" in result.output
        assert "c: Capitalize" in result.output
        assert "hashcat produced: Password" in result.output
        assert "[match]" in result.output

    def test_bare_explain_defaults_to_the_rules_view(self, runner, debug_file):
        """A FILE plus bare --explain and no listing flag shows the rules view."""
        result = runner.invoke(main, [debug_file, "--explain"])
        assert result.exit_code == 0
        assert "Top 10 Rules" in result.output
        assert "c: Capitalize" in result.output

    def test_rules_without_explain_is_unchanged(self, runner, debug_file):
        result = runner.invoke(main, [debug_file, "--rules"])
        assert result.exit_code == 0
        assert "from log" not in result.output
        assert "Capitalize" not in result.output

    def test_mismatch_is_flagged(self, runner, debug_file_mismatch):
        result = runner.invoke(main, [debug_file_mismatch, "--rules", "--explain"])
        assert result.exit_code == 0
        assert "[MISMATCH]" in result.output
        assert "hashcat produced: WRONG" in result.output

    def test_non_ascii_is_not_flagged_as_mismatch(self, runner, debug_file_non_ascii):
        result = runner.invoke(main, [debug_file_non_ascii, "--rules", "--explain"])
        assert result.exit_code == 0
        assert "[unverified: non-ASCII]" in result.output
        assert "[MISMATCH]" not in result.output

    def test_unexplainable_rule_is_reported(self, runner, tmp_path):
        path = tmp_path / "unknown.txt"
        path.write_text("password Q Qpassword\npassword Q Qpassword\n")
        result = runner.invoke(main, [str(path), "--rules", "--explain"])
        assert result.exit_code == 0
        assert "no explanation available" in result.output
        assert "hashcat produced: Qpassword" in result.output

    def test_basewords_explain_shows_a_block_per_rule(self, runner, debug_file):
        result = runner.invoke(
            main, [debug_file, "--basewords", "--explain", "--min-occurrences", "2"]
        )
        assert result.exit_code == 0
        assert "c: Capitalize" in result.output
        assert "u: Uppercase all" in result.output
        assert "hashcat produced: PASSWORD" in result.output

    def test_basewords_explain_caps_rules_and_says_how_many_were_dropped(
        self, runner, debug_file
    ):
        """password has 3 rules in the fixture; --top 1 shows one and reports 2."""
        result = runner.invoke(
            main,
            [debug_file, "--basewords", "--explain", "--min-occurrences", "2", "--top", "1"],
        )
        assert result.exit_code == 0
        assert "... and 2 more rules" in result.output

    def test_export_still_written_and_free_of_explanations(self, runner, debug_file, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(main, [debug_file, "--export", str(out), "--explain"])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "explanation" not in json.dumps(data)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::TestExplainFromDebugLog -v`
Expected: FAIL — no explanation output is produced yet.

- [ ] **Step 3: Add the rendering helpers**

In `hashcat_rosetta/cli.py`, after `_escape_bytes` (line 77), add:

```python
def _match_marker(simulated: str, logged: str) -> str:
    """Compare a simulated candidate to the one hashcat logged.

    Returns "[match]", "[MISMATCH]", or "[unverified: non-ASCII]". The last case
    exists because DebugLogParser reads logs as UTF-8 while the simulator models
    a word as one code point per byte; for high-byte data the two
    representations differ legitimately, so a mismatch marker would be noise.
    """
    if not simulated.isascii() or not logged.isascii():
        return "[unverified: non-ASCII]"
    return "[match]" if simulated == logged else "[MISMATCH]"


def _explanation_lines(rule: str, baseword: str, candidate: str, indent: str) -> list[str]:
    """Render one explanation block: the baseword, each step, and the verdict."""
    lines = [f"{indent}baseword '{_escape_bytes(baseword)}' (from log)"]
    simulated = _simulate_rule(rule, baseword)
    if simulated is None:
        lines.append(f"{indent}  [!] no explanation available")
        lines.append(f"{indent}hashcat produced: {_escape_bytes(candidate)}")
        return lines
    steps, final = simulated
    for step in steps:
        lines.append(f"{indent}  {_escape_bytes(step)}")
    marker = _match_marker(final, candidate)
    lines.append(f"{indent}hashcat produced: {_escape_bytes(candidate)}  {marker}")
    return lines


def _first_entry_for_rule(analyzer: DebugAnalyzer, rule: str) -> dict | None:
    """First log entry using this rule — a stable representative baseword.

    rule_stats["basewords"] is a set, so it cannot provide stable ordering, and
    the paired candidate matters: it is what hashcat produced for that exact
    baseword.
    """
    for entry in analyzer.entries:
        if entry["rule"] == rule:
            return entry
    return None
```

- [ ] **Step 4: Hook into the `--rules` listing**

Replace the body of the `if rules:` echo loop (currently lines 935-936):

```python
        for i, (rule, count) in enumerate(rule_list, 1):
            click.echo(f"{i:2}. Rule: {rule:20} ({count})")
            if explain == _EXPLAIN_FROM_LOG:
                entry = _first_entry_for_rule(analyzer, rule)
                if entry is not None:
                    for line in _explanation_lines(
                        rule, entry["baseword"], entry["candidate"], "      "
                    ):
                        click.echo(line)
```

- [ ] **Step 5: Hook into the `--basewords` listing**

Inside the `for baseword, count in baseword_list:` loop, after the existing
`if detail:` block, add:

```python
            if explain == _EXPLAIN_FROM_LOG:
                bw_detail = analyzer.get_baseword_detail(baseword)
                occurrences = bw_detail["occurrences"] if bw_detail else []
                # One block per distinct rule, in log order, first candidate wins.
                seen: dict[str, str] = {}
                for occ in occurrences:
                    seen.setdefault(occ["rule"], occ["candidate"])
                shown = list(seen.items())[:top]
                for rule, candidate in shown:
                    click.echo(f"    Rule: {rule}")
                    for line in _explanation_lines(rule, baseword, candidate, "      "):
                        click.echo(line)
                dropped = len(seen) - len(shown)
                if dropped:
                    click.echo(f"    ... and {dropped} more rules")
```

- [ ] **Step 6: Make bare `--explain` default to the rules view**

The "Default behavior: show analysis summary" guard (line 884) currently reads:

```python
    if not rules and not basewords and not wordlists and not export:
```

A FILE plus bare `--explain` and no listing flag must show the rules view, not
the summary. Immediately before that guard, add:

```python
    # Bare --explain with no listing flag means "explain the top rules".
    if explain == _EXPLAIN_FROM_LOG and not rules and not basewords and not wordlists:
        rules = True
```

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/test_cli.py::TestExplainFromDebugLog -v`
Expected: PASS.

Run: `uv run pytest`
Expected: PASS — the whole suite, no regressions.

- [ ] **Step 8: Check the output by eye**

```bash
uv run hashcat-rosetta examples/sample_debug.txt --rules --explain --top 3
uv run hashcat-rosetta examples/sample_debug.txt --basewords --explain --top 2
```

Expected: indented step blocks under each rule, each ending in
`hashcat produced: ... [match]`. Confirm the indentation reads cleanly and no
line exceeds a normal terminal width by an absurd amount.

- [ ] **Step 9: Lint, type-check, and commit**

```bash
uv run ruff format hashcat_rosetta/ tests/
uv run ruff check hashcat_rosetta/ tests/
uv run mypy hashcat_rosetta/
git add hashcat_rosetta/cli.py tests/test_cli.py
git commit -m "feat: explain rules from a debug log under --rules and --basewords"
```

---

### Task 4: Document the new mode

**Files:**
- Modify: `hashcat_rosetta/cli.py` — the `main` docstring (lines 794-818)
- Modify: `README.md`
- Modify: `CLAUDE.md` — the "CLI Entry Points" section
- Modify: `CHANGELOG.md`
- Test: `tests/test_cli.py` (existing `TestHelpMatchesEntryPoint`)

**Interfaces:**
- Consumes: the CLI surface from Tasks 2 and 3.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Update the `main` docstring**

In the "Explain rules:" block of the docstring, add these two lines:

```
        hashcat-rosetta debug.txt --rules --explain
        hashcat-rosetta debug.txt --basewords --explain
```

Every example line must start with `hashcat-rosetta ` — `TestHelpMatchesEntryPoint`
fails the build on a bare `rosetta `.

- [ ] **Step 2: Update README.md and CLAUDE.md**

In `README.md`, find the section documenting `--explain` and add a short
subsection showing `hashcat-rosetta debug.txt --rules --explain` with a sample
output block copied from the real run in Task 3 Step 8 — do not invent output.
Mention the `[match]` / `[MISMATCH]` / `[unverified: non-ASCII]` markers and
that `--baseword` is ignored in this mode.

Note: `README.md` already has uncommitted local edits on this branch's base.
Do not revert them; add to the file.

In `CLAUDE.md`, under "CLI Entry Points", add to the command list:

```bash
hashcat-rosetta debug.txt --rules --explain       # explain top rules using log basewords
```

and extend the `cli.py` bullet under "Architecture" to note that `--explain` now
takes an optional value.

- [ ] **Step 3: Add a CHANGELOG entry**

Add under an `## [Unreleased]` heading (create it if absent), following the
existing entry style:

```markdown
### Added
- `--explain` now works against a debug log: `hashcat-rosetta debug.txt --rules --explain`
  explains each top rule using a baseword from the log and flags where the
  simulation disagrees with the candidate hashcat produced.
```

- [ ] **Step 4: Verify and commit**

```bash
uv run pytest tests/test_cli.py::TestHelpMatchesEntryPoint -v
uv run hashcat-rosetta --help
git add hashcat_rosetta/cli.py README.md CLAUDE.md CHANGELOG.md
git commit -m "docs: document explaining rules from a debug log"
```

---

## Self-Review

**Spec coverage:**
- CLI surface table → Task 2 (all six rows have a test).
- Output shape and indentation → Task 3 Steps 4, 5, 8.
- Representative baseword selection (first-seen from `entries`) → Task 3
  `_first_entry_for_rule`.
- Per-baseword cap with "and N more rules" → Task 3 Step 5, tested.
- Match / MISMATCH / non-ASCII markers → Task 3 `_match_marker`, three tests.
- `None` from `explain_rule` → Task 3 `_explanation_lines`, tested.
- `--analyze-rules` conflict, `--export` coexistence, `--baseword` note →
  Task 2 Step 5 and Task 3's export test.
- Accurate final word and the `_verify` switch → Task 1, gated on the sweep.
- Docs → Task 4.

**Type consistency:** `_simulate_rule` returns `tuple[list[str], str] | None`
in Task 1 and is consumed with that shape in Task 3. `_EXPLAIN_FROM_LOG` is
defined in Task 2 and compared with `==` in Tasks 2 and 3. `_explanation_lines`
takes `(rule, baseword, candidate, indent)` at both call sites.
