# Plan: byte-safe rule-file reading

## Context

`hashcat-rosetta --explain <rule-file>` crashes with `UnicodeDecodeError` on
real-world rule files. Reproducer:

```
uv run hashcat-rosetta --explain ~/projects/hashcat/rules/BARRAGE.rule
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xba in position 124
```

33,262 of BARRAGE.rule's 32.4M lines are not valid UTF-8. They are not
corrupt. Hashcat rule files are byte-oriented: any byte 0x00-0xFF is a legal
literal argument to an opcode. Line 513,683 is `o1\xba` — "overwrite position
1 with byte 0xBA".

The codebase already models rules as one Unicode code point per byte:
`explain_rule` transforms code points 0-255, and `cli.py:_escape_bytes`
exists specifically to render code points 0x80-0xFF back as `\xNN` on output
rather than letting Python UTF-8-encode them into multibyte sequences. The
file readers are the only layer that disagrees with that model.

Three distinct defects, all confirmed by experiment before this plan was
written:

1. **`cli.py:828`** opens the rule file with `encoding="utf-8"` → hard crash.
   Read as latin-1, the same line yields
   `o1\xba: Overwrite pos 1 with '\xba' → password → p\xbassword`.
2. **`cli.py:830`** uses `raw_line.strip()`, which deletes a trailing space
   that is a legal opcode argument:
   - `explain_rule('$ ')` → `["$ : Append ' ' → pw → pw "]`
   - `explain_rule('$ '.strip())` → `None`
3. **`cli.py:835` and `cli.py:839`** echo `rule_line` without
   `_escape_bytes`, so `o1\xba` reaches stdout as the bytes
   `6f 31 c2 ba` — a two-byte UTF-8 sequence misrepresenting a single-byte
   rule. This is exactly what `_escape_bytes` was written to prevent, just
   missed at these two call sites.

The same two bugs (bad encoding + `strip()`) recur in
`formatting.py:95,97` (`--analyze-rules`) and `parser.py:92,98,104` (debug
log parser). There they use `errors="ignore"`, which does not crash — it
silently deletes the high byte and then blames the rule:

```
$ printf 'o1\xba\n$ \n' > /tmp/edge.rule
$ hashcat-rosetta /tmp/edge.rule --analyze-rules
Incomplete 2-arg opcode 'o' at position 0 in rule 'o1' - missing parameter(s), skipping
Incomplete 1-arg opcode '$' at position 0 in rule '$' - missing parameter, skipping
No opcodes found
```

Both rules were valid. Silent corruption is worse than the crash.

## Global Constraints

- **TDD is mandatory.** For every behavior change: write the failing test
  first, run it, confirm it fails for the expected reason, then fix. A test
  that passes before the fix proves nothing and must be rewritten.
- **Use `latin-1`, not `errors="surrogateescape"` or `errors="ignore"`**, for
  reading rule and debug files. latin-1 is a total bijection between bytes
  0-255 and code points 0-255, which is the exact model `explain_rule` and
  `_escape_bytes` already assume. Surrogates would leak into the transform
  functions and raise on comparison; `ignore` silently deletes data.
- **Never widen `strip()` to `rstrip()` alone where leading bytes matter.**
  Strip only the line terminator: `rstrip("\r\n")`.
- Do not change `explain_rule`, `_escape_bytes`, or any opcode semantics.
  This plan changes file reading and output escaping only.
- Line length 100. `uv run ruff check`, `uv run ruff format --check`,
  `uv run mypy hashcat_rosetta/`, and `uv run pytest` must all pass.
- Do not add new dependencies.
- Existing tests must keep passing. If an existing test asserts the buggy
  behavior, say so in your report rather than quietly rewriting it.

## Task 1: byte-safe fixture and `--explain` file reading

Create `tests/fixtures/high_byte_rules.py` exposing a pytest fixture that
writes a rule file as **raw bytes** to a tmp_path and returns the path.
Write it with `Path.write_bytes`, not as a committed text file — a committed
file with high bytes is liable to be "helpfully" re-encoded by an editor or
a linter, which would silently defeat every test in this plan. Put a comment
saying exactly that.

Fixture content, in this order, as bytes:

```
b"o1\xba\n"           # BARRAGE line 513683: overwrite pos 1 with byte 0xBA
b"$ \n"               # append a literal space - a legal argument
b"i0\xd0 i1\xbc\n"    # BARRAGE line 1119716: two high-byte args
b"# comment\n"
b"\n"
b"c\n"                # a plain ASCII rule, as a control
```

Then fix `hashcat_rosetta/cli.py` lines 828-839. Write these tests first,
in `tests/test_cli.py`, using the existing `CliRunner` style in that file:

1. `--explain <fixture>` exits 0 and stdout contains
   `o1\xba: Overwrite pos 1`. Currently raises `UnicodeDecodeError`.
2. `--explain <fixture>` output contains `Append ' '` and the transformed
   result retains its trailing space. Currently the line is skipped
   entirely because `strip()` reduces `$ ` to `$`, which `explain_rule`
   rejects as incomplete.
3. **Assert on bytes, not on the decoded string.** Capture output and assert
   `b"o1\\xba"` is present and the raw sequence `b"\xc2\xba"` is absent. A
   str-level assertion passes today and proves nothing — the point of this
   test is that the echoed rule is escaped, and `str` comparison cannot see
   the difference between escaped and UTF-8-encoded.
4. The `# comment`, the blank line, and the `c` control line behave as
   before: comment and blank skipped, `c` explained.

Fixes: `encoding="latin-1"` at line 828; `raw_line.rstrip("\r\n")` in place
of `raw_line.strip()` at line 830; wrap `rule_line` in `_escape_bytes` at
both line 835 and line 839.

Note line 830's `if not rule_line` check still needs to skip the blank line,
and the `startswith("#")` check must still work — verify with test 4 rather
than by inspection.

## Task 2: byte-safe `--analyze-rules` and debug-log parsing

Two readers, same two bugs, no crash — silent data loss instead. Fix both.

**`hashcat_rosetta/formatting.py:95,97`** (`--analyze-rules` path). Failing
test first: `--analyze-rules` on the Task 1 fixture reports the `o`, `$`,
and `i` opcodes with their arguments intact, instead of the current
"Incomplete … opcode … skipping" plus "No opcodes found". Fix: `latin-1`,
and `rstrip("\r\n")` instead of `strip()`.

**`hashcat_rosetta/parser.py:92,98,104`** (debug log parser). Assert this
separately from formatting.py — the parser additionally runs
`_detect_format` and `_resolve_mode` over `sample`, which is itself built
with `.strip()` at line 98, so the space-stripping bug has a second
independent effect here on format and mode detection.

Failing tests first:

1. A mode-4 debug line whose baseword ends in a space still parses into its
   correct fields, and the trailing space survives into the parsed
   `baseword`.
2. A debug line containing a high byte in the rule field parses with the
   byte intact rather than deleted.
3. A mode-5 line whose baseword ends in a space still resolves to mode 5 —
   i.e. field-count detection is not thrown off.

Fix: `encoding="latin-1"` with no `errors=` at line 92, and strip only the
line terminator at 98 and 104. Format/mode detection needs the *content*
of the sample lines, so keep detection semantics otherwise unchanged.

If removing `errors="ignore"` makes some other existing test fail, that is
a real finding — report it, do not re-add `errors="ignore"`.

## Task 3: regression test against the real corpus

Add an integration test, marked `@pytest.mark.integration`, that
`pytest.skip`s when `~/projects/hashcat/rules/BARRAGE.rule` is absent (it is
not in the repo and must never be added — it is 32.4M lines).

The test reads the whole file as latin-1 and asserts:

1. Zero decode errors across all lines.
2. Zero lines where `rstrip("\r\n")` and `strip()` differ in a way that
   changes `explain_rule`'s verdict from non-`None` to `None`. This is the
   space-argument bug, measured against real data rather than a fixture.

Report the actual counts in your report — how many lines are non-UTF-8 and
how many have significant trailing whitespace. Expected: 33,262 non-UTF-8.
If your number differs, investigate and say so; do not adjust the assertion
to match whatever you observe.

This is the test that would have caught the original crash. Keep it cheap
enough to run: a single pass, no per-line subprocess calls, and do not
invoke the hashcat binary.
