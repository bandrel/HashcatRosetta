# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HashcatRosetta analyzes hashcat debug mode 4 output files to identify efficient password cracking rules and baseword frequency patterns. It parses both space-separated (modern) and colon-separated (older) hashcat debug formats.

## Commands

```bash
# Install dependencies
uv sync

# Run CLI
uv run hashcat-rosetta --help
uv run python -m hashcat_rosetta --help

# Run tests
uv run pytest
uv run pytest tests/test_analyzer.py::TestClassName::test_name  # single test
uv run pytest --cov=hashcat_rosetta tests/

# Lint and format
uv run ruff check hashcat_rosetta/ tests/
uv run ruff format hashcat_rosetta/ tests/

# Type check
uv run mypy hashcat_rosetta/

# Run per-opcode correctness sweep (systematic, deterministic)
uv run python scripts/sweep_opcodes.py
```

## Architecture

The package (`hashcat_rosetta/`) has two analysis paths that share a common parser:

- **`parser.py`** - `DebugLogParser` parses debug mode 4 files (auto-detects space vs colon format). `RuleParser` tokenizes individual hashcat rules and computes complexity scores.
- **`debug_analyzer.py`** - `DebugAnalyzer` wraps `DebugLogParser` and computes rule/baseword statistics (frequency, unique basewords per rule, unique candidates). This is the main entry point for debug file analysis.
- **`analyzer.py`** - `RuleAnalyzer` wraps `RuleParser` for static rule analysis (complexity, efficiency scoring, characteristics extraction). Does not require debug output - analyzes rules in isolation.
- **`formatting.py`** - Rule opcode descriptions and display formatting for the `analyze-rules` CLI command.
- **`cli.py`** - Single Click command (`main`) with flags for different output modes (`--rules`, `--basewords`, `--export`, `--explain`, `--analyze-rules`). Also contains `explain_rule()` which simulates rule application step-by-step. Entry point registered as `hashcat-rosetta` in pyproject.toml.
- **`scripts/sweep_opcodes.py`** - Systematic per-opcode correctness sweep. Generates ~230 rules covering every opcode in `_DEFAULT_IMPLEMENTED` against a canonical arg grid, runs them via `_verify.verify_corpus`, and emits a per-opcode matrix to `reports/opcode-sweep.md`. CI job `opcode-sweep` runs this on every PR; mismatches outside `KNOWN_LATENT` fail the build.

The public API exports `RuleAnalyzer`, `RuleParser`, `DebugLogParser`, and `DebugAnalyzer` from `__init__.py`.

## Key Conventions

- Build system: hatchling
- Line length: 100 (configured in pyproject.toml for ruff)
- Python: >=3.10
- Dependencies: click
- Dev dependencies: pytest, pytest-cov, ruff, mypy (in `[project.optional-dependencies] dev`)
- Test paths configured to `tests/` directory
- Tests marked with `@pytest.mark.integration` require the hashcat binary

## CLI Entry Points

The CLI uses a single Click command with multiple flags rather than subcommands (despite the README showing subcommand-style usage). The actual interface is:

```bash
hashcat-rosetta FILE                              # show analysis summary
hashcat-rosetta FILE --rules --metric frequency   # top rules
hashcat-rosetta FILE --basewords --detail         # baseword analysis
hashcat-rosetta FILE --export report.json         # export report
hashcat-rosetta --explain "c$1" --baseword admin  # explain a rule
hashcat-rosetta rules.txt --analyze-rules        # analyze rule file opcodes
```
