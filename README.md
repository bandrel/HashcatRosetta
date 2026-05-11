```
 _   _           _          _   ____                _   _        
| | | | __ _ ___| |__   ___| |_|  _ \ ___  ___  ___| |_| |_ __ _ 
| |_| |/ _` / __| '_ \ / __| __| |_) / _ \/ __|/ _ \ __| __/ _` |
|  _  | (_| \__ \ | | | (__| |_|  _ < (_) \__ \  __/ |_| || (_| |
|_| |_|\__,_|___/_| |_|\___|\__|_| \_\___/|___/\___|\__|\__\__,_|
                                                                  
    Decode the Rosetta Stone of Password Cracking Rules
```

# HashcatRosetta

A Python project designed to analyze hashcat debug mode 4 output files to identify the most efficient rules and track baseword frequency patterns used during password cracking attacks.

## Features

- **Parse hashcat debug files** (--debug-mode 4 format) with automatic baseword and rule extraction
- **Track rule efficiency** by multiple metrics:
  - Application frequency (most commonly applied rules)
  - Baseword spread (rules applied to most unique basewords)
  - Candidate generation (rules producing most unique candidates)
- **Monitor baseword patterns** with detailed occurrence logs and statistics
- **Generate detailed reports** with rule and baseword analytics
- **Export analysis** to JSON or CSV formats for further processing
- **Command-line interface** for easy analysis and reporting

## Installation

### From source

```bash
git clone https://github.com/bandrel/HashcatRosetta.git
cd HashcatRosetta
pip install -e .
```

### With development dependencies

```bash
pip install -e ".[dev]"
```

### Using with uv (recommended)

If you're using [uv](https://github.com/astral-sh/uv), you can run without installation:

```bash
# Clone the repository
git clone https://github.com/bandrel/HashcatRosetta.git
cd HashcatRosetta

# Run as a module (recommended)
uv run python -m hashcat_rosetta --help

# Or use the installed command
uv run rosetta --help
```

## Quick Start

### Analyzing Debug Files

Analyze a hashcat debug file (shows summary by default):
```bash
rosetta debug_output.txt
```

Show top rules by frequency:
```bash
rosetta debug_output.txt --rules --top 10 --metric frequency
```

Show top rules by other metrics:
```bash
rosetta debug_output.txt --rules --metric basewords
rosetta debug_output.txt --rules --metric candidates
```

Show basewords appearing multiple times:
```bash
rosetta debug_output.txt --basewords --top 10
```

Show detailed baseword analysis:
```bash
rosetta debug_output.txt --basewords --top 10 --detail --min-occurrences 2
```

Export complete analysis report:
```bash
rosetta debug_output.txt --export report.json --format json
rosetta debug_output.txt --export report.csv --format csv
```

### Explaining Rules

Explain what a hashcat rule does step-by-step:
```bash
rosetta --explain "c$1" --baseword admin
rosetta --explain "u$!" --baseword myword
```

### Using the Python API

```python
from hashcat_rosetta import DebugAnalyzer

analyzer = DebugAnalyzer()

# Analyze a debug file
result = analyzer.analyze_debug_file('debug_output.txt')
print(f"Total entries: {result['total_entries']}")
print(f"Unique rules: {result['unique_rules']}")
print(f"Unique basewords: {result['unique_basewords']}")

# Get top rules by frequency
top_rules = analyzer.get_top_rules_by_frequency(10)
for rule, count in top_rules:
    print(f"Rule: {rule}, Applications: {count}")

# Get top basewords
top_basewords = analyzer.get_top_basewords_by_frequency(10)
for baseword, count in top_basewords:
    print(f"Baseword: {baseword}, Occurrences: {count}")

# Get basewords appearing multiple times
frequent_basewords = analyzer.get_basewords_with_min_occurrences(2)
print(f"Basewords appearing 2+ times: {len(frequent_basewords)}")

# Get detailed information about a specific baseword
detail = analyzer.get_baseword_detail('password')
print(f"Rules applied to 'password': {detail['unique_rules']}")
print(f"Occurrences: {len(detail['occurrences'])}")

# Export complete analysis
export = analyzer.export_to_dict()
```

## Debug File Format

The analyzer automatically detects and supports both hashcat debug output formats:

### Space-separated format (modern hashcat)

```
baseword rule candidate
password c P@ssword
password u PASSWORD
admin l admin
letmein [ etmein
```

Each line contains three **space-separated** fields:
- **baseword**: The original dictionary word
- **rule**: The hashcat rule applied
- **candidate**: The resulting password candidate after applying the rule

### Colon-separated format (older hashcat versions)

```
baseword:rule:candidate
COMPUTER:} } } } t:retupmoc
EXAMPLE:sa@ se3 so0:3x@mpl3
admin:$1 $5 c ^@:@Admin15
```

Each line contains three **colon-separated** fields with the same meaning as above.

**Note**: The analyzer automatically detects which format your file uses. No manual configuration needed!

### Generating debug files

Generate debug output with hashcat using `--debug-mode 4`:

```bash
# Modern hashcat (produces space-separated format)
hashcat -m [hash-mode] -a 0 --debug-mode 4 -r rules.rule hashes.txt wordlist.txt > debug.txt

# Older hashcat versions (produces colon-separated format)  
hashcat -m [hash-mode] -a 0 --debug-mode=4 -r rules.rule hashes.txt wordlist.txt > debug.txt
```

**Important**: Only use `--debug-mode 4`. Other debug modes (1-3) produce different output formats that are not compatible with this analyzer.

## Project Structure

```
HashcatRosetta/
├── hashcat_rosetta/          # Main package
│   ├── __init__.py           # Package initialization and public API
│   ├── __main__.py           # Module entry point (python -m hashcat_rosetta)
│   ├── parser.py             # Rule and debug log parsing
│   ├── analyzer.py           # Static rule analysis logic
│   ├── debug_analyzer.py     # Debug file analysis logic
│   ├── formatting.py         # Rule opcode descriptions and display
│   └── cli.py                # Command-line interface
├── tests/                    # Test suite
│   ├── test_analyzer.py      # Tests for analyzers and parsers
│   ├── test_cli.py           # CLI interface tests
│   ├── test_edge_cases.py    # Edge case and regression tests
│   ├── test_fixes.py         # Bug fix verification tests
│   └── test_rule_matrix.py   # Rule matrix tests
├── pyproject.toml            # Python packaging and tool config
├── LICENSE                   # MIT license
└── README.md                 # This file
```

## Development

### Running tests

```bash
pytest
```

### Running with coverage

```bash
pytest --cov=hashcat_rosetta tests/
```

### Linting and formatting

```bash
ruff check hashcat_rosetta/ tests/
ruff format hashcat_rosetta/ tests/
```

## Understanding the Analysis

### Rule Efficiency Metrics

**Frequency**: How many times a rule was applied across the debug file. Rules with high frequency are the most commonly used.

**Unique Basewords**: How many different basewords a rule was applied to. Rules affecting more diverse basewords may have broader applicability.

**Unique Candidates**: How many unique candidate passwords a rule generated. Rules generating more unique candidates may be more valuable for password cracking.

### Baseword Patterns

The analyzer tracks every occurrence of each baseword, including:
- Which rules were applied
- What candidates were generated
- The order of operations

This helps identify:
- Most frequently used dictionary words
- Which rules are most effective on specific basewords
- Patterns in word transformation across your attack

## Commands Reference

```
rosetta FILE                                  Show analysis summary
rosetta FILE --rules --metric frequency       Show top rules by metric
rosetta FILE --basewords --detail             Show baseword analysis
rosetta FILE --export report.json             Export analysis report
rosetta --explain "c$1" --baseword admin      Explain a rule step-by-step
rosetta rules.txt --analyze-rules             Analyze rule file opcodes
```

## Advanced Usage

### Filtering basewords by minimum occurrences

```bash
rosetta debug.txt --basewords --min-occurrences 5
```

### Getting detailed metrics for a specific baseword

```python
analyzer = DebugAnalyzer()
analyzer.analyze_debug_file('debug.txt')

detail = analyzer.get_baseword_detail('password')
print(f"Baseword: {detail['baseword']}")
print(f"Occurrences: {detail['total_occurrences']}")
print(f"Rules used: {detail['unique_rules']}")
print(f"Candidates: {detail['unique_candidates']}")

for occurrence in detail['occurrences']:
    print(f"  Rule: {occurrence['rule']} -> {occurrence['candidate']}")
```

### Getting statistics summary

```python
rule_stats = analyzer.get_rule_statistics_summary()
baseword_stats = analyzer.get_baseword_statistics_summary()

print(f"Total rules: {rule_stats['total_rules']}")
print(f"Average applications: {rule_stats['avg_applications_per_rule']:.2f}")
print(f"Total basewords: {baseword_stats['total_basewords']}")
```

## Troubleshooting

### Command not found errors with uv

**Do not use**: `uv run hashcat_rosetta` (this won't work)

**Use instead**:
```bash
# Method 1: Use the CLI command name
uv run rosetta debug.txt

# Method 2: Run as a Python module
uv run python -m hashcat_rosetta debug.txt
```

**Why?** `hashcat_rosetta` is the Python package name (for imports), while `rosetta` is the CLI command name (for running). The package name `hashcat_rosetta` is not executable on its own.

### ImportError with relative imports

If you see `ImportError: attempted relative import with no known parent package`, make sure you're running the package as a module with `-m`:

```bash
python -m hashcat_rosetta   # Correct
python hashcat_rosetta      # Won't work
```

## Configuration

Edit `pyproject.toml` to customize:
- Project version
- Dependencies
- Development tool configurations
- Entry points

## Contributing

1. Create a feature branch
2. Make your changes
3. Write/update tests
4. Run tests and linting
5. Submit a pull request

## Version History

### v0.3.0
- Implement `a` (append memorized), `e` (title-case w/ separator), `v` (toggle every N chars), `(`/`)` (first/last char filters)
- Refresh opcode descriptions to match hashcat source
- Add private `_verify` harness library and `verify_rule` / `verify_corpus` API
- Add baseword corpus + accuracy smoke parametrized across it
- CI: add per-PR accuracy smoke + nightly full verification
- CI fixes:
  - Bump hashcat-utils pin to post-v1.9 (Makefile now builds `bin/*.bin`)
  - Strip trailing whitespace from generated rules (hashcat-utils format change)
  - Skip rules using opcodes hashcat `--stdout` can't oracle (M, X, JtR-only opcodes, truncated opcodes, OOB positions)
  - Preserve baseword whitespace through verification (`_extract_final` no longer `.strip()`s)
  - Treat empty result / empty baseword as parity rejections
  - Per-call `--session` to avoid hashcat 6.2.x single-instance lock under thread parallelism
  - Prewarm POCL kernel cache before parallel pool
  - Scope nightly to fit POCL runtime budget on `ubuntu-latest`

### v0.2.0
- Apply QA review fixes across parser and analyzer
- Add comprehensive test suite (rule matrix, edge cases, CLI, fixes)
- Implement missing opcodes (M, X, =, B) and add `verify_rules.py` validation script
- Fix incorrect opcode documentation against hashcat source
- Add hashcat-utils integration tests
- Add pytest pre-commit hook

## License

MIT License - see LICENSE file for details

## References

- [Hashcat Rule-based Attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [Password Cracking Techniques](https://en.wikipedia.org/wiki/Password_cracking)
