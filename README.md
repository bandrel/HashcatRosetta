```
 _   _           _               _   ____                _   _        
| | | | __ _ ___| |__   ___ __ _| |_|  _ \ ___  ___  ___| |_| |_ __ _ 
| |_| |/ _` / __| '_ \ / __/ _` | __| |_) / _ \/ __|/ _ \ __| __/ _` |
|  _  | (_| \__ \ | | | (_| (_| | |_|  _ < (_) \__ \  __/ |_| || (_| |
|_| |_|\__,_|___/_| |_|\___\__,_|\__|_| \_\___/|___/\___|\__|\__\__,_|
                                                                  
    Decode the Rosetta Stone of Password Cracking Rules
```

# HashcatRosetta

A Python project designed to analyze hashcat debug mode 4 and mode 5 output files to identify the most efficient rules and track baseword frequency patterns used during password cracking attacks.

## Features

- **Parse hashcat debug files** (`--debug-mode 4` and `--debug-mode 5`) with automatic baseword and rule extraction
- **Attribute candidates to source wordlists** (mode 5) for per-wordlist statistics
- **Track rule efficiency** by multiple metrics:
  - Application frequency (most commonly applied rules)
  - Baseword spread (rules applied to most unique basewords)
  - Candidate generation (rules producing most unique candidates)
- **Monitor baseword patterns** with detailed occurrence logs and statistics
- **Generate detailed reports** with rule and baseword analytics
- **Export analysis** to JSON or CSV formats for further processing
- **Command-line interface** for easy analysis and reporting

## Installation

### Using with uv (recommended)

If you're using [uv](https://github.com/astral-sh/uv), you can run without installation:

```bash
# Clone the repository
git clone https://github.com/bandrel/HashcatRosetta.git
cd HashcatRosetta

# Run as a module (recommended)
uv run python -m hashcat_rosetta --help

# Or use the installed command
uv run hashcat-rosetta --help
```

### From source

```bash
uv tool install git+https://github.com/bandrel/HashcatRosetta.git
```

### With development dependencies

The dev tools live in the `dev` [dependency group](https://peps.python.org/pep-0735/).

```bash
# With uv (installs the dev group by default)
uv sync

# With pip (25.1+)
pip install -e . --group dev
```

## Quick Start

### Analyzing Debug Files

Analyze a hashcat debug file (shows summary by default):
```bash
hashcat-rosetta debug_output.txt
```

Show top rules by frequency:
```bash
hashcat-rosetta debug_output.txt --rules --top 10 --metric frequency
```

Show top rules by other metrics:
```bash
hashcat-rosetta debug_output.txt --rules --metric basewords
hashcat-rosetta debug_output.txt --rules --metric candidates
```

Show basewords appearing multiple times:
```bash
hashcat-rosetta debug_output.txt --basewords --top 10
```

Show top wordlists (debug mode 5 only):
```bash
hashcat-rosetta debug_output.txt --wordlists --top 10
```

Show detailed per-wordlist statistics (unique basewords, candidates, and rules):
```bash
hashcat-rosetta debug_output.txt --wordlists --top 10 --detail
```

The `--wordlists` output mirrors `--rules`: a `Top N Wordlists` header followed by
numbered `Wordlist: <name> (<count>)` lines. When a mode-5 file is analyzed without
any output flags, the default summary also includes a **Wordlist Statistics** section.

Force a specific debug mode instead of auto-detecting it:
```bash
hashcat-rosetta debug_output.txt --debug-mode 5 --wordlists
```

Show detailed baseword analysis:
```bash
hashcat-rosetta debug_output.txt --basewords --top 10 --detail --min-occurrences 2
```

Export complete analysis report:
```bash
hashcat-rosetta debug_output.txt --export report.json --format json
hashcat-rosetta debug_output.txt --export report.csv --format csv
```

### Explaining Rules

Explain what a hashcat rule does step-by-step:
```bash
hashcat-rosetta --explain "c$1" --baseword admin
hashcat-rosetta --explain "u$!" --baseword myword
```

### Generating Masks with Natural Language

Generate hashcat masks from English descriptions using a local LLM:

```bash
hashcat-rosetta --mask "The word 'Summer' followed by six digits."
```

Output:
```
Mask Suggestions for: 'The word 'Summer' followed by six digits.'
======================================================================

1. Summer?d?d?d?d?d?d
   literal "Summer", then 6 × digit → 1,000,000 candidates
   Why: matches the literal word followed by a 6-digit number
```

Save the generated mask to a file:
```bash
hashcat-rosetta --mask "The word 'Summer' followed by six digits." -o masks.hcmask
```

Generate masks from other descriptions:
```bash
hashcat-rosetta --mask "a capitalized season, two digits, and a special char"
hashcat-rosetta --mask "year 2020-2025 followed by exclamation or question mark"
```

The mask generation feature uses a local Ollama server running an OpenAI-compatible chat
endpoint. By default, it connects to `http://localhost:11434` and uses the model
`qwen3.6:35b-a3b`. These can be configured via environment variables or CLI flags:

```bash
# Using environment variables
OLLAMA_HOST=http://192.168.1.100:11434 OLLAMA_MODEL=llama2:70b \
  hashcat-rosetta --mask "your description here"

# Using CLI flags (override environment variables)
hashcat-rosetta --mask "your description" --ollama-host http://custom.host:11434 --model llama2
```

**Security note:** Mask descriptions are sent only to the Ollama endpoint you configure
(`localhost` by default, or wherever `--ollama-host`/`OLLAMA_HOST` points) — never to a
cloud provider. The OpenAI SDK is used purely as an HTTP client against that endpoint;
no data or API key is ever transmitted to `api.openai.com`.

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

### Colon-separated format (hashcat's native format)

```
baseword:rule:candidate
COMPUTER:} } } } t:retupmoc
EXAMPLE:sa@ se3 so0:3x@mpl3
admin:$1 $5 c ^@:@Admin15
```

Each line contains three **colon-separated** fields:
- **baseword**: The original dictionary word
- **rule**: The hashcat rule applied
- **candidate**: The resulting password candidate after applying the rule

hashcat has always emitted this format (`src/debugfile.c` writes `orig`, `:`, `rule`, `:`, `mod`).

### Space-separated format (legacy)

```
baseword rule candidate
password c P@ssword
password u PASSWORD
admin l admin
letmein [ etmein
```

Each line contains three **space-separated** fields with the same meaning as above. This is an older, legacy format that this parser also accepts.

**Note**: The analyzer automatically detects which format your file uses. No manual configuration needed!

### Debug mode 5 format (wordlist attribution)

Hashcat `--debug-mode 5` adds a trailing **wordlist** field to each colon-separated line:

```
baseword:rule:candidate:wordlist
password:c:P@ssword:/opt/wordlists/rockyou.txt
admin:l:admin:/opt/wordlists/rockyou.txt
letmein:[:etmein:<stdin>
```

Each line contains four fields:
- **baseword**: The original dictionary word
- **rule**: The hashcat rule applied
- **candidate**: The resulting password candidate
- **wordlist**: The source dictionary path, or a sentinel (`<stdin>`, `<generic>`, `<none>`) when hashcat has no path to report

Mode 5 unlocks the `--wordlists` output and a **Wordlist Statistics** section in the
default summary. Mode-4 analysis is unchanged.

### Choosing the debug mode

By default the analyzer auto-detects the mode by counting fields. Use `--debug-mode`
to force interpretation:

```bash
hashcat-rosetta debug.txt --debug-mode auto   # default: detect from field count
hashcat-rosetta debug.txt --debug-mode 4      # force mode 4
hashcat-rosetta debug.txt --debug-mode 5      # force mode 5
```

`--debug-mode` applies to debug-file analysis only (not `--analyze-rules`).

**Windows path limitation**: Hashcat does not escape colons, so basewords, candidates,
and Windows wordlist paths (e.g. `C:\wordlists\rockyou.txt`) may contain `:`. The parser
assumes the trailing wordlist field contains no colon, which holds for Linux paths and the
sentinels but not for Windows drive-letter paths. Forcing `--debug-mode 5` mitigates this
by treating everything after the candidate as the wordlist field.

### Generating debug files

Generate debug output with hashcat using `--debug-mode 4` or `--debug-mode 5`:

```bash
# Mode 4 (baseword rule candidate)
hashcat -m [hash-mode] -a 0 --debug-mode 4 -r rules.rule hashes.txt wordlist.txt > debug.txt

# Mode 5 (baseword:rule:candidate:wordlist — adds source wordlist attribution)
hashcat -m [hash-mode] -a 0 --debug-mode 5 -r rules.rule hashes.txt wordlist.txt > debug.txt
```

**Important**: Use `--debug-mode 4` or `--debug-mode 5`. Other debug modes (1-3) produce different output formats that are not compatible with this analyzer.

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
hashcat-rosetta FILE                                  Show analysis summary
hashcat-rosetta FILE --rules --metric frequency       Show top rules by metric
hashcat-rosetta FILE --basewords --detail             Show baseword analysis
hashcat-rosetta FILE --wordlists --detail             Show wordlist analysis (mode 5)
hashcat-rosetta FILE --debug-mode 5 --wordlists       Force mode 5, show wordlists
hashcat-rosetta FILE --export report.json             Export analysis report
hashcat-rosetta --explain "c$1" --baseword admin      Explain a rule step-by-step
hashcat-rosetta rules.txt --analyze-rules             Analyze rule file opcodes
```

## Advanced Usage

### Filtering basewords by minimum occurrences

```bash
hashcat-rosetta debug.txt --basewords --min-occurrences 5
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
uv run hashcat-rosetta debug.txt

# Method 2: Run as a Python module
uv run python -m hashcat_rosetta debug.txt
```

**Why?** `hashcat_rosetta` is the Python package name (for imports), while `hashcat-rosetta` is the CLI command name (for running). The package name `hashcat_rosetta` is not executable on its own.

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

See [CHANGELOG.md](CHANGELOG.md). It is the single record of what changed in
each release; this section used to duplicate it, which is a good way to end up
with two histories that disagree.

## License

MIT License - see LICENSE file for details

## References

- [Hashcat Rule-based Attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [Password Cracking Techniques](https://en.wikipedia.org/wiki/Password_cracking)
