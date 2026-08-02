#!/usr/bin/env python3
"""Orchestration script: run all five validation layers and write SUMMARY.md.

Usage:
    uv run python scripts/run_validation.py [--no-oracle] [--quiet]

Options:
    --no-oracle  Skip Layer 1 (oracle tests; requires hashcat + generate-rules.bin)
    --quiet      Suppress per-layer pytest output; only show the final summary
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Project root — works regardless of cwd
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
REPORTS_DIR = PROJECT_ROOT / "reports" / "validation"

# ANSI colour codes (disabled automatically when not a tty)
_USE_COLOUR = sys.stdout.isatty()


def _colour(text: str, code: str) -> str:
    if not _USE_COLOUR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return _colour(text, "32")


def red(text: str) -> str:
    return _colour(text, "31")


def yellow(text: str) -> str:
    return _colour(text, "33")


# ---------------------------------------------------------------------------
# Layer definitions
# ---------------------------------------------------------------------------
@dataclass
class Layer:
    number: int
    name: str
    pytest_args: list[str]
    skip_if_no_oracle: bool = False


LAYERS: list[Layer] = [
    Layer(
        number=1,
        name="Oracle",
        pytest_args=["tests/test_validation_oracle.py", "-m", "validation"],
        skip_if_no_oracle=True,
    ),
    Layer(
        number=2,
        name="Parser",
        pytest_args=["tests/test_parser_property.py"],
    ),
    Layer(
        number=3,
        name="Statistics",
        pytest_args=["tests/test_statistics_property.py"],
    ),
    Layer(
        number=4,
        name="Metadata",
        pytest_args=["tests/test_opcode_metadata.py"],
    ),
    Layer(
        number=5,
        name="Analyzer",
        pytest_args=["tests/test_analyzer.py::TestRuleAnalyzerInvariants"],
    ),
]

# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_SKIPPED = "SKIPPED"


@dataclass
class LayerResult:
    layer: Layer
    status: str  # STATUS_PASS | STATUS_FAIL | STATUS_SKIPPED
    detail: str  # e.g. "41 tests" or "hashcat not available"
    output: str  # combined stdout+stderr from pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_COUNT_RE = re.compile(
    r"(\d+)\s+passed"
    r"(?:,\s+(\d+)\s+failed)?"
    r"(?:,\s+(\d+)\s+xfailed)?"
    r"(?:,\s+(\d+)\s+skipped)?",
)


def _parse_counts(output: str) -> str:
    """Return a human-readable test-count string from pytest summary output."""
    # Search the last few lines where pytest prints the summary
    for line in reversed(output.splitlines()):
        m = _COUNT_RE.search(line)
        if m:
            passed = int(m.group(1))
            failed = int(m.group(2) or 0)
            xfailed = int(m.group(3) or 0)
            skipped = int(m.group(4) or 0)
            parts = [f"{passed} passed"]
            if failed:
                parts.append(f"{failed} failed")
            if xfailed:
                parts.append(f"{xfailed} xfailed")
            if skipped:
                parts.append(f"{skipped} skipped")
            return ", ".join(parts)
    return "0 tests"


def _is_oracle_skipped(returncode: int, output: str) -> bool:
    """Return True if the oracle layer ran no tests (hashcat unavailable)."""
    if returncode == 5:  # pytest exit code 5: no tests collected
        return True
    lower = output.lower()
    # All tests were skipped and none passed
    if "no tests ran" in lower:
        return True
    if "passed" not in lower and ("skipped" in lower or "deselected" in lower):
        return True
    return False


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------
def run_layer(layer: Layer, quiet: bool) -> LayerResult:
    """Run a single validation layer via `uv run pytest` and return its result."""
    cmd = ["uv", "run", "pytest", "-v", "--tb=short", "--override-ini=addopts="] + layer.pytest_args

    if not quiet:
        print(f"\n{'─' * 60}")
        print(f"Layer {layer.number} ({layer.name}): running …")
        print(f"  cmd: {' '.join(cmd)}")
        print(f"{'─' * 60}")

    # Always capture so we can parse counts; echo to stdout when not quiet.
    proc = subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    output = proc.stdout + proc.stderr

    if not quiet:
        print(output, end="")

    returncode = proc.returncode

    # Determine status
    if layer.skip_if_no_oracle and _is_oracle_skipped(returncode, output):
        return LayerResult(
            layer=layer,
            status=STATUS_SKIPPED,
            detail="hashcat / generate-rules.bin not available",
            output=output,
        )

    if returncode == 0:
        detail = _parse_counts(output)
        return LayerResult(layer=layer, status=STATUS_PASS, detail=detail, output=output)
    else:
        detail = _parse_counts(output) or f"exit code {returncode}"
        return LayerResult(layer=layer, status=STATUS_FAIL, detail=detail, output=output)


# ---------------------------------------------------------------------------
# Summary rendering
# ---------------------------------------------------------------------------
def _status_display(result: LayerResult, colour: bool = True) -> str:
    if result.status == STATUS_PASS:
        label = green("PASS") if colour else "PASS"
    elif result.status == STATUS_FAIL:
        label = red("FAIL") if colour else "FAIL"
    else:
        label = yellow("SKIPPED") if colour else "SKIPPED"
    return f"{label} ({result.detail})"


def _layer_label(result: LayerResult) -> str:
    return f"Layer {result.layer.number} ({result.layer.name})"


def print_summary(results: list[LayerResult]) -> bool:
    """Print summary table; return True if overall PASS."""
    overall_pass = all(r.status != STATUS_FAIL for r in results)
    overall_label = green("PASS") if overall_pass else red("FAIL")

    col_width = max(len(_layer_label(r)) for r in results) + 2

    print("\n=== Validation Summary ===")
    for r in results:
        label = _layer_label(r)
        print(f"  {label:<{col_width}} {_status_display(r, colour=_USE_COLOUR)}")
    print("=" * 26)
    print(f"Overall: {overall_label}")
    return overall_pass


def write_summary_md(results: list[LayerResult]) -> Path:
    """Write SUMMARY.md to reports/validation/ and return the path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    summary_path = REPORTS_DIR / "SUMMARY.md"

    overall_pass = all(r.status != STATUS_FAIL for r in results)
    overall_label = "PASS" if overall_pass else "FAIL"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        "# Validation Summary",
        "",
        f"Generated: {timestamp}",
        "",
        "## Results",
        "",
        "| Layer | Name | Status | Detail |",
        "| ----- | ---- | ------ | ------ |",
    ]
    for r in results:
        status_md = r.status
        lines.append(f"| {r.layer.number} | {r.layer.name} | {status_md} | {r.detail} |")

    lines += [
        "",
        "## Overall",
        "",
        f"**{overall_label}**",
        "",
    ]

    summary_path.write_text("\n".join(lines) + "\n")
    return summary_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run all HashcatRosetta validation layers and write a summary report."
    )
    parser.add_argument(
        "--no-oracle",
        action="store_true",
        help="Skip Layer 1 (oracle tests; requires hashcat + generate-rules.bin)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-layer pytest output; only show summary",
    )
    args = parser.parse_args()

    results: list[LayerResult] = []
    for layer in LAYERS:
        if args.no_oracle and layer.skip_if_no_oracle:
            results.append(
                LayerResult(
                    layer=layer,
                    status=STATUS_SKIPPED,
                    detail="skipped via --no-oracle",
                    output="",
                )
            )
            continue
        results.append(run_layer(layer, quiet=args.quiet))

    overall_pass = print_summary(results)
    summary_path = write_summary_md(results)
    print(f"\nReport written to: {summary_path.relative_to(PROJECT_ROOT)}")

    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
