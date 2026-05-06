"""Private verification harness library.

Diffs `explain_rule` output against the actual hashcat binary across a baseword
corpus. Public surface: `verify_rule`, `verify_corpus`, `load_baseword_corpus`.

Underscore prefix: this module is internal. Do not import from outside the
package or expose its names from `__init__.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

VerifyStatus = Literal["match", "mismatch", "skipped_unimpl", "skipped_hashcat", "skipped_nonascii"]


@dataclass
class VerifyResult:
    status: VerifyStatus
    rule: str
    baseword: str
    ours: str | None = None
    hashcat: str | None = None
    unimpl_opcodes: list[str] = field(default_factory=list)


@dataclass
class CorpusReport:
    rounds: list[dict] = field(default_factory=list)
    total_tested: int = 0
    total_matched: int = 0
    total_mismatches: int = 0


def load_baseword_corpus(path: Path) -> list[str]:
    """Load corpus JSON; return just the value field for each entry."""
    data = json.loads(Path(path).read_text())
    values: list[str] = []
    for idx, entry in enumerate(data):
        if "value" not in entry:
            raise ValueError(f"corpus entry {idx} missing 'value' field")
        values.append(entry["value"])
    return values


def decide_rejection_status(
    ours_rejected: bool, hashcat_rejected: bool
) -> Literal["match", "mismatch", "needs_string_compare"]:
    """Compare rejection outcomes; spec phase 1 rejection-semantics fix.

    Both rejected -> match. One rejected -> mismatch. Neither rejected ->
    caller still needs to compare strings.
    """
    if ours_rejected and hashcat_rejected:
        return "match"
    if ours_rejected != hashcat_rejected:
        return "mismatch"
    return "needs_string_compare"
