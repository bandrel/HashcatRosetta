"""Hashcat Rule Analyzer - Evaluate the efficiency of hashcat password cracking rules."""

__version__ = "0.3.0"
__author__ = "Justin Bollinger"

from .analyzer import RuleAnalyzer
from .debug_analyzer import DebugAnalyzer
from .parser import DebugLogParser, RuleParser
from typing import TYPE_CHECKING, Any

from .mask import HcmaskLine, MaskError, describe, format_hcmask_line, keyspace, parse_hcmask_line

if TYPE_CHECKING:  # pragma: no cover - import-time typing only
    from .nlmask import MaskGenerationError, MaskSuggestion, generate_masks

# Names re-exported from .nlmask. That module imports the ``openai`` SDK,
# which costs ~450ms, so it is loaded on first attribute access (PEP 562)
# rather than at ``import hashcat_rosetta`` time.
_LAZY_NLMASK_EXPORTS = frozenset({"generate_masks", "MaskGenerationError", "MaskSuggestion"})


def __getattr__(name: str) -> Any:
    """Lazily resolve the ``nlmask`` re-exports (PEP 562)."""
    if name in _LAZY_NLMASK_EXPORTS:
        from . import nlmask

        value = getattr(nlmask, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _LAZY_NLMASK_EXPORTS)


__all__ = [
    "RuleAnalyzer",
    "RuleParser",
    "DebugLogParser",
    "DebugAnalyzer",
    "HcmaskLine",
    "MaskError",
    "parse_hcmask_line",
    "keyspace",
    "describe",
    "format_hcmask_line",
    "generate_masks",
    "MaskGenerationError",
    "MaskSuggestion",
]
