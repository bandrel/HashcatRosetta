"""Analyzer module for hashcat debug files."""

from collections import defaultdict
from typing import Any

from .parser import DebugLogParser


def _median(values: list[int]) -> float:
    """Calculate the median of a list of numeric values."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    mid = n // 2
    if n % 2 == 0:
        return (s[mid - 1] + s[mid]) / 2
    return float(s[mid])


class DebugAnalyzer:
    """Analyze hashcat debug files for rule efficiency and baseword patterns."""

    def __init__(self, debug_mode: int | None = None) -> None:
        """Initialize the debug analyzer.

        Args:
            debug_mode: Optional override for the hashcat debug mode passed
                through to the parser. ``None`` auto-detects, ``4`` forces
                mode-4 parsing, ``5`` forces mode-5 parsing (wordlist field).
        """
        self.parser = DebugLogParser(debug_mode=debug_mode)
        self.entries: list[dict[str, Any]] = []

        # Rule statistics
        self.rule_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "count": 0,  # Total applications
                "basewords": set(),  # Unique basewords used with this rule
                "candidates": set(),  # Unique candidates generated
                "match_count": 0,  # Successful matches
            }
        )

        # Baseword statistics
        self.baseword_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "occurrences": [],  # List of {rule, candidate, matched}
                "count": 0,
                "match_count": 0,
            }
        )

        # Wordlist statistics (mode-5 only)
        self.wordlist_stats: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "count": 0,  # Total entries attributed to this wordlist
                "basewords": set(),  # Unique basewords from this wordlist
                "candidates": set(),  # Unique candidates from this wordlist
                "rules": set(),  # Unique rules seen with this wordlist
                "match_count": 0,  # Successful matches
            }
        )

    def analyze_debug_file(self, filepath: str) -> dict:
        """
        Analyze a hashcat debug file.

        Args:
            filepath: Path to the debug file

        Returns:
            Dictionary containing analysis results
        """
        self.entries = self.parser.parse_debug_file(filepath)
        return self._compute_analysis()

    def analyze_debug_lines(self, lines: list) -> dict:
        """
        Analyze debug output lines.

        Args:
            lines: List of debug output lines

        Returns:
            Dictionary containing analysis results
        """
        self.entries = self.parser.parse_debug_lines(lines)
        return self._compute_analysis()

    def _compute_analysis(self) -> dict:
        """Compute statistics from parsed entries."""
        self.rule_stats.clear()
        self.baseword_stats.clear()
        self.wordlist_stats.clear()

        for entry in self.entries:
            baseword = entry["baseword"]
            rule = entry["rule"]
            candidate = entry["candidate"]
            wordlist = entry.get("wordlist")

            # Update rule statistics
            self.rule_stats[rule]["count"] += 1
            self.rule_stats[rule]["basewords"].add(baseword)
            self.rule_stats[rule]["candidates"].add(candidate)

            # Update match counts
            if entry.get("matched", False):
                self.rule_stats[rule]["match_count"] += 1

            # Update baseword statistics
            self.baseword_stats[baseword]["occurrences"].append(
                {
                    "rule": rule,
                    "candidate": candidate,
                    "matched": entry.get("matched", False),
                }
            )
            self.baseword_stats[baseword]["count"] += 1
            if entry.get("matched", False):
                self.baseword_stats[baseword]["match_count"] += 1

            # Update wordlist statistics (mode-5 only; skip mode-4 entries).
            if wordlist is not None:
                self.wordlist_stats[wordlist]["count"] += 1
                self.wordlist_stats[wordlist]["basewords"].add(baseword)
                self.wordlist_stats[wordlist]["candidates"].add(candidate)
                self.wordlist_stats[wordlist]["rules"].add(rule)
                if entry.get("matched", False):
                    self.wordlist_stats[wordlist]["match_count"] += 1

        return {
            "total_entries": len(self.entries),
            "unique_rules": len(self.rule_stats),
            "unique_basewords": len(self.baseword_stats),
            "unique_wordlists": len(self.wordlist_stats),
            "rule_stats": self._make_serializable(dict(self.rule_stats)),
            "baseword_stats": self._make_serializable(dict(self.baseword_stats)),
            "wordlist_stats": self._make_serializable(dict(self.wordlist_stats)),
        }

    def get_top_rules_by_frequency(self, top_n: int = 10) -> list:
        """
        Get top rules by application frequency.

        Args:
            top_n: Number of top rules to return

        Returns:
            List of (rule, count) tuples
        """
        rules = sorted(self.rule_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:top_n]
        return [(rule, stats["count"]) for rule, stats in rules]

    def get_top_rules_by_unique_basewords(self, top_n: int = 10) -> list:
        """
        Get top rules by number of unique basewords they were applied to.

        Args:
            top_n: Number of top rules to return

        Returns:
            List of (rule, unique_baseword_count) tuples
        """
        rules = sorted(self.rule_stats.items(), key=lambda x: len(x[1]["basewords"]), reverse=True)[
            :top_n
        ]
        return [(rule, len(stats["basewords"])) for rule, stats in rules]

    def get_top_rules_by_unique_candidates(self, top_n: int = 10) -> list:
        """
        Get top rules by number of unique candidates they generated.

        Args:
            top_n: Number of top rules to return

        Returns:
            List of (rule, unique_candidate_count) tuples
        """
        rules = sorted(
            self.rule_stats.items(), key=lambda x: len(x[1]["candidates"]), reverse=True
        )[:top_n]
        return [(rule, len(stats["candidates"])) for rule, stats in rules]

    def get_top_basewords_by_frequency(self, top_n: int = 10) -> list:
        """
        Get top basewords by occurrence frequency.

        Args:
            top_n: Number of top basewords to return

        Returns:
            List of (baseword, count) tuples
        """
        basewords = sorted(self.baseword_stats.items(), key=lambda x: x[1]["count"], reverse=True)[
            :top_n
        ]
        return [(bw, stats["count"]) for bw, stats in basewords]

    def get_baseword_detail(self, baseword: str) -> dict | None:
        """
        Get detailed information about a specific baseword.

        Args:
            baseword: The baseword to analyze

        Returns:
            Dictionary with occurrence details
        """
        if baseword not in self.baseword_stats:
            return None

        stats = self.baseword_stats[baseword]
        return {
            "baseword": baseword,
            "total_occurrences": stats["count"],
            "occurrences": stats["occurrences"],
            "unique_rules": len(set(occ["rule"] for occ in stats["occurrences"])),
            "unique_candidates": len(set(occ["candidate"] for occ in stats["occurrences"])),
        }

    def get_rule_detail(self, rule: str) -> dict | None:
        """
        Get detailed information about a specific rule.

        Args:
            rule: The rule to analyze

        Returns:
            Dictionary with rule details
        """
        if rule not in self.rule_stats:
            return None

        stats = self.rule_stats[rule]
        return {
            "rule": rule,
            "total_applications": stats["count"],
            "unique_basewords": len(stats["basewords"]),
            "unique_candidates": len(stats["candidates"]),
            "basewords": sorted(list(stats["basewords"])),
            "candidates": sorted(list(stats["candidates"])),
        }

    def get_basewords_with_min_occurrences(self, min_occurrences: int = 2) -> list:
        """
        Get all basewords that appear at least min_occurrences times.

        Args:
            min_occurrences: Minimum number of occurrences

        Returns:
            List of (baseword, count) tuples, sorted by count descending
        """
        filtered = [
            (bw, stats["count"])
            for bw, stats in self.baseword_stats.items()
            if stats["count"] >= min_occurrences
        ]
        return sorted(filtered, key=lambda x: x[1], reverse=True)

    def get_rule_statistics_summary(self) -> dict:
        """
        Get summary statistics about all rules.

        Returns:
            Dictionary with aggregate statistics
        """
        if not self.rule_stats:
            return {}

        counts = [stats["count"] for stats in self.rule_stats.values()]
        unique_bw_counts = [len(stats["basewords"]) for stats in self.rule_stats.values()]
        unique_cand_counts = [len(stats["candidates"]) for stats in self.rule_stats.values()]

        return {
            "total_rules": len(self.rule_stats),
            "total_applications": sum(counts),
            "avg_applications_per_rule": sum(counts) / len(counts) if counts else 0,
            "median_applications": _median(counts),
            "max_applications": max(counts) if counts else 0,
            "min_applications": min(counts) if counts else 0,
            "avg_basewords_per_rule": sum(unique_bw_counts) / len(unique_bw_counts)
            if unique_bw_counts
            else 0,
            "avg_candidates_per_rule": sum(unique_cand_counts) / len(unique_cand_counts)
            if unique_cand_counts
            else 0,
        }

    def get_baseword_statistics_summary(self) -> dict:
        """
        Get summary statistics about all basewords.

        Returns:
            Dictionary with aggregate statistics
        """
        if not self.baseword_stats:
            return {}

        counts = [stats["count"] for stats in self.baseword_stats.values()]

        return {
            "total_basewords": len(self.baseword_stats),
            "total_occurrences": sum(counts),
            "avg_occurrences_per_baseword": sum(counts) / len(counts) if counts else 0,
            "median_occurrences": _median(counts),
            "max_occurrences": max(counts) if counts else 0,
            "min_occurrences": min(counts) if counts else 0,
        }

    def get_top_wordlists(self, top_n: int = 10) -> list:
        """
        Get top wordlists by number of attributed entries.

        Args:
            top_n: Number of top wordlists to return

        Returns:
            List of (wordlist, count) tuples, sorted by count descending
        """
        wordlists = sorted(self.wordlist_stats.items(), key=lambda x: x[1]["count"], reverse=True)[
            :top_n
        ]
        return [(wl, stats["count"]) for wl, stats in wordlists]

    def get_wordlist_statistics_summary(self) -> dict:
        """
        Get summary statistics about all wordlists.

        Returns:
            Dictionary with aggregate statistics (empty if no wordlists)
        """
        if not self.wordlist_stats:
            return {}

        counts = [stats["count"] for stats in self.wordlist_stats.values()]
        unique_bw_counts = [len(stats["basewords"]) for stats in self.wordlist_stats.values()]
        unique_cand_counts = [len(stats["candidates"]) for stats in self.wordlist_stats.values()]
        unique_rule_counts = [len(stats["rules"]) for stats in self.wordlist_stats.values()]

        return {
            "total_wordlists": len(self.wordlist_stats),
            "total_attributed_entries": sum(counts),
            "avg_entries_per_wordlist": sum(counts) / len(counts) if counts else 0,
            "median_entries": _median(counts),
            "max_entries": max(counts) if counts else 0,
            "min_entries": min(counts) if counts else 0,
            "avg_basewords_per_wordlist": sum(unique_bw_counts) / len(unique_bw_counts)
            if unique_bw_counts
            else 0,
            "avg_candidates_per_wordlist": sum(unique_cand_counts) / len(unique_cand_counts)
            if unique_cand_counts
            else 0,
            "avg_rules_per_wordlist": sum(unique_rule_counts) / len(unique_rule_counts)
            if unique_rule_counts
            else 0,
        }

    def get_wordlist_detail(self, wordlist: str) -> dict | None:
        """
        Get detailed information about a specific wordlist.

        Args:
            wordlist: The wordlist to analyze

        Returns:
            Dictionary with wordlist details, or None if not present
        """
        if wordlist not in self.wordlist_stats:
            return None

        stats = self.wordlist_stats[wordlist]
        return {
            "wordlist": wordlist,
            "total_occurrences": stats["count"],
            "unique_basewords": len(stats["basewords"]),
            "unique_candidates": len(stats["candidates"]),
            "unique_rules": len(stats["rules"]),
            "basewords": sorted(list(stats["basewords"])),
            "candidates": sorted(list(stats["candidates"])),
            "rules": sorted(list(stats["rules"])),
        }

    def export_to_dict(self) -> Any:
        """
        Export complete analysis data as a JSON-serializable dictionary.

        Returns:
            Complete analysis data structure (all values are JSON-safe)
        """
        data = {
            "summary": {
                "total_entries": len(self.entries),
                "rules": self.get_rule_statistics_summary(),
                "basewords": self.get_baseword_statistics_summary(),
                "wordlists": self.get_wordlist_statistics_summary(),
            },
            "top_rules_by_frequency": self.get_top_rules_by_frequency(20),
            "top_rules_by_basewords": self.get_top_rules_by_unique_basewords(20),
            "top_rules_by_candidates": self.get_top_rules_by_unique_candidates(20),
            "top_basewords": self.get_top_basewords_by_frequency(20),
            "basewords_with_duplicates": self.get_basewords_with_min_occurrences(2),
            "top_wordlists": self.get_top_wordlists(20),
            "wordlist_summary": self.get_wordlist_statistics_summary(),
            "all_rule_details": {
                rule: self.get_rule_detail(rule) for rule in sorted(self.rule_stats.keys())
            },
            "all_wordlist_details": {
                wl: self.get_wordlist_detail(wl) for wl in sorted(self.wordlist_stats.keys())
            },
        }
        return self._make_serializable(data)

    @staticmethod
    def _make_serializable(obj: Any) -> Any:
        """Convert sets and other non-serializable objects to JSON-safe types."""
        if isinstance(obj, set):
            return sorted(list(obj))
        elif isinstance(obj, dict):
            return {k: DebugAnalyzer._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [DebugAnalyzer._make_serializable(item) for item in obj]
        else:
            return obj
