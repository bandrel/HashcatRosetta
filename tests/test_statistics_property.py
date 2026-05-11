"""Property tests for DebugAnalyzer statistics correctness.

Uses synthetic in-memory fixtures via analyze_debug_lines() — no file I/O.
Uses stdlib random with fixed seeds — no Hypothesis dependency.
"""

import json
import random
import statistics
from hashcat_rosetta import DebugAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_lines(entries: list[tuple[str, str, str]]) -> list[str]:
    """Convert (baseword, rule, candidate) tuples to space-separated debug lines."""
    return [f"{bw} {rule} {cand}" for bw, rule, cand in entries]


def _build_analyzer(entries: list[tuple[str, str, str]]) -> DebugAnalyzer:
    """Build and run a DebugAnalyzer from a list of (baseword, rule, candidate) tuples."""
    analyzer = DebugAnalyzer()
    lines = _make_lines(entries)
    analyzer.analyze_debug_lines(lines)
    return analyzer


# ---------------------------------------------------------------------------
# 1. Conservation laws
# ---------------------------------------------------------------------------


class TestConservationLaws:
    """Every entry must be accounted for exactly once in both stat dicts."""

    def _synthetic_entries(self, n: int = 100, seed: int = 42) -> list[tuple[str, str, str]]:
        rng = random.Random(seed)
        rules = ["c", "u", "l", "r", "d", "f", "t"]
        basewords = [f"word{i}" for i in range(10)]
        entries = []
        for _ in range(n):
            bw = rng.choice(basewords)
            rule = rng.choice(rules)
            candidate = f"{bw}_mutated_{rng.randint(0, 999)}"
            entries.append((bw, rule, candidate))
        return entries

    def test_rule_stats_count_sum_equals_total_entries(self):
        """sum(rule_stats[r]['count']) must equal total number of entries."""
        entries = self._synthetic_entries(100)
        analyzer = _build_analyzer(entries)
        total = sum(stats["count"] for stats in analyzer.rule_stats.values())
        assert total == len(entries)

    def test_baseword_stats_count_sum_equals_total_entries(self):
        """sum(baseword_stats[bw]['count']) must equal total number of entries."""
        entries = self._synthetic_entries(100)
        analyzer = _build_analyzer(entries)
        total = sum(stats["count"] for stats in analyzer.baseword_stats.values())
        assert total == len(entries)

    def test_unique_basewords_per_rule_matches_set_count(self):
        """len(rule_stats[r]['basewords']) must equal the true unique baseword count for that rule."""
        entries = self._synthetic_entries(200, seed=7)
        analyzer = _build_analyzer(entries)

        for rule, stats in analyzer.rule_stats.items():
            expected_unique_bw = {bw for bw, r, _cand in entries if r == rule}
            assert stats["basewords"] == expected_unique_bw, (
                f"Rule '{rule}': basewords set mismatch — "
                f"expected {expected_unique_bw}, got {stats['basewords']}"
            )

    def test_rule_stats_count_matches_manual_count(self):
        """rule_stats[r]['count'] must equal the number of entries with that rule."""
        entries = self._synthetic_entries(150, seed=13)
        analyzer = _build_analyzer(entries)

        for rule, stats in analyzer.rule_stats.items():
            expected_count = sum(1 for _bw, r, _cand in entries if r == rule)
            assert stats["count"] == expected_count, (
                f"Rule '{rule}': count mismatch — expected {expected_count}, got {stats['count']}"
            )

    def test_baseword_stats_count_matches_manual_count(self):
        """baseword_stats[bw]['count'] must equal the number of entries with that baseword."""
        entries = self._synthetic_entries(150, seed=17)
        analyzer = _build_analyzer(entries)

        for bw, stats in analyzer.baseword_stats.items():
            expected_count = sum(1 for b, _r, _cand in entries if b == bw)
            assert stats["count"] == expected_count, (
                f"Baseword '{bw}': count mismatch — expected {expected_count}, got {stats['count']}"
            )

    def test_match_count_for_rules_is_zero_by_default(self):
        """When no entries have matched=True (format does not carry it), match_count should be 0."""
        entries = self._synthetic_entries(50, seed=99)
        analyzer = _build_analyzer(entries)

        for rule, stats in analyzer.rule_stats.items():
            assert stats["match_count"] == 0, (
                f"Rule '{rule}': expected match_count=0 for space-format entries, "
                f"got {stats['match_count']}"
            )

    def test_no_entries_are_double_counted(self):
        """Each (rule, baseword) pair should contribute to exactly one rule bucket and one baseword bucket."""
        entries = self._synthetic_entries(80, seed=31)
        analyzer = _build_analyzer(entries)

        rule_total = sum(stats["count"] for stats in analyzer.rule_stats.values())
        bw_total = sum(stats["count"] for stats in analyzer.baseword_stats.values())

        assert rule_total == bw_total == len(entries)


# ---------------------------------------------------------------------------
# 2. Median correctness
# ---------------------------------------------------------------------------


class TestMedianCorrectness:
    """get_rule_statistics_summary()['median_applications'] must match statistics.median()."""

    def _build_analyzer_with_rule_counts(self, counts: list[int]) -> DebugAnalyzer:
        """
        Build a DebugAnalyzer where each rule appears exactly `counts[i]` times.
        Rules are named r0, r1, ...; basewords are named bw0, bw1, ...
        """
        entries: list[tuple[str, str, str]] = []
        for rule_idx, count in enumerate(counts):
            rule = f"rule{rule_idx}"
            for j in range(count):
                bw = f"bw{rule_idx}_{j}"
                cand = f"cand{rule_idx}_{j}"
                entries.append((bw, rule, cand))
        return _build_analyzer(entries)

    def test_median_single_element(self):
        """[5] → median = 5.0"""
        counts = [5]
        analyzer = self._build_analyzer_with_rule_counts(counts)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == statistics.median(counts)

    def test_median_two_elements(self):
        """[3, 7] → median = 5.0"""
        counts = [3, 7]
        analyzer = self._build_analyzer_with_rule_counts(counts)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == statistics.median(counts)

    def test_median_three_elements_odd(self):
        """[1, 3, 5] → median = 3"""
        counts = [1, 3, 5]
        analyzer = self._build_analyzer_with_rule_counts(counts)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == statistics.median(counts)

    def test_median_four_elements_even(self):
        """[1, 2, 3, 4] → median = 2.5"""
        counts = [1, 2, 3, 4]
        analyzer = self._build_analyzer_with_rule_counts(counts)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == statistics.median(counts)

    def test_median_all_equal(self):
        """[4, 4, 4, 4] → median = 4"""
        counts = [4, 4, 4, 4]
        analyzer = self._build_analyzer_with_rule_counts(counts)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == statistics.median(counts)

    def test_median_large_random(self):
        """100 random counts (fixed seed) → median matches statistics.median()."""
        rng = random.Random(2024)
        counts = [rng.randint(1, 50) for _ in range(100)]
        analyzer = self._build_analyzer_with_rule_counts(counts)
        summary = analyzer.get_rule_statistics_summary()
        assert summary["median_applications"] == statistics.median(counts)

    def test_baseword_median_two_elements(self):
        """Baseword summary median: [3, 7] → 5.0"""
        # Each baseword appears exactly `count` times (each with a distinct rule)
        entries: list[tuple[str, str, str]] = []
        for i in range(3):
            entries.append(("alpha", f"rule{i}", f"cand_a_{i}"))
        for i in range(7):
            entries.append(("beta", f"rule{i}", f"cand_b_{i}"))
        analyzer = _build_analyzer(entries)
        summary = analyzer.get_baseword_statistics_summary()
        assert summary["median_occurrences"] == 5.0

    def test_baseword_median_four_elements_even(self):
        """Baseword summary median: [1, 2, 3, 4] → 2.5"""
        entries: list[tuple[str, str, str]] = []
        for bw, count in [("a", 1), ("b", 2), ("c", 3), ("d", 4)]:
            for i in range(count):
                entries.append((bw, f"rule{i}", f"cand_{bw}_{i}"))
        analyzer = _build_analyzer(entries)
        summary = analyzer.get_baseword_statistics_summary()
        assert summary["median_occurrences"] == 2.5


# ---------------------------------------------------------------------------
# 3. Top-N ordering invariants
# ---------------------------------------------------------------------------


class TestTopNOrdering:
    """get_top_rules_by_frequency() and related methods must respect ordering and limit."""

    def _build_known_frequency_analyzer(self) -> tuple[DebugAnalyzer, dict[str, int]]:
        """
        Build an analyzer with precisely controlled per-rule frequencies.
        Returns (analyzer, rule_to_count_map).
        """
        rule_counts = {"c": 10, "u": 7, "l": 5, "r": 3, "d": 2, "f": 1}
        entries: list[tuple[str, str, str]] = []
        for rule, count in rule_counts.items():
            for i in range(count):
                entries.append((f"bw{i}", rule, f"cand_{rule}_{i}"))
        analyzer = _build_analyzer(entries)
        return analyzer, rule_counts

    def test_top_rules_by_frequency_length_bounded_by_n(self):
        """Length of result ≤ top_n."""
        analyzer, _ = self._build_known_frequency_analyzer()
        for n in (1, 3, 5, 10, 100):
            result = analyzer.get_top_rules_by_frequency(top_n=n)
            assert len(result) <= n

    def test_top_rules_by_frequency_sorted_descending(self):
        """Result must be sorted by count descending."""
        analyzer, _ = self._build_known_frequency_analyzer()
        result = analyzer.get_top_rules_by_frequency(top_n=10)
        counts = [count for _rule, count in result]
        assert counts == sorted(counts, reverse=True), f"Not descending: {counts}"

    def test_top_rules_by_frequency_top_entry_is_highest(self):
        """The first entry must have the highest count overall."""
        analyzer, rule_counts = self._build_known_frequency_analyzer()
        result = analyzer.get_top_rules_by_frequency(top_n=10)
        assert len(result) > 0
        top_rule, top_count = result[0]
        max_count = max(rule_counts.values())
        assert top_count == max_count, f"Top entry count {top_count} ≠ overall max {max_count}"

    def test_top_rules_by_frequency_returns_all_when_n_large(self):
        """When top_n exceeds the number of rules, all rules are returned."""
        analyzer, rule_counts = self._build_known_frequency_analyzer()
        result = analyzer.get_top_rules_by_frequency(top_n=1000)
        assert len(result) == len(rule_counts)

    def test_top_rules_by_frequency_partial_top_n(self):
        """When top_n=3, only the 3 highest-count rules are returned."""
        analyzer, rule_counts = self._build_known_frequency_analyzer()
        result = analyzer.get_top_rules_by_frequency(top_n=3)
        assert len(result) == 3
        returned_counts = [count for _rule, count in result]
        all_counts_desc = sorted(rule_counts.values(), reverse=True)
        assert returned_counts == all_counts_desc[:3]

    def test_top_rules_by_unique_basewords_sorted_descending(self):
        """get_top_rules_by_unique_basewords() must be sorted descending by unique baseword count."""
        # Give each rule a different number of unique basewords
        entries: list[tuple[str, str, str]] = []
        # rule "c": 5 unique basewords; rule "u": 3; rule "l": 1
        for i in range(5):
            entries.append((f"bw{i}", "c", f"cand_c_{i}"))
        for i in range(3):
            entries.append((f"bw{i}", "u", f"cand_u_{i}"))
        for i in range(1):
            entries.append((f"bw{i}", "l", f"cand_l_{i}"))
        analyzer = _build_analyzer(entries)
        result = analyzer.get_top_rules_by_unique_basewords(top_n=10)
        counts = [count for _rule, count in result]
        assert counts == sorted(counts, reverse=True)

    def test_top_rules_by_unique_basewords_top_entry_correct(self):
        """The rule with the most unique basewords must appear first."""
        entries: list[tuple[str, str, str]] = []
        for i in range(8):
            entries.append((f"bw{i}", "c", f"cand_c_{i}"))
        for i in range(2):
            entries.append((f"bw{i}", "u", f"cand_u_{i}"))
        analyzer = _build_analyzer(entries)
        result = analyzer.get_top_rules_by_unique_basewords(top_n=10)
        assert result[0][0] == "c"
        assert result[0][1] == 8

    def test_top_basewords_by_frequency_sorted_descending(self):
        """get_top_basewords_by_frequency() must be sorted descending."""
        entries = [
            ("alpha", "c", "Alpha"),
            ("alpha", "u", "ALPHA"),
            ("alpha", "l", "alpha"),
            ("beta", "c", "Beta"),
            ("beta", "u", "BETA"),
            ("gamma", "c", "Gamma"),
        ]
        analyzer = _build_analyzer(entries)
        result = analyzer.get_top_basewords_by_frequency(top_n=10)
        counts = [count for _bw, count in result]
        assert counts == sorted(counts, reverse=True)

    def test_top_basewords_by_frequency_top_entry_is_highest(self):
        """The baseword with the highest frequency must appear first."""
        entries = [
            ("alpha", "c", "Alpha"),
            ("alpha", "u", "ALPHA"),
            ("alpha", "l", "alpha"),
            ("beta", "c", "Beta"),
            ("gamma", "c", "Gamma"),
        ]
        analyzer = _build_analyzer(entries)
        result = analyzer.get_top_basewords_by_frequency(top_n=10)
        assert result[0][0] == "alpha"
        assert result[0][1] == 3


# ---------------------------------------------------------------------------
# 4. Export round-trip
# ---------------------------------------------------------------------------


class TestExportRoundTrip:
    """export_to_dict() must produce JSON-serializable output with no data loss."""

    def _build_typical_analyzer(self) -> DebugAnalyzer:
        entries = [
            ("password", "c", "Password"),
            ("password", "u", "PASSWORD"),
            ("admin", "c", "Admin"),
            ("admin", "u", "ADMIN"),
            ("admin", "l", "admin"),
            ("secret", "r", "terces"),
        ]
        return _build_analyzer(entries)

    def test_export_to_dict_is_json_serializable(self):
        """export_to_dict() must not raise when passed through json.dumps."""
        analyzer = self._build_typical_analyzer()
        data = analyzer.export_to_dict()
        # Should not raise
        json_str = json.dumps(data)
        assert isinstance(json_str, str)
        assert len(json_str) > 0

    def test_export_round_trip_preserves_rule_counts(self):
        """Rule counts in export must survive JSON round-trip unchanged."""
        analyzer = self._build_typical_analyzer()
        original = analyzer.export_to_dict()
        round_tripped = json.loads(json.dumps(original))

        # top_rules_by_frequency is a list of [rule, count] pairs
        original_top = {rule: count for rule, count in original["top_rules_by_frequency"]}
        rt_top = {rule: count for rule, count in round_tripped["top_rules_by_frequency"]}
        assert original_top == rt_top

    def test_export_round_trip_preserves_baseword_counts(self):
        """Baseword counts in export must survive JSON round-trip unchanged."""
        analyzer = self._build_typical_analyzer()
        original = analyzer.export_to_dict()
        round_tripped = json.loads(json.dumps(original))

        original_bw = {bw: count for bw, count in original["top_basewords"]}
        rt_bw = {bw: count for bw, count in round_tripped["top_basewords"]}
        assert original_bw == rt_bw

    def test_export_round_trip_no_keys_lost(self):
        """All top-level keys in the export dict must survive round-trip."""
        analyzer = self._build_typical_analyzer()
        original = analyzer.export_to_dict()
        round_tripped = json.loads(json.dumps(original))
        assert set(original.keys()) == set(round_tripped.keys())

    def test_export_rule_details_survive_round_trip(self):
        """all_rule_details counts must match after JSON round-trip."""
        analyzer = self._build_typical_analyzer()
        original = analyzer.export_to_dict()
        round_tripped = json.loads(json.dumps(original))

        for rule, detail in original["all_rule_details"].items():
            assert rule in round_tripped["all_rule_details"]
            rt_detail = round_tripped["all_rule_details"][rule]
            assert detail["total_applications"] == rt_detail["total_applications"]

    def test_export_summary_total_entries_correct(self):
        """summary.total_entries must match the number of lines fed in."""
        entries = [
            ("password", "c", "Password"),
            ("password", "u", "PASSWORD"),
            ("admin", "c", "Admin"),
            ("admin", "u", "ADMIN"),
            ("admin", "l", "admin"),
            ("secret", "r", "terces"),
        ]
        analyzer = _build_analyzer(entries)
        data = analyzer.export_to_dict()
        assert data["summary"]["total_entries"] == len(entries)


# ---------------------------------------------------------------------------
# 5. UTF-8 encoding losslessness
# ---------------------------------------------------------------------------


class TestUtf8EncodingLosslessness:
    """Baseword strings with non-ASCII characters must survive export → JSON → reload."""

    def _utf8_entries(self) -> list[tuple[str, str, str]]:
        return [
            ("pässwörd", "c", "Pässwörd"),
            ("café", "u", "CAFÉ"),
            ("naïve", "l", "naïve"),
            ("résumé", "r", "émusér"),
            ("日本語", "c", "日本語"),
            ("ñoño", "u", "ÑOÑO"),
        ]

    def test_utf8_basewords_survive_json_round_trip(self):
        """Non-ASCII baseword strings must be identical after export → JSON → reload."""
        entries = self._utf8_entries()
        analyzer = _build_analyzer(entries)
        data = analyzer.export_to_dict()
        round_tripped = json.loads(json.dumps(data, ensure_ascii=False))

        original_bws = {bw for bw, _rule, _cand in entries}
        # The exported top_basewords list contains [baseword, count] pairs
        exported_bws = {bw for bw, _count in round_tripped["top_basewords"]}
        assert original_bws == exported_bws, (
            f"UTF-8 basewords lost in round-trip: "
            f"missing={original_bws - exported_bws}, extra={exported_bws - original_bws}"
        )

    def test_utf8_basewords_are_in_stats(self):
        """Non-ASCII basewords must appear in analyzer.baseword_stats after parsing."""
        entries = self._utf8_entries()
        analyzer = _build_analyzer(entries)
        for bw, _rule, _cand in entries:
            assert bw in analyzer.baseword_stats, f"UTF-8 baseword '{bw}' not found in stats"

    def test_utf8_baseword_counts_are_correct(self):
        """Counts for non-ASCII basewords must be accurate."""
        entries = self._utf8_entries()
        # Add a second occurrence of "café" to verify counting
        entries.append(("café", "l", "café"))
        analyzer = _build_analyzer(entries)
        assert analyzer.baseword_stats["café"]["count"] == 2

    def test_utf8_export_with_ascii_flag_false(self):
        """json.dumps(ensure_ascii=False) must preserve all non-ASCII codepoints."""
        entries = self._utf8_entries()
        analyzer = _build_analyzer(entries)
        data = analyzer.export_to_dict()
        json_str = json.dumps(data, ensure_ascii=False)
        reloaded = json.loads(json_str)
        bws = {bw for bw, _count in reloaded["top_basewords"]}
        for bw, _rule, _cand in entries:
            assert bw in bws, f"'{bw}' missing after ensure_ascii=False round-trip"

    def test_utf8_export_with_ascii_escaping(self):
        """json.dumps(ensure_ascii=True) must also correctly escape and restore non-ASCII."""
        entries = [("café", "c", "Café"), ("naïve", "u", "NAÏVE")]
        analyzer = _build_analyzer(entries)
        data = analyzer.export_to_dict()
        json_str = json.dumps(data, ensure_ascii=True)
        # All non-ASCII chars should be escaped
        assert "\\u" in json_str
        reloaded = json.loads(json_str)
        bws = {bw for bw, _count in reloaded["top_basewords"]}
        assert "café" in bws
        assert "naïve" in bws
