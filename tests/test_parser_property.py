"""Property tests for DebugLogParser.

Tests fixture-driven parsing correctness, round-trip fidelity for both
space-separated and colon-separated formats, format auto-detection, and
idempotence across multiple parse calls.
"""

import json
import pathlib

import pytest

from hashcat_rosetta.parser import DebugLogParser

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures" / "debug_logs"


def _load_expected(jsonl_path: pathlib.Path) -> list[dict]:
    """Load expected entries from a .expected.jsonl file."""
    entries = []
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _fixture_pairs() -> list[tuple[pathlib.Path, pathlib.Path]]:
    """Discover all (log_file, expected_jsonl) pairs in the fixtures directory."""
    pairs = []
    for log_file in sorted(FIXTURES_DIR.glob("*.log")):
        expected_file = log_file.with_suffix(".expected.jsonl")
        if expected_file.exists():
            pairs.append((log_file, expected_file))
    return pairs


# ---------------------------------------------------------------------------
# TestFixtureCorpus
# ---------------------------------------------------------------------------


class TestFixtureCorpus:
    """Fixture-driven correctness tests: parse each log file and compare against expected JSONL."""

    @pytest.mark.parametrize(
        "log_file,expected_file",
        _fixture_pairs(),
        ids=[p.stem for p, _ in _fixture_pairs()],
    )
    def test_fixture_entry_count(self, log_file: pathlib.Path, expected_file: pathlib.Path) -> None:
        """Parsed entry count must match expected count."""
        parser = DebugLogParser()
        result = parser.parse_debug_file(str(log_file))
        expected = _load_expected(expected_file)
        assert len(result) == len(expected), (
            f"{log_file.name}: expected {len(expected)} entries, got {len(result)}"
        )

    @pytest.mark.parametrize(
        "log_file,expected_file",
        _fixture_pairs(),
        ids=[p.stem for p, _ in _fixture_pairs()],
    )
    def test_fixture_entry_fields(
        self, log_file: pathlib.Path, expected_file: pathlib.Path
    ) -> None:
        """Each parsed entry must match baseword, rule, and candidate from expected JSONL."""
        parser = DebugLogParser()
        result = parser.parse_debug_file(str(log_file))
        expected = _load_expected(expected_file)

        for i, (got, exp) in enumerate(zip(result, expected)):
            for field in ("baseword", "rule", "candidate"):
                assert got[field] == exp[field], (
                    f"{log_file.name}[{i}].{field}: expected {exp[field]!r}, got {got[field]!r}"
                )

    @pytest.mark.parametrize(
        "log_file,expected_file",
        _fixture_pairs(),
        ids=[p.stem for p, _ in _fixture_pairs()],
    )
    def test_fixture_matched_false(
        self, log_file: pathlib.Path, expected_file: pathlib.Path
    ) -> None:
        """All parsed entries must have matched=False (static parse, no hash comparison)."""
        parser = DebugLogParser()
        result = parser.parse_debug_file(str(log_file))
        for i, entry in enumerate(result):
            assert entry["matched"] is False, (
                f"{log_file.name}[{i}]: expected matched=False, got {entry['matched']!r}"
            )


# ---------------------------------------------------------------------------
# TestRoundTrip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """Round-trip tests: format a line, parse it back, assert equality."""

    # These tuples must not trigger the heuristic:
    # - baseword must not be in common_rules ("culrdftE$^[]{}@")
    # - if baseword starts with a rule_prefix ("s","i","o","T","+","-","*","x","O","D","'","z","Z"),
    #   candidate must be > 3 chars
    SPACE_CASES: list[tuple[str, str, str]] = [
        ("football", "u", "FOOTBALL"),
        ("password", "c$1", "Password1"),
        ("test123", "d", "test123test123"),
        ("hello", "l", "hello"),
        ("monkey", "r", "yeknom"),
        # Note: rules containing spaces cannot be round-tripped in space format since
        # _parse_space_line uses split(maxsplit=2) — only space-free rules are valid here.
        ("winter", "c", "Winter"),
    ]

    COLON_CASES: list[tuple[str, str, str]] = [
        ("football", "u", "FOOTBALL"),
        ("password", "c", "Password"),
        ("test123", "d", "test123test123"),
        ("hello", "l", "hello"),
        ("monkey", "r", "yeknom"),
    ]

    @pytest.mark.parametrize(
        "baseword,rule,candidate",
        SPACE_CASES,
        ids=[f"{bw}_{rule}" for bw, rule, _ in SPACE_CASES],
    )
    def test_space_round_trip(self, baseword: str, rule: str, candidate: str) -> None:
        """Formatting a space-separated line and parsing it back must return original values."""
        line = f"{baseword} {rule} {candidate}"
        parser = DebugLogParser()
        parser._format = "space"
        result = parser._parse_space_line(line)
        assert result is not None, f"Expected non-None result for line: {line!r}"
        assert result["baseword"] == baseword, (
            f"baseword mismatch: expected {baseword!r}, got {result['baseword']!r}"
        )
        assert result["rule"] == rule, f"rule mismatch: expected {rule!r}, got {result['rule']!r}"
        assert result["candidate"] == candidate, (
            f"candidate mismatch: expected {candidate!r}, got {result['candidate']!r}"
        )

    @pytest.mark.parametrize(
        "baseword,rule,candidate",
        COLON_CASES,
        ids=[f"{bw}_{rule}" for bw, rule, _ in COLON_CASES],
    )
    def test_colon_round_trip(self, baseword: str, rule: str, candidate: str) -> None:
        """Formatting a colon-separated line and parsing it back must return original values."""
        # Only safe when baseword and rule contain no colons
        assert ":" not in baseword, f"Test misconfiguration: colon in baseword {baseword!r}"
        assert ":" not in rule, f"Test misconfiguration: colon in rule {rule!r}"
        line = f"{baseword}:{rule}:{candidate}"
        parser = DebugLogParser()
        result = parser._parse_colon_line(line)
        assert result is not None, f"Expected non-None result for line: {line!r}"
        assert result["baseword"] == baseword, (
            f"baseword mismatch: expected {baseword!r}, got {result['baseword']!r}"
        )
        assert result["rule"] == rule, f"rule mismatch: expected {rule!r}, got {result['rule']!r}"
        assert result["candidate"] == candidate, (
            f"candidate mismatch: expected {candidate!r}, got {result['candidate']!r}"
        )


# ---------------------------------------------------------------------------
# TestFormatDetection
# ---------------------------------------------------------------------------


class TestFormatDetection:
    """Tests for _detect_format heuristics."""

    def _make_space_lines(self, n: int) -> list[str]:
        """Generate n valid space-format lines."""
        words = ["football", "password", "monkey", "dragon", "princess", "baseball"]
        rules = ["u", "c", "l", "r", "d", "f"]
        candidates = ["FOOTBALL", "Password", "monkey", "nogarD", "princessprincess", "llabesab"]
        lines = []
        for i in range(n):
            w, r, c = words[i % len(words)], rules[i % len(rules)], candidates[i % len(candidates)]
            lines.append(f"{w} {r} {c}")
        return lines

    def _make_colon_lines(self, n: int) -> list[str]:
        """Generate n valid colon-format lines."""
        words = ["football", "password", "monkey", "dragon", "princess", "baseball"]
        rules = ["u", "c", "l", "r", "d", "f"]
        candidates = ["FOOTBALL", "Password", "monkey", "nogarD", "princessprincess", "llabesab"]
        lines = []
        for i in range(n):
            w, r, c = words[i % len(words)], rules[i % len(rules)], candidates[i % len(candidates)]
            lines.append(f"{w}:{r}:{c}")
        return lines

    def test_pure_space_detection(self) -> None:
        """Twenty space-format lines should be detected as 'space'."""
        lines = self._make_space_lines(20)
        parser = DebugLogParser()
        assert parser._detect_format(lines) == "space"

    def test_space_with_malformed_minority(self) -> None:
        """Space format detected when 9 of 20 lines are malformed (not matching either format)."""
        space_lines = self._make_space_lines(20)
        # Replace 9 lines with malformed content
        malformed = ["notvalid"] * 9
        mixed = space_lines[:11] + malformed
        parser = DebugLogParser()
        # Malformed lines get no votes; 11 space-format lines vote space
        assert parser._detect_format(mixed) == "space"

    def test_pure_colon_detection(self) -> None:
        """Ten colon-format lines should be detected as 'colon'."""
        lines = self._make_colon_lines(10)
        parser = DebugLogParser()
        assert parser._detect_format(lines) == "colon"

    def test_empty_returns_space(self) -> None:
        """Empty input should default to 'space'."""
        parser = DebugLogParser()
        assert parser._detect_format([]) == "space"

    def test_space_format_with_colon_in_baseword(self) -> None:
        """Space-format lines where the space-split baseword contains a colon.

        When ALL lines have colon-in-baseword, the detector votes colon for each.
        This test verifies that a MAJORITY of plain space lines tips the balance back to 'space'.
        """
        # 6 plain space lines (no colon in baseword) → 6 space_votes
        # 3 colon-in-baseword space lines → 3 colon_votes
        # Result: space_votes (6) > colon_votes (3) → "space"
        plain = self._make_space_lines(6)
        colon_baseword = [
            "foo:bar u FOO:BAR",
            "biz:baz c Biz:baz",
            "pass:word r drow:ssap",
        ]
        lines = plain + colon_baseword
        parser = DebugLogParser()
        assert parser._detect_format(lines) == "space"

    def test_colon_majority_wins(self) -> None:
        """When colon lines outnumber space lines, detection returns 'colon'."""
        colon_lines = self._make_colon_lines(15)
        space_lines = self._make_space_lines(5)
        # Colon lines where no colons in baseword may vote as space (space_parts has 1 element,
        # has_space_format=True, has_colon_format=True, no colon in space_parts[0]) → space_votes
        # Actually pure colon lines like "football:u:FOOTBALL" have space-split of 1 part →
        # has_space_format=False, has_colon_format=True → colon_votes
        lines = colon_lines + space_lines
        parser = DebugLogParser()
        assert parser._detect_format(lines) == "colon"


# ---------------------------------------------------------------------------
# TestIdempotence
# ---------------------------------------------------------------------------


class TestIdempotence:
    """Parsing the same file twice with separate instances must produce identical results."""

    @pytest.mark.parametrize(
        "log_file",
        [p for p, _ in _fixture_pairs()],
        ids=[p.stem for p, _ in _fixture_pairs()],
    )
    def test_parse_idempotent(self, log_file: pathlib.Path) -> None:
        """Two independent parses of the same file must yield identical entries."""
        parser_a = DebugLogParser()
        parser_b = DebugLogParser()
        result_a = parser_a.parse_debug_file(str(log_file))
        result_b = parser_b.parse_debug_file(str(log_file))

        assert len(result_a) == len(result_b), (
            f"{log_file.name}: first parse={len(result_a)}, second parse={len(result_b)}"
        )
        for i, (a, b) in enumerate(zip(result_a, result_b)):
            for field in ("baseword", "rule", "candidate", "matched"):
                assert a[field] == b[field], (
                    f"{log_file.name}[{i}].{field}: first={a[field]!r}, second={b[field]!r}"
                )
