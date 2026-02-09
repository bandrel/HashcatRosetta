"""Analyzer module for evaluating hashcat rule efficiency."""

from .parser import RuleParser


class RuleAnalyzer:
    """Analyze hashcat rules for efficiency and effectiveness."""

    def __init__(self):
        """Initialize the rule analyzer."""
        self.parser = RuleParser()
        self.analyzed_rules = []

    def analyze_rule(self, rule_string: str) -> dict | None:
        """
        Analyze a single rule for efficiency metrics.

        Args:
            rule_string: The hashcat rule to analyze

        Returns:
            Dictionary containing analysis results
        """
        parsed = self.parser.parse_rule(rule_string)
        if not parsed:
            return None

        return {
            "rule": rule_string,
            "component_count": len(parsed["components"]),
            "complexity": parsed["complexity"],
            "efficiency_score": self._calculate_efficiency(parsed),
            "characteristics": self._extract_characteristics(parsed),
        }

    def analyze_ruleset(self, rules: list) -> dict | None:
        """
        Analyze a complete ruleset for efficiency and coverage.

        Args:
            rules: List of rule strings

        Returns:
            Dictionary containing ruleset analysis
        """
        analyses = []
        for rule in rules:
            analysis = self.analyze_rule(rule)
            if analysis:
                analyses.append(analysis)

        if not analyses:
            return None

        return {
            "total_rules": len(analyses),
            "average_complexity": sum(a["complexity"] for a in analyses) / len(analyses),
            "average_efficiency": sum(a["efficiency_score"] for a in analyses) / len(analyses),
            "rule_analyses": analyses,
            "statistics": self._compute_statistics(analyses),
        }

    def _calculate_efficiency(self, parsed_rule: dict) -> float:
        """
        Calculate efficiency score (higher is better).

        Args:
            parsed_rule: Parsed rule dictionary

        Returns:
            Efficiency score (0-100)
        """
        # Efficiency inversely correlated with complexity but considering rule length
        components = parsed_rule["components"]
        complexity = parsed_rule["complexity"]

        if not components:
            return 0.0

        # Sweet spot: 3-5 components with moderate complexity
        optimal_count = 4
        count_diff = abs(len(components) - optimal_count)
        count_penalty = count_diff * 5

        efficiency = max(0, 100 - complexity - count_penalty)
        return efficiency

    def _extract_characteristics(self, parsed_rule: dict) -> list:
        """
        Extract characteristics of the rule.

        Args:
            parsed_rule: Parsed rule dictionary

        Returns:
            List of rule characteristics
        """
        characteristics = []
        components = parsed_rule["components"]

        if any(c in ["i", "u", "l"] for c in components):
            characteristics.append("case_transform")
        if any(c.startswith(("d", "p", "x", "X")) for c in components):
            characteristics.append("substitution")
        if any(c.startswith(("^", "$")) for c in components):
            characteristics.append("position_based")
        if any(c in ["r", "R"] for c in components):
            characteristics.append("reversal")
        if len(components) > 5:
            characteristics.append("complex")

        return characteristics

    def _compute_statistics(self, analyses: list) -> dict:
        """
        Compute statistics across multiple rule analyses.

        Args:
            analyses: List of rule analysis dictionaries

        Returns:
            Statistics dictionary
        """
        if not analyses:
            return {}

        complexities = [a["complexity"] for a in analyses]
        efficiencies = [a["efficiency_score"] for a in analyses]

        return {
            "complexity_range": (min(complexities), max(complexities)),
            "efficiency_range": (min(efficiencies), max(efficiencies)),
            "complexity_std": self._std_dev(complexities),
            "efficiency_std": self._std_dev(efficiencies),
        }

    @staticmethod
    def _std_dev(values: list) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
