"""Example usage of the hashcat debug file analyzer."""

from hashcat_rosetta import DebugAnalyzer, DebugLogParser

# Example 1: Parse and analyze a debug file
print("=" * 70)
print("Example 1: Analyzing a Hashcat Debug File")
print("=" * 70)

analyzer = DebugAnalyzer()

# Analyze the sample debug file
result = analyzer.analyze_debug_file("examples/sample_debug.txt")

print("\nFile Analysis Summary:")
print(f"  Total Entries: {result['total_entries']}")
print(f"  Unique Rules: {result['unique_rules']}")
print(f"  Unique Basewords: {result['unique_basewords']}")

# Example 2: Get top rules by frequency
print("\n" + "=" * 70)
print("Example 2: Top Rules by Application Frequency")
print("=" * 70)

top_rules = analyzer.get_top_rules_by_frequency(5)
for i, (rule, count) in enumerate(top_rules, 1):
    print(f"{i}. Rule '{rule}': applied {count} times")

# Example 3: Get top rules by baseword coverage
print("\n" + "=" * 70)
print("Example 3: Top Rules by Unique Baseword Coverage")
print("=" * 70)

top_basewords = analyzer.get_top_rules_by_unique_basewords(5)
for i, (rule, unique_count) in enumerate(top_basewords, 1):
    print(f"{i}. Rule '{rule}': applied to {unique_count} unique basewords")

# Example 4: Get top rules by candidate generation
print("\n" + "=" * 70)
print("Example 4: Top Rules by Unique Candidate Generation")
print("=" * 70)

top_candidates = analyzer.get_top_rules_by_unique_candidates(5)
for i, (rule, candidate_count) in enumerate(top_candidates, 1):
    print(f"{i}. Rule '{rule}': generated {candidate_count} unique candidates")

# Example 5: Get most frequent basewords
print("\n" + "=" * 70)
print("Example 5: Most Frequent Basewords")
print("=" * 70)

top_basewords_list = analyzer.get_top_basewords_by_frequency(5)
for i, (baseword, count) in enumerate(top_basewords_list, 1):
    print(f"{i}. '{baseword}': appears {count} times")

# Example 6: Basewords appearing multiple times
print("\n" + "=" * 70)
print("Example 6: Basewords Appearing 2+ Times with Details")
print("=" * 70)

frequent_basewords = analyzer.get_basewords_with_min_occurrences(2)
for baseword, count in frequent_basewords[:3]:
    detail = analyzer.get_baseword_detail(baseword)
    if detail:
        print(f"\nBaseword: '{baseword}'")
        print(f"  Total Occurrences: {count}")
        print(f"  Unique Rules Applied: {detail['unique_rules']}")
        print(f"  Unique Candidates: {detail['unique_candidates']}")
        print(
            f"  Rules Used: {', '.join(sorted(set(occ['rule'] for occ in detail['occurrences'])))}"
        )

# Example 7: Detailed rule analysis
print("\n" + "=" * 70)
print("Example 7: Detailed Rule Analysis")
print("=" * 70)

rule_detail = analyzer.get_rule_detail("c")
if rule_detail:
    print(f"\nRule: '{rule_detail['rule']}'")
    print(f"  Total Applications: {rule_detail['total_applications']}")
    print(f"  Unique Basewords: {rule_detail['unique_basewords']}")
    print(f"  Unique Candidates: {rule_detail['unique_candidates']}")

# Example 8: Statistics summary
print("\n" + "=" * 70)
print("Example 8: Rule Statistics Summary")
print("=" * 70)

rule_stats = analyzer.get_rule_statistics_summary()
print("\nRules:")
print(f"  Total Rules: {rule_stats['total_rules']}")
print(f"  Total Applications: {rule_stats['total_applications']}")
print(f"  Average/Rule: {rule_stats['avg_applications_per_rule']:.2f}")
print(f"  Max: {rule_stats['max_applications']}, Min: {rule_stats['min_applications']}")

baseword_stats = analyzer.get_baseword_statistics_summary()
print("\nBasewords:")
print(f"  Total Basewords: {baseword_stats['total_basewords']}")
print(f"  Total Occurrences: {baseword_stats['total_occurrences']}")
print(f"  Average/Baseword: {baseword_stats['avg_occurrences_per_baseword']:.2f}")
print(f"  Max: {baseword_stats['max_occurrences']}, Min: {baseword_stats['min_occurrences']}")

# Example 9: Using the low-level parser directly
print("\n" + "=" * 70)
print("Example 9: Low-level Debug Log Parsing")
print("=" * 70)

parser = DebugLogParser()
entries = parser.parse_debug_file("examples/sample_debug.txt")

print(f"\nParsed {len(entries)} entries from debug file")
print("\nFirst 3 entries:")
for entry in entries[:3]:
    print(
        f"  Baseword: '{entry['baseword']:15}' Rule: '{entry['rule']:5}' -> '{entry['candidate']}'"
    )

# Example 10: Exporting analysis data
print("\n" + "=" * 70)
print("Example 10: Exporting Analysis Data")
print("=" * 70)

export_data = analyzer.export_to_dict()
print("\nExported data contains:")
print("  - Summary statistics")
print(f"  - Top rules by frequency: {len(export_data['top_rules_by_frequency'])} rules")
print(f"  - Top rules by basewords: {len(export_data['top_rules_by_basewords'])} rules")
print(f"  - Top rules by candidates: {len(export_data['top_rules_by_candidates'])} rules")
print(f"  - Top basewords: {len(export_data['top_basewords'])} basewords")
print(f"  - Basewords with duplicates: {len(export_data['basewords_with_duplicates'])} basewords")
print(f"  - Full rule details: {len(export_data['all_rule_details'])} rules")
