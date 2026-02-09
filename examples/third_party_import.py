"""
Example of importing and using hashcat_rosetta as a third-party library.

This shows how other Python projects can import and use the analyzer.
"""

# Import the main classes
from hashcat_rosetta import (
    DebugAnalyzer,      # For analyzing debug files
    DebugLogParser,     # For low-level parsing
    )

def example_third_party_usage():
    """Example showing typical third-party usage."""
    
    print("Example: Third-Party Library Integration")
    print("=" * 60)
    
    # 1. Quick debug file analysis
    analyzer = DebugAnalyzer()
    result = analyzer.analyze_debug_file('examples/sample_debug.txt')
    
    print("\n✓ Analyzed debug file:")
    print(f"  - Total entries: {result['total_entries']}")
    print(f"  - Unique rules: {result['unique_rules']}")
    print(f"  - Unique basewords: {result['unique_basewords']}")
    
    # 2. Get efficiency metrics
    top_rules = analyzer.get_top_rules_by_frequency(3)
    print("\n✓ Top 3 rules by frequency:")
    for rule, count in top_rules:
        print(f"  - Rule '{rule}': {count} applications")
    
    # 3. Track baseword patterns
    basewords = analyzer.get_basewords_with_min_occurrences(5)
    print(f"\n✓ Basewords appearing 5+ times: {len(basewords)}")
    for word, count in basewords[:3]:
        print(f"  - '{word}': {count} occurrences")
    
    # 4. Export for further processing
    export_data = analyzer.export_to_dict()
    print(f"\n✓ Export contains {len(export_data)} data sections")
    
    # 5. Low-level parsing
    parser = DebugLogParser()
    lines = [
        "password c P@ssword",
        "admin u ADMIN",
        "test123 l test123"
    ]
    entries = parser.parse_debug_lines(lines)
    print(f"\n✓ Parsed {len(entries)} entries from custom data")
    
    print("\n" + "=" * 60)
    print("Integration complete!")


if __name__ == "__main__":
    example_third_party_usage()
