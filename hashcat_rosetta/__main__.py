"""Allow the package to be run as a module: python -m hashcat_rosetta"""

import click
import json
import csv
from pathlib import Path
from .debug_analyzer import DebugAnalyzer
from .formatting import display_rule_opcodes_summary

@click.command(cls=click.Group, invoke_without_command=True)
@click.pass_context
def main(ctx):
    """Hashcat Rule Efficiency Analyzer - Analyze hashcat debug output files.
    
    Use 'hashcat-rosetta COMMAND [OPTIONS]' to run specific commands.
    """
    if ctx.invoked_subcommand is None:
        # No subcommand, show help
        click.echo(ctx.get_help())

@main.command('analyze')
@click.argument('file', type=click.Path(exists=True))
def analyze(file):
    """Analyze a hashcat debug mode 4 output file."""
    analyzer = DebugAnalyzer()
    result = analyzer.analyze_debug_file(file)
    
    click.echo(f"\n📊 Debug File Analysis: {file}")
    click.echo(f"{'='*60}")
    click.echo(f"Total lines processed: {result['total_lines']}")
    click.echo(f"Unique rules found: {result['unique_rules']}")
    click.echo(f"Unique basewords: {result['unique_basewords']}")
    click.echo(f"Total candidates generated: {result['total_candidates']}")
    click.echo(f"{'='*60}\n")

@main.command('show-rules')
@click.argument('file', type=click.Path(exists=True))
@click.option('--metric', type=click.Choice(['frequency', 'basewords', 'candidates']), 
              default='frequency', help='Metric to rank rules by')
@click.option('--top', default=10, help='Number of top rules to show')
def show_rules(file, metric, top):
    """Show the most efficient rules from a debug file."""
    analyzer = DebugAnalyzer()
    analyzer.analyze_debug_file(file)
    
    if metric == 'frequency':
        rules = analyzer.get_top_rules_by_frequency(top)
        click.echo(f"\n🔝 Top {top} Rules by Application Frequency:")
    elif metric == 'basewords':
        rules = analyzer.get_top_rules_by_basewords(top)
        click.echo(f"\n🔝 Top {top} Rules by Unique Basewords:")
    else:  # candidates
        rules = analyzer.get_top_rules_by_candidates(top)
        click.echo(f"\n🔝 Top {top} Rules by Candidates Generated:")
    
    click.echo(f"{'='*60}")
    for i, (rule, count) in enumerate(rules, 1):
        click.echo(f"{i:2d}. '{rule}' → {count}")
    click.echo(f"{'='*60}\n")

@main.command('show-basewords')
@click.argument('file', type=click.Path(exists=True))
@click.option('--min-occurrences', default=2, help='Minimum occurrences to display')
@click.option('--detail', is_flag=True, help='Show detailed rule applications')
@click.option('--top', default=20, help='Number of top basewords to show')
def show_basewords(file, min_occurrences, detail, top):
    """Show basewords that appear multiple times."""
    analyzer = DebugAnalyzer()
    analyzer.analyze_debug_file(file)
    
    basewords = analyzer.get_basewords_with_min_occurrences(min_occurrences)
    
    # Limit to top N
    basewords = basewords[:top]
    
    click.echo(f"\n📝 Basewords with {min_occurrences}+ occurrences (showing top {top}):")
    click.echo(f"{'='*60}")
    
    for baseword, count in basewords:
        click.echo(f"\n'{baseword}' → {count} occurrences")
        
        if detail:
            details = analyzer.get_baseword_details(baseword)
            for i, (rule, candidate) in enumerate(details[:5], 1):  # Show first 5
                click.echo(f"  {i}. Rule: '{rule}' → '{candidate}'")
            if len(details) > 5:
                click.echo(f"  ... and {len(details) - 5} more")
    
    click.echo(f"{'='*60}\n")

@main.command('export-report')
@click.argument('file', type=click.Path(exists=True))
@click.argument('output', type=click.Path())
@click.option('--format', type=click.Choice(['json', 'csv']), default='json',
              help='Export format')
def export_report(file, output, format):
    """Export analysis results to JSON or CSV."""
    analyzer = DebugAnalyzer()
    analyzer.analyze_debug_file(file)
    
    output_path = Path(output)
    
    if format == 'json':
        report = analyzer.generate_report()
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        click.echo(f"✅ JSON report exported to: {output_path}")
    
    else:  # csv
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write rule statistics
            writer.writerow(['Rule', 'Frequency', 'Unique Basewords', 'Candidates Generated'])
            for rule, stats in analyzer.rule_stats.items():
                writer.writerow([
                    rule,
                    stats['count'],
                    stats['unique_basewords'],
                    stats['candidates_generated']
                ])
        
        click.echo(f"✅ CSV report exported to: {output_path}")

@main.command('analyze-rules')
@click.argument('rule_file', type=click.Path(exists=True))
def analyze_rules(rule_file):
    """Analyze rule file and display opcode statistics.
    
    Show frequency and distribution of rule opcodes in a rule file.
    
    Examples:
        hashcat-rosetta analyze-rules rules.txt
        hashcat-rosetta analyze-rules /hash/rules/buka_400k.rule
    """
    display_rule_opcodes_summary(rule_file)

if __name__ == '__main__':
    main()
