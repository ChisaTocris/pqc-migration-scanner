"""
CLI interface for PQC Migration Scanner
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from pqc_scanner.scanner import PQCScanner
from pqc_scanner.models import Severity
from pqc_scanner.reporters.text import TextReporter
from pqc_scanner.reporters.json import JSONReporter
from pqc_scanner.reporters.markdown import MarkdownReporter

console = Console()


@click.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format",
    type=click.Choice(["text", "json", "markdown", "html"]),
    default="text",
    help="Output format",
)
@click.option("--output", type=click.Path(), help="Output file path")
@click.option(
    "--severity",
    type=click.Choice(["critical", "warning", "info"]),
    default="info",
    help="Minimum severity level",
)
@click.option("--badge", is_flag=True, help="Generate README badge")
@click.option("--config", type=click.Path(exists=True), help="Config file path")
@click.option("--exclude", multiple=True, help="Exclude file patterns")
@click.option("--verbose", is_flag=True, help="Verbose output")
@click.version_option()
def main(
    path: str,
    format: str,
    output: Optional[str],
    severity: str,
    badge: bool,
    config: Optional[str],
    exclude: tuple,
    verbose: bool,
) -> None:
    """
    Scan PATH for post-quantum cryptography vulnerabilities.
    
    Detects outdated OpenSSL versions, weak TLS configs, deprecated
    cipher suites, and insufficient key sizes before the 2029 deadline.
    """
    try:
        # Initialize scanner
        scanner = PQCScanner(
            root_path=Path(path),
            config_path=Path(config) if config else None,
            exclude_patterns=list(exclude),
            verbose=verbose,
        )

        # Run scan
        console.print("[yellow]🔍 Scanning for PQC vulnerabilities...[/yellow]")
        report = scanner.scan()

        # Filter by severity
        severity_level = Severity[severity.upper()]
        filtered_issues = [
            issue for issue in report.issues if issue.severity.value >= severity_level.value
        ]
        report.issues = filtered_issues

        # Generate output
        if format == "text":
            reporter = TextReporter()
            output_text = reporter.generate(report)
        elif format == "json":
            reporter = JSONReporter()
            output_text = reporter.generate(report)
        elif format == "markdown":
            reporter = MarkdownReporter()
            output_text = reporter.generate(report)
        else:
            console.print(f"[red]Unsupported format: {format}[/red]")
            sys.exit(1)

        # Write output
        if output:
            Path(output).write_text(output_text)
            console.print(f"[green]✓[/green] Report saved to {output}")
        else:
            console.print(output_text)

        # Generate badge
        if badge:
            badge_path = Path(path) / "pqc-badge.svg"
            badge_svg = _generate_badge(report)
            badge_path.write_text(badge_svg)
            console.print(f"[green]✓[/green] Badge saved to {badge_path}")

        # Exit with appropriate code
        critical_count = sum(1 for issue in report.issues if issue.severity == Severity.CRITICAL)
        if critical_count > 0:
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)


def _generate_badge(report) -> str:
    """Generate SVG badge based on scan results"""
    critical = sum(1 for i in report.issues if i.severity == Severity.CRITICAL)
    warning = sum(1 for i in report.issues if i.severity == Severity.WARNING)

    if critical > 0:
        color = "red"
        status = f"Critical ({critical})"
    elif warning > 0:
        color = "yellow"
        status = f"Warnings ({warning})"
    else:
        color = "green"
        status = "Ready"

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
  <rect width="40" height="20" fill="#555"/>
  <rect x="40" width="80" height="20" fill="{color}"/>
  <text x="5" y="15" fill="#fff" font-family="Arial" font-size="11">PQC</text>
  <text x="45" y="15" fill="#fff" font-family="Arial" font-size="11">{status}</text>
</svg>"""


if __name__ == "__main__":
    main()
