"""
Text (terminal) reporter with Rich formatting
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from pqc_scanner.models import Report, Severity


class TextReporter:
    """Generate rich terminal output"""

    def __init__(self):
        self.console = Console()

    def generate(self, report: Report) -> str:
        """Generate formatted text report"""
        output = []

        # Header
        header = Panel(
            f"[bold cyan]PQC Migration Scanner v0.1.0[/bold cyan]\n"
            f"Cloudflare 2029 Deadline: [yellow]{report.days_until_deadline}[/yellow] days away",
            expand=False,
        )
        output.append(self._render_to_string(header))

        # Summary
        output.append(f"\n🔍 Scanned: {report.files_scanned} files")
        output.append(f"⚠️  Issues Found: {len(report.issues)}\n")

        # Issues by severity
        if report.critical_count > 0:
            output.append(self._render_severity_section("CRITICAL", report, Severity.CRITICAL))

        if report.warning_count > 0:
            output.append(self._render_severity_section("WARNING", report, Severity.WARNING))

        if report.info_count > 0:
            output.append(self._render_severity_section("INFO", report, Severity.INFO))

        # Readiness score
        score_color = "green" if report.readiness_score >= 80 else "yellow" if report.readiness_score >= 50 else "red"
        
        effort = "4-8 weeks" if report.readiness_score >= 70 else "8-16 weeks" if report.readiness_score >= 40 else "16-24 weeks"
        
        priority = "LOW" if report.readiness_score >= 80 else "MEDIUM" if report.readiness_score >= 50 else "HIGH"
        
        summary_panel = Panel(
            f"[{score_color}]PQC Readiness Score: {report.readiness_score}/100[/{score_color}]\n"
            f"Estimated Migration Effort: {effort}\n"
            f"Priority: {priority} ({report.days_until_deadline} days to deadline)",
            expand=False,
        )
        output.append(self._render_to_string(summary_panel))

        # Next steps
        output.append("\n📝 Full report: pqc-report.md")
        output.append("🎯 Next steps: Run 'pqc-scan . --fix' for auto-remediation")

        return "\n".join(output)

    def _render_severity_section(self, title: str, report: Report, severity: Severity) -> str:
        """Render issues of a specific severity"""
        issues = [i for i in report.issues if i.severity == severity]
        if not issues:
            return ""

        lines = [f"\n{title} ({len(issues)})"]
        lines.append("━" * 80)

        for issue in issues[:10]:  # Limit to first 10 per severity
            lines.append(f"  • {issue.file_path}:{issue.line_number}")
            lines.append(f"    {issue.title}")
            lines.append(f"    Remediation: {issue.remediation.split(chr(10))[0]}")
            if issue.nist_reference:
                lines.append(f"    NIST Reference: {issue.nist_reference}")
            lines.append("")

        if len(issues) > 10:
            lines.append(f"  ... and {len(issues) - 10} more {title.lower()} issues")

        return "\n".join(lines)

    def _render_to_string(self, renderable) -> str:
        """Render Rich object to string"""
        with self.console.capture() as capture:
            self.console.print(renderable)
        return capture.get()
