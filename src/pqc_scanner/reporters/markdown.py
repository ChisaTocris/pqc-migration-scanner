"""
Markdown reporter for documentation/reports
"""

from pqc_scanner.models import Report, Severity


class MarkdownReporter:
    """Generate Markdown report"""

    def generate(self, report: Report) -> str:
        """Generate markdown report"""
        lines = [
            "# PQC Migration Scanner Report",
            "",
            f"**Scan Date:** {report.scan_time.strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Root Path:** `{report.root_path}`  ",
            f"**Files Scanned:** {report.files_scanned}  ",
            f"**Days Until 2029 Deadline:** {report.days_until_deadline}  ",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"- **PQC Readiness Score:** {report.readiness_score}/100",
            f"- **Total Issues:** {len(report.issues)}",
            f"  - Critical: {report.critical_count}",
            f"  - Warning: {report.warning_count}",
            f"  - Info: {report.info_count}",
            "",
        ]

        # Critical issues
        if report.critical_count > 0:
            lines.extend(self._render_severity_section("Critical Issues", report, Severity.CRITICAL))

        # Warning issues
        if report.warning_count > 0:
            lines.extend(self._render_severity_section("Warnings", report, Severity.WARNING))

        # Info issues
        if report.info_count > 0:
            lines.extend(self._render_severity_section("Informational", report, Severity.INFO))

        # Recommendations
        lines.extend(
            [
                "",
                "---",
                "",
                "## Recommended Actions",
                "",
                "1. **Address Critical Issues Immediately**",
                "   - Upgrade OpenSSL to 3.0+",
                "   - Enable TLS 1.3",
                "   - Replace weak cipher suites",
                "",
                "2. **Plan Migration Timeline**",
                "   - Q1 2027: Complete infrastructure upgrades",
                "   - Q2-Q3 2027: Implement hybrid classical-PQ crypto",
                "   - Q4 2027: Begin full PQC rollout",
                "   - Q1 2028: Complete migration testing",
                "",
                "3. **Resources**",
                "   - [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)",
                "   - [Cloudflare PQC Migration Guide](https://blog.cloudflare.com/post-quantum-cryptography-2029)",
                "   - [OpenSSL 3.0 Documentation](https://www.openssl.org/docs/man3.0/)",
                "",
            ]
        )

        return "\n".join(lines)

    def _render_severity_section(self, title: str, report: Report, severity: Severity) -> list:
        """Render markdown section for a severity level"""
        issues = [i for i in report.issues if i.severity == severity]
        lines = [
            "",
            f"## {title} ({len(issues)})",
            "",
        ]

        for i, issue in enumerate(issues, 1):
            lines.extend(
                [
                    f"### {i}. {issue.title}",
                    "",
                    f"**File:** `{issue.file_path}:{issue.line_number}`  ",
                    f"**Description:** {issue.description}  ",
                    "",
                    "**Remediation:**",
                    "```",
                    issue.remediation,
                    "```",
                    "",
                ]
            )

            if issue.nist_reference:
                lines.append(f"**NIST Reference:** {issue.nist_reference}  ")

            if issue.code_snippet:
                lines.extend(["", "**Code Snippet:**", "```", issue.code_snippet, "```", ""])

        return lines
