"""
JSON reporter for programmatic consumption
"""

import json
from datetime import datetime

from pqc_scanner.models import Report


class JSONReporter:
    """Generate JSON output"""

    def generate(self, report: Report) -> str:
        """Generate JSON report"""
        data = {
            "scan_time": report.scan_time.isoformat(),
            "root_path": str(report.root_path),
            "files_scanned": report.files_scanned,
            "readiness_score": report.readiness_score,
            "days_until_deadline": report.days_until_deadline,
            "summary": {
                "total_issues": len(report.issues),
                "critical": report.critical_count,
                "warning": report.warning_count,
                "info": report.info_count,
            },
            "issues": [
                {
                    "file_path": str(issue.file_path),
                    "line_number": issue.line_number,
                    "severity": issue.severity.name,
                    "title": issue.title,
                    "description": issue.description,
                    "remediation": issue.remediation,
                    "nist_reference": issue.nist_reference,
                    "code_snippet": issue.code_snippet,
                }
                for issue in report.issues
            ],
        }

        return json.dumps(data, indent=2)
