"""
Data models for PQC Scanner
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Severity(Enum):
    """Issue severity levels"""

    INFO = 1
    WARNING = 2
    CRITICAL = 3


@dataclass
class Issue:
    """Represents a single PQC vulnerability"""

    file_path: Path
    line_number: int
    severity: Severity
    title: str
    description: str
    remediation: str
    nist_reference: Optional[str] = None
    code_snippet: Optional[str] = None

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.file_path}:{self.line_number} - {self.title}"


@dataclass
class Report:
    """Complete scan report"""

    scan_time: datetime
    root_path: Path
    files_scanned: int
    issues: List[Issue]
    days_until_deadline: int
    readiness_score: int = field(init=False)

    def __post_init__(self) -> None:
        """Calculate readiness score"""
        # Base score
        score = 100

        # Deduct points for issues
        for issue in self.issues:
            if issue.severity == Severity.CRITICAL:
                score -= 10
            elif issue.severity == Severity.WARNING:
                score -= 3
            else:
                score -= 1

        self.readiness_score = max(0, score)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.INFO)
