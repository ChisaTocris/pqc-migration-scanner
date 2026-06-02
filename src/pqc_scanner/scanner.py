"""
Core scanning engine for PQC vulnerabilities
"""

from pathlib import Path
from typing import List, Optional
from datetime import datetime

from pqc_scanner.models import Issue, Report
from pqc_scanner.detectors.openssl import OpenSSLDetector
from pqc_scanner.detectors.tls import TLSDetector
from pqc_scanner.detectors.cipher import CipherDetector
from pqc_scanner.detectors.keys import KeyDetector
from pqc_scanner.detectors.hardcoded import HardcodedCryptoDetector
from pqc_scanner.detectors.language import LanguageCryptoDetector


class PQCScanner:
    """Main scanner that coordinates all detection modules"""

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".go",
        ".rs",
        ".java",
        ".cs",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".sh",
        ".yml",
        ".yaml",
        ".json",
        ".conf",
        ".config",
        ".xml",
        ".toml",
        ".ini",
        ".env",
    }

    # Directories to exclude by default
    DEFAULT_EXCLUDES = {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "vendor",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
    }

    def __init__(
        self,
        root_path: Path,
        config_path: Optional[Path] = None,
        exclude_patterns: Optional[List[str]] = None,
        verbose: bool = False,
    ):
        self.root_path = root_path
        self.verbose = verbose
        self.exclude_patterns = set(exclude_patterns or [])
        self.exclude_patterns.update(self.DEFAULT_EXCLUDES)

        # Initialize detectors
        self.detectors = [
            OpenSSLDetector(),
            TLSDetector(),
            CipherDetector(),
            KeyDetector(),
            HardcodedCryptoDetector(),
            LanguageCryptoDetector(),
        ]

        # Calculate deadline
        self.deadline = datetime(2029, 1, 1)
        self.days_until_deadline = (self.deadline - datetime.now()).days

    def scan(self) -> Report:
        """Run full scan and return report"""
        issues: List[Issue] = []
        files_scanned = 0

        # Collect all files to scan
        files = self._collect_files()

        # Scan each file
        for file_path in files:
            files_scanned += 1
            if self.verbose and files_scanned % 100 == 0:
                print(f"Scanned {files_scanned}/{len(files)} files...")

            try:
                content = file_path.read_text(errors="ignore")
                file_issues = self._scan_file(file_path, content)
                issues.extend(file_issues)
            except Exception as e:
                if self.verbose:
                    print(f"Error scanning {file_path}: {e}")
                continue

        # Generate report
        report = Report(
            scan_time=datetime.now(),
            root_path=self.root_path,
            files_scanned=files_scanned,
            issues=issues,
            days_until_deadline=self.days_until_deadline,
        )

        return report

    def _collect_files(self) -> List[Path]:
        """Collect all files to scan"""
        files = []

        for path in self.root_path.rglob("*"):
            # Skip directories
            if path.is_dir():
                continue

            # Skip excluded directories
            if any(excluded in path.parts for excluded in self.exclude_patterns):
                continue

            # Only scan relevant file types
            if path.suffix in self.SCANNABLE_EXTENSIONS:
                files.append(path)

        return files

    def _scan_file(self, file_path: Path, content: str) -> List[Issue]:
        """Scan a single file with all detectors"""
        issues = []

        for detector in self.detectors:
            try:
                detector_issues = detector.detect(file_path, content)
                issues.extend(detector_issues)
            except Exception as e:
                if self.verbose:
                    print(f"Detector {detector.__class__.__name__} error on {file_path}: {e}")

        return issues
