"""
Detector for OpenSSL version issues
"""

import re
from pathlib import Path
from typing import List

from pqc_scanner.models import Issue, Severity


class OpenSSLDetector:
    """Detects outdated OpenSSL versions"""

    PATTERNS = [
        # Direct version specifications
        (r"openssl[_-]?(?:version)?[\s:=]+[\"']?(1\.[0-1]\.\d+)", "OpenSSL 1.0.x/1.1.x"),
        (r"OPENSSL_VERSION\s*=\s*[\"'](1\.[0-1]\.\d+)", "OpenSSL 1.0.x/1.1.x"),
        # Package manager dependencies
        (r"libssl1\.1", "OpenSSL 1.1 library"),
        (r"openssl@1\.1", "OpenSSL 1.1 via Homebrew"),
        # Dockerfile base images
        (r"FROM\s+ubuntu:(16\.04|18\.04|20\.04)", "Ubuntu with old OpenSSL"),
        (r"FROM\s+debian:(stretch|buster)", "Debian with old OpenSSL"),
        # CMake/Make configuration
        (r"find_package\(OpenSSL\s+1\.[0-1]", "CMake requiring old OpenSSL"),
    ]

    def detect(self, file_path: Path, content: str) -> List[Issue]:
        """Detect OpenSSL version issues"""
        issues = []

        for pattern, description in self.PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1
                version = match.group(1) if match.lastindex else "unknown"

                issues.append(
                    Issue(
                        file_path=file_path,
                        line_number=line_number,
                        severity=Severity.CRITICAL,
                        title=f"Outdated OpenSSL version detected: {description}",
                        description=(
                            f"OpenSSL version {version} does not support post-quantum "
                            "cryptography algorithms. OpenSSL 3.0 or later is required "
                            "for ML-KEM and ML-DSA support."
                        ),
                        remediation=(
                            "Upgrade to OpenSSL 3.0 or later. For system packages, "
                            "upgrade to Ubuntu 22.04+, Debian 12+, or RHEL 9+. "
                            "For containerized apps, use updated base images."
                        ),
                        nist_reference="NIST IR 8413",
                        code_snippet=self._get_snippet(content, match.start()),
                    )
                )

        return issues

    def _get_snippet(self, content: str, position: int, context: int = 50) -> str:
        """Extract code snippet around position"""
        start = max(0, position - context)
        end = min(len(content), position + context)
        return content[start:end].strip()
