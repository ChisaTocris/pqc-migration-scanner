"""
Detector for TLS configuration issues
"""

import re
from pathlib import Path
from typing import List

from pqc_scanner.models import Issue, Severity


class TLSDetector:
    """Detects weak TLS configurations"""

    PATTERNS = [
        # TLS version specifications
        (r"TLS[_v]?1[._]?[0-2]", Severity.CRITICAL, "TLS 1.0/1.1/1.2 configured"),
        (r"ssl_protocols.*TLSv1\.2", Severity.CRITICAL, "Nginx: TLS 1.2 only"),
        (r"SSLProtocol.*TLSv1\.2", Severity.CRITICAL, "Apache: TLS 1.2 only"),
        # Python SSL contexts
        (r"ssl\.PROTOCOL_TLSv1_2", Severity.CRITICAL, "Python: TLS 1.2 protocol"),
        (r"ssl\.PROTOCOL_TLS(?!v1_3)", Severity.WARNING, "Python: Non-specific TLS version"),
        # Go TLS config
        (r"MinVersion:\s*tls\.VersionTLS1[0-2]", Severity.CRITICAL, "Go: TLS 1.0/1.1/1.2 min"),
        (r"MaxVersion:\s*tls\.VersionTLS1[0-2]", Severity.CRITICAL, "Go: TLS 1.0/1.1/1.2 max"),
        # Node.js
        (r"secureProtocol:\s*[\"']TLSv1_2_method", Severity.CRITICAL, "Node: TLS 1.2 method"),
        (r"minVersion:\s*[\"']TLSv1\.2", Severity.CRITICAL, "Node: TLS 1.2 minimum"),
        # Java
        (r"SSLContext\.getInstance\([\"']TLSv1\.2", Severity.CRITICAL, "Java: TLS 1.2 context"),
    ]

    def detect(self, file_path: Path, content: str) -> List[Issue]:
        """Detect TLS configuration issues"""
        issues = []

        for pattern, severity, description in self.PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1

                issues.append(
                    Issue(
                        file_path=file_path,
                        line_number=line_number,
                        severity=severity,
                        title=f"Weak TLS configuration: {description}",
                        description=(
                            "TLS 1.2 and earlier versions do not support post-quantum "
                            "key exchange algorithms. TLS 1.3 is required for hybrid "
                            "classical-PQ cipher suites."
                        ),
                        remediation=(
                            "Upgrade to TLS 1.3 with hybrid cipher suites:\n"
                            "- Enable TLS_AES_256_GCM_SHA384 with X25519MLKEM768\n"
                            "- Configure server to prefer PQ-enabled clients\n"
                            "- Maintain TLS 1.3 backward compatibility during transition"
                        ),
                        nist_reference="NIST SP 800-52 Rev. 2",
                        code_snippet=match.group(0),
                    )
                )

        return issues
