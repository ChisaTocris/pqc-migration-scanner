"""
Detector for insufficient key sizes
"""

import re
from pathlib import Path
from typing import List

from pqc_scanner.models import Issue, Severity


class KeyDetector:
    """Detects insufficient key sizes for PQC transition"""

    KEY_PATTERNS = [
        # RSA key size specifications
        (r"rsa[_-]?(?:key)?[_-]?size[\s:=]+(\d+)", "RSA key size"),
        (r"RSA\.generate\((\d+)\)", "Python RSA key generation"),
        (r"genrsa\s+(\d+)", "OpenSSL RSA generation"),
        (r"KEY_SIZE\s*=\s*(\d+)", "Hardcoded key size"),
        # SSH key generation
        (r"ssh-keygen.*-b\s+(\d+)", "SSH key generation"),
        # ECDSA curves
        (r"secp256[kr]1|prime256v1|P-256", "ECDSA P-256 curve"),
        # DSA keys (deprecated)
        (r"dsa[_-]?(?:key)?[_-]?size", "DSA key"),
    ]

    # Minimum recommended key sizes
    MIN_RSA_SIZE = 3072  # For PQC transition period
    MIN_ECDSA_SIZE = 384  # P-384 minimum

    def detect(self, file_path: Path, content: str) -> List[Issue]:
        """Detect insufficient key sizes"""
        issues = []

        for pattern, description in self.KEY_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1

                # Extract key size if present
                key_size = None
                if match.lastindex:
                    try:
                        key_size = int(match.group(1))
                    except (ValueError, IndexError):
                        pass

                # Determine severity
                severity = Severity.INFO
                title = f"Key configuration found: {description}"
                remediation = "Review key size against PQC recommendations"

                # RSA key analysis
                if "rsa" in description.lower() and key_size:
                    if key_size < 2048:
                        severity = Severity.CRITICAL
                        title = f"Critically weak RSA key: {key_size} bits"
                        remediation = (
                            f"RSA {key_size}-bit keys are insufficient. "
                            "Immediate action required:\n"
                            "1. Generate new 3072-bit RSA keys minimum\n"
                            "2. Rotate all certificates and credentials\n"
                            "3. Plan migration to ML-DSA-65 by 2028"
                        )
                    elif key_size < self.MIN_RSA_SIZE:
                        severity = Severity.CRITICAL
                        title = f"Insufficient RSA key size: {key_size} bits"
                        remediation = (
                            f"RSA {key_size}-bit keys will not provide adequate "
                            "security during PQC transition. Upgrade to 3072+ bits:\n"
                            "1. Generate 3072-bit RSA keys\n"
                            "2. Update all dependent systems\n"
                            "3. Plan hybrid classical-PQ signing"
                        )

                # ECDSA curve analysis
                elif "ecdsa" in description.lower() or "p-256" in description.lower():
                    severity = Severity.WARNING
                    title = "ECDSA P-256 curve detected"
                    remediation = (
                        "P-256 may be insufficient for post-quantum transition:\n"
                        "1. Upgrade to P-384 or P-521 curves\n"
                        "2. Consider hybrid X25519+ML-KEM for key exchange\n"
                        "3. Migrate to ML-DSA for signatures by 2028"
                    )

                # DSA detection
                elif "dsa" in description.lower():
                    severity = Severity.CRITICAL
                    title = "DSA keys detected (deprecated)"
                    remediation = (
                        "DSA is deprecated and not quantum-resistant:\n"
                        "1. Immediately migrate to RSA 3072+ or ECDSA P-384+\n"
                        "2. Plan migration to ML-DSA-65\n"
                        "3. Rotate all DSA-signed certificates"
                    )

                issues.append(
                    Issue(
                        file_path=file_path,
                        line_number=line_number,
                        severity=severity,
                        title=title,
                        description=(
                            f"Found {description} configuration. "
                            "Key sizes must be sufficient for post-quantum transition "
                            "period (2025-2029) even before full PQC deployment."
                        ),
                        remediation=remediation,
                        nist_reference="NIST SP 800-57 Part 1 Rev. 5",
                        code_snippet=match.group(0),
                    )
                )

        return issues
