"""
Detector for deprecated cipher suites
"""

import re
from pathlib import Path
from typing import List

from pqc_scanner.models import Issue, Severity


class CipherDetector:
    """Detects deprecated cipher suites and algorithms"""

    # Cipher patterns mapped to severity
    CIPHER_PATTERNS = [
        # Weak/deprecated ciphers (CRITICAL)
        (r"(?:RSA|DES|3DES|RC4|MD5)(?:_|\b)", Severity.CRITICAL, "Deprecated cipher"),
        (r"ECDHE-RSA-AES", Severity.CRITICAL, "RSA-based ECDHE"),
        (r"DHE-RSA-AES", Severity.CRITICAL, "RSA-based DHE"),
        # Weak key exchange (CRITICAL)
        (r"kRSA|kDH(?!E)|kECDH(?!E)", Severity.CRITICAL, "Non-ephemeral key exchange"),
        # P-256 curve (WARNING - weak for PQC)
        (r"prime256v1|secp256r1|P-256", Severity.WARNING, "P-256 curve"),
        # AES-128 (WARNING - may be insufficient)
        (r"AES-?128", Severity.WARNING, "AES-128"),
        # Hardcoded cipher lists (INFO)
        (
            r"cipher.*suites?[\s:=]+[\[\{\"']",
            Severity.INFO,
            "Hardcoded cipher configuration",
        ),
    ]

    # PQC-ready cipher suites (should be present)
    PQC_READY_CIPHERS = [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "MLKEM768",
        "X25519MLKEM768",
    ]

    def detect(self, file_path: Path, content: str) -> List[Issue]:
        """Detect cipher suite issues"""
        issues = []

        # Check for deprecated ciphers
        for pattern, severity, description in self.CIPHER_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1

                remediation = self._get_remediation(severity)

                issues.append(
                    Issue(
                        file_path=file_path,
                        line_number=line_number,
                        severity=severity,
                        title=f"Deprecated cipher detected: {description}",
                        description=(
                            f"Cipher suite {match.group(0)} is not quantum-resistant. "
                            "Post-quantum cryptography requires migration to ML-KEM "
                            "for key exchange and ML-DSA for signatures."
                        ),
                        remediation=remediation,
                        nist_reference="NIST FIPS 203/204",
                        code_snippet=match.group(0),
                    )
                )

        # Check for presence of PQC-ready ciphers (positive signal)
        has_pqc_ready = any(cipher in content for cipher in self.PQC_READY_CIPHERS)

        if not has_pqc_ready and "cipher" in content.lower():
            # File configures ciphers but has no PQC-ready ones
            issues.append(
                Issue(
                    file_path=file_path,
                    line_number=1,
                    severity=Severity.INFO,
                    title="No PQC-ready cipher suites configured",
                    description=(
                        "This file configures cryptographic ciphers but does not "
                        "include post-quantum ready algorithms like ML-KEM or hybrid suites."
                    ),
                    remediation=(
                        "Add PQC-ready cipher suites:\n"
                        "- TLS_AES_256_GCM_SHA384 with X25519MLKEM768\n"
                        "- TLS_CHACHA20_POLY1305_SHA256\n"
                        "Enable hybrid mode for backward compatibility."
                    ),
                    nist_reference="NIST SP 800-186",
                )
            )

        return issues

    def _get_remediation(self, severity: Severity) -> str:
        """Get appropriate remediation steps based on severity"""
        if severity == Severity.CRITICAL:
            return (
                "IMMEDIATE ACTION REQUIRED:\n"
                "1. Remove deprecated cipher suites (RSA, DES, 3DES, RC4)\n"
                "2. Migrate to TLS 1.3 with ECDHE or DHE key exchange\n"
                "3. Enable hybrid PQC cipher suites:\n"
                "   - X25519MLKEM768 for key exchange\n"
                "   - ML-DSA-65 for digital signatures\n"
                "4. Test compatibility with major clients (browsers, curl, etc.)"
            )
        elif severity == Severity.WARNING:
            return (
                "RECOMMENDED:\n"
                "1. Upgrade AES-128 to AES-256 for long-term security\n"
                "2. Replace P-256 with P-384 or hybrid X25519+ML-KEM\n"
                "3. Plan migration to full PQC by Q4 2028"
            )
        else:
            return "Document PQC migration timeline and test cipher configurations."
