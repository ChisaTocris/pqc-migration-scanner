"""
Detector for hardcoded cryptographic constants
"""

import re
from pathlib import Path
from typing import List

from pqc_scanner.models import Issue, Severity


class HardcodedCryptoDetector:
    """Detects hardcoded cryptographic implementations that lack algorithm agility"""

    PATTERNS = [
        # Hardcoded algorithm names
        (
            r"(?:algorithm|cipher|hash)[\s:=]+[\"'](SHA-?1|MD5|RSA|DES)",
            Severity.CRITICAL,
            "Hardcoded weak algorithm",
        ),
        (
            r"(?:algorithm|cipher|hash)[\s:=]+[\"'](SHA-?256|AES-128|ECDSA)",
            Severity.WARNING,
            "Hardcoded algorithm without agility",
        ),
        # Cryptographic constants
        (r"const\s+\w+(?:Algorithm|Cipher|Hash)\s*=", Severity.INFO, "Crypto constant"),
        (
            r"final\s+static\s+String\s+\w+(?:ALGORITHM|CIPHER)",
            Severity.INFO,
            "Java crypto constant",
        ),
        # Direct cryptographic library calls without configuration
        (r"hashlib\.sha1\(", Severity.CRITICAL, "SHA-1 usage"),
        (r"hashlib\.md5\(", Severity.CRITICAL, "MD5 usage"),
        (r"Cipher\.getInstance\([\"']RSA/", Severity.WARNING, "Hardcoded RSA cipher"),
        (r"crypto\.createHash\([\"']sha1", Severity.CRITICAL, "Node.js SHA-1"),
        (r"crypto\.createHash\([\"']md5", Severity.CRITICAL, "Node.js MD5"),
        # Certificate validation issues
        (r"verify[_-]?(?:ssl|tls|cert)[\s:=]+false", Severity.CRITICAL, "TLS verification disabled"),
        (r"InsecureSkipVerify[\s:=]+true", Severity.CRITICAL, "Go TLS verification skip"),
        (r"CERT_NONE", Severity.CRITICAL, "Python certificate verification disabled"),
    ]

    def detect(self, file_path: Path, content: str) -> List[Issue]:
        """Detect hardcoded crypto issues"""
        issues = []

        for pattern, severity, description in self.PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1

                remediation = self._get_remediation(description, severity)

                issues.append(
                    Issue(
                        file_path=file_path,
                        line_number=line_number,
                        severity=severity,
                        title=f"Hardcoded crypto detected: {description}",
                        description=(
                            "Hardcoded cryptographic implementations prevent algorithm "
                            "agility required for PQC migration. Systems must support "
                            "runtime algorithm selection for smooth transition."
                        ),
                        remediation=remediation,
                        nist_reference="NIST IR 8413",
                        code_snippet=match.group(0),
                    )
                )

        return issues

    def _get_remediation(self, description: str, severity: Severity) -> str:
        """Get remediation steps based on issue type"""
        if "sha-1" in description.lower() or "md5" in description.lower():
            return (
                "IMMEDIATE ACTION: Replace deprecated hash functions:\n"
                "1. Migrate MD5/SHA-1 to SHA-256 minimum (SHA-384 recommended)\n"
                "2. Update all signature verification code\n"
                "3. Re-sign any data/certificates using deprecated hashes\n"
                "4. Implement algorithm agility for future PQC migration"
            )
        elif "verification disabled" in description.lower() or "skip" in description.lower():
            return (
                "CRITICAL SECURITY ISSUE:\n"
                "1. Re-enable certificate/TLS verification immediately\n"
                "2. Fix underlying certificate issues properly\n"
                "3. Never disable security checks in production\n"
                "4. Use proper CA certificate configuration"
            )
        elif "hardcoded" in description.lower():
            return (
                "Implement algorithm agility:\n"
                "1. Move algorithm selection to configuration files\n"
                "2. Support multiple algorithms via runtime selection\n"
                "3. Design for future PQC algorithm updates:\n"
                "   - ML-KEM-768 for key exchange\n"
                "   - ML-DSA-65 for signatures\n"
                "4. Use cryptographic abstraction layers (e.g., KeyStore, HSM)"
            )
        else:
            return (
                "Review cryptographic implementations:\n"
                "1. Ensure algorithm configurability\n"
                "2. Document supported algorithms\n"
                "3. Plan PQC migration path"
            )
