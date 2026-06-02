"""
Language-specific detector for quantum-vulnerable cryptographic APIs.
"""

import re
from pathlib import Path
from typing import ClassVar, List, NamedTuple

from pqc_scanner.models import Issue, Severity


class LanguageCryptoPattern(NamedTuple):
    pattern: str
    severity: Severity
    title: str
    description: str
    remediation: str


class LanguageCryptoDetector:
    """Detects direct use of classical public-key cryptography APIs."""

    PATTERNS: ClassVar[List[LanguageCryptoPattern]] = [
        LanguageCryptoPattern(
            r"\bec\.generate_private_key\s*\(",
            Severity.CRITICAL,
            "Python elliptic-curve key generation detected",
            "The Python cryptography EC API creates quantum-vulnerable ECDSA/ECDH keys.",
            "Add algorithm agility around key generation and plan migration to ML-DSA for "
            "signatures and ML-KEM or hybrid KEMs for key establishment.",
        ),
        LanguageCryptoPattern(
            r"\b(?:SigningKey|VerifyingKey)\.(?:generate|from_|from_string)",
            Severity.CRITICAL,
            "python-ecdsa key operation detected",
            "python-ecdsa relies on elliptic-curve signatures that are vulnerable to a "
            "cryptographically relevant quantum computer.",
            "Inventory all ecdsa keys, avoid new long-lived ECDSA credentials, and add a "
            "migration path to ML-DSA-backed signing.",
        ),
        LanguageCryptoPattern(
            r"\b(?:RSA|rsa)\.generate(?:_private_key)?\b\s*\(",
            Severity.CRITICAL,
            "Python RSA key generation detected",
            "RSA key generation creates signatures or key transport primitives that are "
            "not quantum-resistant.",
            "Prefer configurable key providers and prepare hybrid or ML-DSA signing for "
            "new credentials.",
        ),
        LanguageCryptoPattern(
            r"\bnacl\.(?:public\.PrivateKey|signing\.SigningKey)(?:\.generate)?\s*\(",
            Severity.CRITICAL,
            "PyNaCl public-key primitive detected",
            "PyNaCl public-key signing and key-exchange primitives use Ed25519 or "
            "Curve25519, which are not quantum-resistant.",
            "Inventory PyNaCl public-key call sites and prepare ML-DSA signatures or "
            "ML-KEM/hybrid key establishment for long-lived credentials.",
        ),
        LanguageCryptoPattern(
            r"\bcrypto\.(?:generateKeyPair|generateKeyPairSync)\s*\(\s*[\"'](?:rsa|ec|dsa)[\"']",
            Severity.CRITICAL,
            "Node.js classical key-pair generation detected",
            "Node.js crypto is generating RSA, EC, or DSA keys that need PQC migration.",
            "Wrap key generation in an algorithm-agile provider and add ML-DSA/ML-KEM "
            "migration support where dependencies permit.",
        ),
        LanguageCryptoPattern(
            r"\bcrypto\.create(?:ECDH|Sign|Verify)\s*\(",
            Severity.WARNING,
            "Node.js classical signature or ECDH API detected",
            "Direct Node.js signing, verification, or ECDH APIs often hardcode "
            "quantum-vulnerable primitives.",
            "Review the selected algorithm names and make them configurable before PQC "
            "migration.",
        ),
        LanguageCryptoPattern(
            r"\bsubtle\.(?:generateKey|importKey)\s*\([^)]*\b(?:ECDSA|ECDH|RSA-PSS|RSASSA-PKCS1-v1_5)\b",
            Severity.CRITICAL,
            "WebCrypto classical public-key algorithm detected",
            "WebCrypto is configured for RSA, ECDSA, or ECDH, all of which require PQC "
            "migration planning.",
            "Introduce algorithm agility at the WebCrypto boundary and track browser or "
            "runtime support for standardized PQC algorithms.",
        ),
        LanguageCryptoPattern(
            r"\brsa\.GenerateKey\s*\(",
            Severity.CRITICAL,
            "Go RSA key generation detected",
            "Go code is generating RSA keys that are vulnerable to quantum attacks.",
            "Move RSA key creation behind a configurable crypto provider and plan "
            "migration to ML-DSA or hybrid signing.",
        ),
        LanguageCryptoPattern(
            r"\becdsa\.(?:GenerateKey|Sign|Verify)\s*\(",
            Severity.CRITICAL,
            "Go ECDSA operation detected",
            "Go ECDSA signatures are quantum-vulnerable and should be inventoried for "
            "migration.",
            "Avoid issuing new long-lived ECDSA credentials and prepare ML-DSA signing " "support.",
        ),
        LanguageCryptoPattern(
            r"\belliptic\.P(?:224|256|384|521)\s*\(",
            Severity.WARNING,
            "Go NIST elliptic curve detected",
            "NIST elliptic curves provide classical security only and are not "
            "quantum-resistant.",
            "Treat curve selection as configuration and plan hybrid key exchange where "
            "applicable.",
        ),
        LanguageCryptoPattern(
            r"\bcurve25519\.(?:X25519|ScalarBaseMult|ScalarMult)\s*\(",
            Severity.WARNING,
            "Go Curve25519 key exchange detected",
            "Go Curve25519/X25519 key exchange is a classical elliptic-curve primitive "
            "that is not quantum-resistant.",
            "Inventory X25519 key exchange paths and plan hybrid ML-KEM key "
            "establishment for PQC migration.",
        ),
        LanguageCryptoPattern(
            r"\bring::(?:signature::(?:EcdsaKeyPair|RsaKeyPair)|agreement::EphemeralPrivateKey)\b",
            Severity.CRITICAL,
            "Rust ring classical public-key primitive detected",
            "Rust ring public-key APIs for ECDSA, RSA, and ECDH-style agreement are "
            "quantum-vulnerable.",
            "Centralize ring public-key usage and prepare ML-DSA signatures or "
            "ML-KEM/hybrid key establishment where supported.",
        ),
        LanguageCryptoPattern(
            r"\bKeyPairGenerator\.getInstance\s*\(\s*[\"'](?:RSA|EC|ECDSA|DSA|DH)[\"']",
            Severity.CRITICAL,
            "Java classical key-pair generator detected",
            "Java is generating RSA, EC, DSA, or DH key pairs that require PQC migration.",
            "Centralize KeyPairGenerator selection and add a path for ML-DSA signatures "
            "or ML-KEM key establishment.",
        ),
        LanguageCryptoPattern(
            r"\bKeyFactory\.getInstance\s*\(\s*[\"'](?:RSA|EC|ECDSA|DSA|DH)[\"']",
            Severity.WARNING,
            "Java classical key factory detected",
            "Java KeyFactory is parsing or materializing classical public-key algorithms "
            "that require PQC migration planning.",
            "Inventory imported key formats and ensure key parsing is routed through an "
            "algorithm-agile provider.",
        ),
        LanguageCryptoPattern(
            r"\b(?:Signature|KeyAgreement|Cipher)\.getInstance\s*\(\s*[\"'][^\"']*(?:RSA|ECDSA|ECDH|DSA|DH)[^\"']*[\"']",
            Severity.WARNING,
            "Java classical crypto algorithm detected",
            "Java crypto APIs are configured with classical public-key algorithms.",
            "Make algorithm names configurable and inventory all RSA/ECDSA/ECDH/DSA/DH "
            "call sites.",
        ),
        LanguageCryptoPattern(
            r"\bECGenParameterSpec\s*\(\s*[\"'](?:secp256r1|prime256v1|secp256k1|P-256|P-384|P-521)[\"']",
            Severity.WARNING,
            "Java elliptic-curve parameter detected",
            "Hardcoded elliptic-curve parameters reduce algorithm agility for PQC " "migration.",
            "Move curve selection into configuration and define a PQC migration timeline.",
        ),
        LanguageCryptoPattern(
            r"\b(?:RSA|ECDsa|ECDiffieHellman|DSA)\.Create\s*\(",
            Severity.CRITICAL,
            ".NET classical public-key primitive detected",
            ".NET code is creating RSA, ECDSA, ECDH, or DSA primitives that are "
            "quantum-vulnerable.",
            "Route primitive creation through an algorithm-agile abstraction and prepare "
            "ML-DSA/ML-KEM migration support.",
        ),
    ]

    def detect(self, file_path: Path, content: str) -> List[Issue]:
        """Detect language-specific crypto issues."""
        issues = []

        for crypto_pattern in self.PATTERNS:
            for match in re.finditer(crypto_pattern.pattern, content, re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1
                if self._is_comment_only_line(content, match.start()):
                    continue

                issues.append(
                    Issue(
                        file_path=file_path,
                        line_number=line_number,
                        severity=crypto_pattern.severity,
                        title=crypto_pattern.title,
                        description=crypto_pattern.description,
                        remediation=crypto_pattern.remediation,
                        nist_reference="NIST FIPS 203/204/205",
                        code_snippet=match.group(0),
                    )
                )

        return issues

    def _is_comment_only_line(self, content: str, match_start: int) -> bool:
        """Skip obvious comment-only matches to reduce noisy findings."""
        line_start = content.rfind("\n", 0, match_start) + 1
        line_end = content.find("\n", match_start)
        if line_end == -1:
            line_end = len(content)

        line = content[line_start:line_end].lstrip()
        return line.startswith(("#", "//", "/*", "*"))
