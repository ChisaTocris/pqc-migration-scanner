from pathlib import Path

from pqc_scanner.detectors.language import LanguageCryptoDetector
from pqc_scanner.models import Severity
from pqc_scanner.scanner import PQCScanner


def test_language_detector_finds_python_ecdsa_usage() -> None:
    content = """
from ecdsa import SigningKey, NIST256p

key = SigningKey.generate(curve=NIST256p)
"""

    issues = LanguageCryptoDetector().detect(Path("example.py"), content)

    assert any(issue.title == "python-ecdsa key operation detected" for issue in issues)
    assert any(issue.severity == Severity.CRITICAL for issue in issues)


def test_language_detector_finds_node_key_generation() -> None:
    content = """
const crypto = require("crypto");
const key = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
"""

    issues = LanguageCryptoDetector().detect(Path("example.js"), content)

    assert any(issue.title == "Node.js classical key-pair generation detected" for issue in issues)


def test_language_detector_finds_go_ecdsa_and_curve_usage() -> None:
    content = """
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
"""

    issues = LanguageCryptoDetector().detect(Path("example.go"), content)

    titles = {issue.title for issue in issues}
    assert "Go ECDSA operation detected" in titles
    assert "Go NIST elliptic curve detected" in titles


def test_language_detector_finds_java_crypto_apis() -> None:
    content = """
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
Signature sig = Signature.getInstance("SHA256withECDSA");
"""

    issues = LanguageCryptoDetector().detect(Path("Example.java"), content)

    titles = {issue.title for issue in issues}
    assert "Java classical key-pair generator detected" in titles
    assert "Java classical crypto algorithm detected" in titles


def test_scanner_collects_csharp_files(tmp_path: Path) -> None:
    source = tmp_path / "Example.cs"
    source.write_text("var key = ECDsa.Create();")

    report = PQCScanner(tmp_path).scan()

    assert report.files_scanned == 1
    assert any(
        issue.title == ".NET classical public-key primitive detected" for issue in report.issues
    )
