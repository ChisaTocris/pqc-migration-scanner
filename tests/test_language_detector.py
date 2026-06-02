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
KeyFactory factory = KeyFactory.getInstance("RSA");
"""

    issues = LanguageCryptoDetector().detect(Path("Example.java"), content)

    titles = {issue.title for issue in issues}
    assert "Java classical key-pair generator detected" in titles
    assert "Java classical crypto algorithm detected" in titles
    assert "Java classical key factory detected" in titles


def test_language_detector_finds_pynacl_usage() -> None:
    content = """
from nacl.signing import SigningKey

signing_key = nacl.signing.SigningKey.generate()
private_key = nacl.public.PrivateKey.generate()
"""

    issues = LanguageCryptoDetector().detect(Path("example.py"), content)

    assert any(issue.title == "PyNaCl public-key primitive detected" for issue in issues)


def test_language_detector_finds_go_curve25519_usage() -> None:
    content = """
shared, err := curve25519.X25519(privateKey, peerKey)
"""

    issues = LanguageCryptoDetector().detect(Path("example.go"), content)

    assert any(issue.title == "Go Curve25519 key exchange detected" for issue in issues)


def test_language_detector_finds_rust_ring_usage() -> None:
    content = """
let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(&alg, bytes, rng)?;
let private_key = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, rng)?;
"""

    issues = LanguageCryptoDetector().detect(Path("example.rs"), content)

    assert any(
        issue.title == "Rust ring classical public-key primitive detected" for issue in issues
    )


def test_language_detector_ignores_comment_only_matches() -> None:
    content = """
# key = SigningKey.generate(curve=NIST256p)
// KeyPairGenerator.getInstance("RSA")
"""

    issues = LanguageCryptoDetector().detect(Path("example.py"), content)

    assert issues == []


def test_language_detector_ignores_similar_non_crypto_names() -> None:
    content = """
rsa_generated = True
RSA_generate_report()
ec.generate_report()
"""

    issues = LanguageCryptoDetector().detect(Path("example.py"), content)

    assert issues == []


def test_scanner_collects_csharp_files(tmp_path: Path) -> None:
    source = tmp_path / "Example.cs"
    source.write_text("var key = ECDsa.Create();")

    report = PQCScanner(tmp_path).scan()

    assert report.files_scanned == 1
    assert any(
        issue.title == ".NET classical public-key primitive detected" for issue in report.issues
    )
