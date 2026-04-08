# pqc-migration-scanner

**Scan your codebase for post-quantum cryptography vulnerabilities before Cloudflare's 2029 deadline.**

## What is this?

`pqc-migration-scanner` is a production-ready CLI tool and GitHub Action that automatically detects post-quantum cryptography (PQC) compliance issues in your codebase. It identifies outdated OpenSSL versions, weak TLS configurations, deprecated cipher suites, and insufficient key sizes—then generates actionable remediation reports aligned with NIST recommendations. Use it as a CLI tool, integrate it into your CI/CD pipeline, or deploy it as a GitHub Action to catch PQC issues before they reach production.

## Features

- **Multi-detector scanning** – OpenSSL versions, TLS configurations, cipher suites, key sizes, and hardcoded cryptographic patterns
- **NIST-aligned remediation** – Every finding includes specific steps to reach PQC readiness
- **Multiple output formats** – Text, JSON, and Markdown reports for easy integration with existing workflows
- **GitHub Action ready** – Drop into your CI/CD with zero configuration; auto-generates compliance badges
- **Cloudflare 2029 deadline tracking** – Built-in timeline awareness for regulatory compliance
- **README badges** – Auto-generate "PQC Ready" or "Migration Required" badges for your project
- **Enterprise-scale scanning** – Efficiently handles large codebases across multiple repos

## Quick Start

### Installation

```bash
# Install from PyPI
pip install pqc-migration-scanner

# Or clone and install from source
git clone https://github.com/yourusername/pqc-migration-scanner.git
cd pqc-migration-scanner
pip install -e .
```

### CLI Usage

```bash
# Scan current directory
pqc-scanner scan .

# Scan specific path with JSON output
pqc-scanner scan ./src --format json --output report.json

# Generate markdown report for README
pqc-scanner scan . --format markdown --output PQC_REPORT.md

# Generate compliance badge
pqc-scanner badge --output badge.svg
```

### GitHub Action

Add to `.github/workflows/pqc-compliance.yml`:

```yaml
name: PQC Compliance Check

on: [push, pull_request]

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: yourusername/pqc-migration-scanner@v1
        with:
          format: markdown
          fail-on-issues: true
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: pqc-report
          path: pqc-report.md
```

## Usage Examples

### Scan and Generate Report

```bash
pqc-scanner scan ./my-project --format markdown --output COMPLIANCE.md
```

Output includes:
- Detected vulnerabilities with severity levels
- Specific file locations and line numbers
- Remediation steps tied to NIST recommendations
- Cloudflare 2029 deadline countdown

### Integrate with CI/CD

```bash
pqc-scanner scan . --format json --output results.json --fail-on-issues
```

Exit codes:
- `0` – No issues found
- `1` – Issues found; CI/CD failure
- `2` – Scanning error

### Check Compliance Status

```bash
pqc-scanner status .
```

Returns current PQC readiness score and migration progress.

## Tech Stack

- **Language**: Python 3.10+
- **CLI Framework**: Click
- **Scanning**: AST parsing, regex pattern matching, version detection
- **Reporting**: Jinja2 templates for flexible output formats
- **Distribution**: PyPI + GitHub Actions marketplace

## License

MIT

---

**Get started now**: [Installation](#installation) | [GitHub Action Setup](#github-action) | [Full Docs](./OVERVIEW.md)