# 🔐 Secure Coding Review

An educational Python static-analysis tool developed as part of my CodeAlpha Cyber Security Internship projects.

The tool scans Python source code for common security-related coding patterns and provides findings with severity levels and recommendations. It uses Python's standard library and does not execute the source code being reviewed.

## Features

- Detects potential hardcoded credentials.
- Flags possible SQL injection patterns.
- Identifies potentially risky subprocess usage.
- Detects dynamic code execution through `eval()` and `exec()`.
- Flags potentially unsafe `pickle` deserialization.
- Identifies use of MD5 and SHA-1 hashing functions.
- Detects explicit `debug=True` settings.
- Reports the line number, severity, finding category, and recommendation.
- Includes automated unit tests.

## Project Structure

```text
CodeAlpha_SecureCodingReview/
├── src/
│   └── secure_code_review.py
├── tests/
│   └── test_secure_code_review.py
├── screenshots/
│   └── README.md
├── .gitignore
├── requirements.txt
└── README.md

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Usage

Run the scanner against a Python file:

```bash
python3 src/secure_code_review.py src/secure_code_review.py
## Exit Codes
- `0`: No configured patterns detected.
- `1`: One or more findings reported.
- `2`: The input file is missing or cannot be read.
## Run the Tests

Run the following command from the project root:

    python3 -m unittest discover -s tests -v

The project includes nine automated tests covering detection rules, safe basic code, and line-number reporting.

## Security Checks
- **Hardcoded credentials (High):** Flags possible credentials assigned to string literals.
- **Possible SQL injection (High):** Flags selected SQL queries using dynamic string construction.
- **Risky shell execution (High):** Flags selected subprocess calls for review.
- **Dynamic code execution (High):** Detects `eval()` and `exec()` patterns.
- **Unsafe deserialization (High):** Detects selected `pickle` loading patterns.
- **Weak hash algorithm (Medium):** Flags MD5 and SHA-1 usage.
- **Debug mode enabled (Medium):** Flags explicit `debug=True` settings.

## Limitations
This is an educational, pattern-based scanner, not a replacement for a professional security audit.
- Pattern matching can produce false positives and miss vulnerabilities.
- A finding does not automatically prove that code is vulnerable.
- The scanner does not execute the source file being reviewed.
- Review findings in context before deciding on remediation.

## Learning Objectives
- Practice Python and regular expressions.
- Understand common secure-coding weaknesses.
- Build a basic static-analysis tool.
- Write automated tests with unittest.

## Responsible Use
Review code you own or are authorized to assess. Treat the output as a starting point for manual security review.

## Author
Developed as a cybersecurity learning project for my CodeAlpha internship portfolio.
