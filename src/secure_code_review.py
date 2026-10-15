#!/usr/bin/env python3
"""Educational static security checks for Python source code."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """One potential security issue found in source code."""

    line: int
    severity: str
    category: str
    description: str
    recommendation: str


RULES = [
    (
        "HIGH",
        "Hardcoded credential",
        re.compile(
            r"""(?i)\b(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token)"""
            r"""\b\s*[:=]\s*["'][^"'\n]{4,}["']"""
        ),
        "A credential-like value may be embedded in source code.",
        "Load secrets from environment variables or a dedicated secret manager.",
    ),
    (
        "HIGH",
        "Possible SQL injection",
        re.compile(
            r"""(?i)\bexecute\s*\(\s*(?:f["']|["'][^"']*["']\s*[%+])"""
        ),
        "A SQL execution call may construct its query using string formatting or concatenation.",
        "Use parameterized queries and pass values separately from the SQL statement.",
    ),
    (
        "HIGH",
        "Risky shell execution",
        re.compile(r"""\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("""),
        "A subprocess call needs review, especially if it receives untrusted input or enables a shell.",
        "Prefer argument lists with shell=False; validate untrusted input.",
    ),
    (
        "HIGH",
        "Dynamic code execution",
        re.compile(r"""\b(?:eval|exec)\s*\("""),
        "Dynamic code execution can run input as Python code.",
        "Avoid eval/exec for untrusted data; use safer parsing or explicit logic.",
    ),
    (
        "HIGH",
        "Unsafe deserialization",
        re.compile(r"""\bpickle\.(?:loads|load)\s*\("""),
        "Deserializing untrusted pickle data can execute attacker-controlled code.",
        "Never unpickle untrusted data; use a safer data format such as JSON where appropriate.",
    ),
    (
        "MEDIUM",
        "Weak hash algorithm",
        re.compile(r"""\bhashlib\.(?:md5|sha1)\s*\("""),
        "MD5 and SHA-1 are unsuitable for modern collision-resistant security uses.",
        "For integrity or signatures, use an appropriate modern hash; for passwords, use a password-hashing scheme.",
    ),
    (
        "MEDIUM",
        "Debug mode enabled",
        re.compile(r"""(?i)\bdebug\s*=\s*True\b"""),
        "Debug mode may expose diagnostic information if enabled in a deployed application.",
        "Disable debug mode in production and manage configuration by environment.",
    ),
]


def review_source(source: str) -> list[Finding]:
    """Return potential findings from source text without executing it."""
    findings: list[Finding] = []

    for line_number, line in enumerate(source.splitlines(), start=1):
        for severity, category, pattern, description, recommendation in RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        line=line_number,
                        severity=severity,
                        category=category,
                        description=description,
                        recommendation=recommendation,
                    )
                )

    return findings


def analyze_file(path: Path) -> list[Finding]:
    """Read a Python source file and review its text."""
    source = path.read_text(encoding="utf-8")
    return review_source(source)


def print_report(path: str, findings: list[Finding]) -> None:
    """Print a human-readable review report."""
    print(f"\nSecure Coding Review: {path}")
    print("=" * 60)

    if not findings:
        print("No configured patterns detected.")
        print("This does not prove the code is secure.")
        return

    print(f"Potential findings: {len(findings)}")

    for index, finding in enumerate(findings, start=1):
        print(
            f"\n{index}. [{finding.severity}] {finding.category}"
            f" (line {finding.line})"
        )
        print(f"   Finding: {finding.description}")
        print(f"   Recommendation: {finding.recommendation}")

    print("\nReview findings manually; pattern matches can be false positives.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Educational static security checks for Python source files."
    )
    parser.add_argument("file", type=Path, help="Path to a Python source file")
    args = parser.parse_args(argv)

    if not args.file.is_file():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2

    try:
        findings = analyze_file(args.file)
    except (OSError, UnicodeError) as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 2

    print_report(str(args.file), findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
