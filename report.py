#!/usr/bin/env python3
"""
BLVKOUT Secure Code Review — Report Generator

Generates a structured security code review report following
OWASP Code Review Guide and Secure Code Review Cheat Sheet methodology.

Usage:
    python report.py <file_or_directory>
    python report.py ./project/ --output report.md
    python report.py ./project/ --format html --output report.html
    python report.py ./project/ --format json --output report.json

References:
    - OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/
    - OWASP Secure Code Review Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html
"""

import os
import sys
import argparse
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

# Import the scanner
from scan import scan_target, ScanResult, Finding, RULES, detect_language, EXT_MAP, SKIP_DIRS


# =============================================================================
# OWASP Review Checklist Categories
# =============================================================================

OWASP_CATEGORIES = {
    "input_validation": {
        "title": "Input Validation",
        "checks": [
            "Server-side validation for all inputs",
            "Allowlist validation preferred over blocklist",
            "Context-appropriate output encoding (HTML, JS, CSS, URL, SQL)",
            "File upload content validation and size limits",
            "SQL injection prevention via parameterized queries",
            "Input length restrictions enforced",
            "Special characters and Unicode properly handled",
            "No sensitive information in error responses",
        ],
    },
    "authentication": {
        "title": "Authentication & Session Management",
        "checks": [
            "Strong password hashing (bcrypt, argon2, scrypt)",
            "Account lockout after failed attempts",
            "Session tokens with sufficient entropy (≥128 bits)",
            "Session invalidation on logout/timeout",
            "Re-authentication for sensitive operations",
            "MFA implementation for high-risk accounts",
            "Secure password reset mechanism",
            "HttpOnly, Secure, SameSite cookie attributes",
        ],
    },
    "authorization": {
        "title": "Authorization & Access Control",
        "checks": [
            "All access controls enforced server-side",
            "Default deny access policy",
            "IDOR prevention — proper authorization for resources",
            "Admin functions properly protected",
            "Role assignments cannot be manipulated",
            "Horizontal and vertical privilege escalation prevented",
            "Centralized access control logic",
            "Authorization verified after authentication",
        ],
    },
    "cryptography": {
        "title": "Cryptography",
        "checks": [
            "Modern algorithms (AES-256, RSA-2048+, ECDSA P-256+)",
            "Proper key generation, storage, and rotation",
            "Certificate validation including hostname",
            "Cryptographically secure random number generation",
            "Encryption at rest and in transit",
            "Unique and unpredictable IVs/nonces",
            "Up-to-date cryptographic libraries",
            "Protection against timing side-channels",
        ],
    },
    "business_logic": {
        "title": "Business Logic",
        "checks": [
            "Multi-step workflow state validation",
            "Race condition prevention in concurrent ops",
            "Transaction atomicity and rollback",
            "Rate limiting and resource quotas",
            "Business rules cannot be bypassed via direct API",
        ],
    },
    "configuration": {
        "title": "Configuration & Deployment",
        "checks": [
            "Security-focused default configurations",
            "Proper environment isolation",
            "No hardcoded secrets — proper secret management",
            "Graceful error handling without info disclosure",
            "Sensitive data not logged",
            "HTTP security headers configured",
            "Strong TLS cipher suites and protocol versions",
            "Dependencies up-to-date without known CVEs",
        ],
    },
    "data_protection": {
        "title": "Data Protection",
        "checks": [
            "Sensitive data classified and labeled",
            "PII handling compliant with regulations",
            "Data minimization — only collect what's needed",
            "Secure data deletion procedures",
            "Encryption for sensitive data at rest",
            "Data masking in logs and displays",
        ],
    },
}


# =============================================================================
# Code Metrics
# =============================================================================

@dataclass
class FileMetrics:
    path: str
    language: str
    lines: int
    size_bytes: int


@dataclass
class ProjectMetrics:
    total_files: int = 0
    total_lines: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    files: List[FileMetrics] = field(default_factory=list)


def gather_metrics(target: str) -> ProjectMetrics:
    """Gather basic code metrics for the target."""
    metrics = ProjectMetrics()
    target_path = Path(target)

    if target_path.is_file():
        files = [target_path]
    else:
        files = []
        for root, dirs, fnames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in fnames:
                fpath = Path(root) / fname
                if fpath.stat().st_size > 0 and fpath.stat().st_size < 5 * 1024 * 1024:
                    try:
                        with open(fpath, "rb") as f:
                            if b"\x00" not in f.read(1024):
                                files.append(fpath)
                    except (PermissionError, OSError):
                        pass

    for fpath in files:
        lang = detect_language(fpath)
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = sum(1 for _ in f)
        except (PermissionError, OSError):
            lines = 0

        metrics.total_files += 1
        metrics.total_lines += lines
        metrics.languages[lang] = metrics.languages.get(lang, 0) + 1
        metrics.files.append(FileMetrics(
            path=str(fpath), language=lang,
            lines=lines, size_bytes=fpath.stat().st_size,
        ))

    return metrics


# =============================================================================
# Risk Assessment
# =============================================================================

def compute_risk_level(scan_result: ScanResult) -> str:
    """Compute overall risk level based on findings."""
    if scan_result.critical_count > 0:
        return "CRITICAL"
    elif scan_result.high_count > 2:
        return "HIGH"
    elif scan_result.high_count > 0:
        return "HIGH"
    elif scan_result.medium_count > 3:
        return "MEDIUM"
    elif scan_result.medium_count > 0:
        return "MEDIUM"
    elif scan_result.low_count > 0:
        return "LOW"
    return "NONE"


# =============================================================================
# Report Generators
# =============================================================================

def generate_markdown_report(
    target: str,
    scan_result: ScanResult,
    metrics: ProjectMetrics,
    reviewer: str = "BLVKOUT Automated Scanner",
) -> str:
    """Generate a Markdown secure code review report."""
    now = datetime.now()
    risk = compute_risk_level(scan_result)
    target_name = Path(target).name or target

    lines = []
    lines.append(f"# Secure Code Review Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **Application** | {target_name} |")
    lines.append(f"| **Reviewer** | {reviewer} |")
    lines.append(f"| **Date** | {now.strftime('%Y-%m-%d %H:%M')} |")
    lines.append(f"| **Scope** | {metrics.total_files} files, {metrics.total_lines} lines |")
    lines.append(f"| **Overall Risk** | **{risk}** |")
    lines.append(f"| **Scan Time** | {scan_result.scan_time_ms:.0f}ms |")
    lines.append("")
    lines.append("### Methodology")
    lines.append("")
    lines.append("This review follows the [OWASP Secure Code Review Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html) methodology, combining automated pattern detection with structured checklist analysis.")
    lines.append("")

    # Findings summary
    lines.append("## Findings Summary")
    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|---|---|")
    lines.append(f"| 🔴 Critical | {scan_result.critical_count} |")
    lines.append(f"| 🟡 High | {scan_result.high_count} |")
    lines.append(f"| 🔵 Medium | {scan_result.medium_count} |")
    lines.append(f"| ⚪ Low | {scan_result.low_count} |")
    lines.append(f"| **Total** | **{len(scan_result.findings)}** |")
    lines.append("")

    # Detailed findings
    if scan_result.findings:
        lines.append("## Detailed Findings")
        lines.append("")

        for i, f in enumerate(scan_result.findings, 1):
            sev_icon = {"critical": "🔴", "high": "🟡", "medium": "🔵", "low": "⚪"}.get(f.rule.severity, "⚪")
            lines.append(f"### {i}. {f.rule.name}")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|---|---|")
            lines.append(f"| **Severity** | {sev_icon} {f.rule.severity.upper()} |")
            lines.append(f"| **Category** | {f.rule.category.replace('_', ' ').title()} |")
            lines.append(f"| **Rule ID** | {f.rule.id} |")
            lines.append(f"| **Location** | `{f.file_path}:{f.line_number}` |")
            lines.append("")
            lines.append(f"**Description:** {f.rule.description}")
            lines.append("")
            lines.append(f"**Evidence:**")
            lines.append(f"```")
            lines.append(f"{f.line_content}")
            lines.append(f"```")
            lines.append("")
            lines.append(f"**Recommendation:** Review and remediate this pattern. Remove or replace with a safe alternative.")
            lines.append("")
            if f.rule.false_positive_hint:
                lines.append(f"> ℹ️ {f.rule.false_positive_hint}")
                lines.append("")

    # OWASP Checklist
    lines.append("## OWASP Security Checklist")
    lines.append("")
    lines.append("The following checklist items should be manually verified as part of a complete secure code review:")
    lines.append("")

    for cat_id, cat in OWASP_CATEGORIES.items():
        lines.append(f"### {cat['title']}")
        lines.append("")
        for check in cat["checks"]:
            lines.append(f"- [ ] {check}")
        lines.append("")

    # Project metrics
    lines.append("## Project Metrics")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Total Files | {metrics.total_files} |")
    lines.append(f"| Total Lines | {metrics.total_lines} |")
    lines.append(f"| Languages | {', '.join(sorted(metrics.languages.keys()))} |")
    lines.append("")

    if metrics.languages:
        lines.append("### Language Breakdown")
        lines.append("")
        lines.append(f"| Language | Files |")
        lines.append(f"|---|---|")
        for lang, count in sorted(metrics.languages.items(), key=lambda x: -x[1]):
            lines.append(f"| {lang} | {count} |")
        lines.append("")

    # References
    lines.append("## References")
    lines.append("")
    lines.append("- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)")
    lines.append("- [OWASP Secure Code Review Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)")
    lines.append("- [OWASP Top 10](https://owasp.org/www-project-top-ten/)")
    lines.append("- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)")
    lines.append("- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)")
    lines.append("")
    lines.append("---")
    lines.append(f"*Generated by BLVKOUT Secure Code Review Scanner on {now.strftime('%Y-%m-%d %H:%M:%S')}*")

    return "\n".join(lines)


def generate_html_report(
    target: str,
    scan_result: ScanResult,
    metrics: ProjectMetrics,
    reviewer: str = "BLVKOUT Automated Scanner",
) -> str:
    """Generate an HTML secure code review report."""
    md = generate_markdown_report(target, scan_result, metrics, reviewer)
    # Simple HTML wrapper with the markdown content rendered as preformatted
    now = datetime.now()
    risk = compute_risk_level(scan_result)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLVKOUT Secure Code Review — {Path(target).name}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
h1 {{ color: #fff; border-bottom: 2px solid #4ade80; padding-bottom: 10px; }}
h2 {{ color: #4ade80; margin-top: 30px; }}
h3 {{ color: #ccc; margin-top: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #333; padding: 8px 12px; text-align: left; }}
th {{ background: #1a1a1a; color: #4ade80; }}
code, pre {{ background: #1a1a1a; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
pre {{ padding: 12px; overflow-x: auto; }}
blockquote {{ border-left: 3px solid #4ade80; padding-left: 12px; color: #888; }}
.risk-critical {{ color: #ef4444; font-weight: bold; }}
.risk-high {{ color: #f5a623; font-weight: bold; }}
.risk-medium {{ color: #60a5fa; font-weight: bold; }}
.risk-low {{ color: #888; }}
.risk-none {{ color: #4ade80; font-weight: bold; }}
ul {{ list-style: none; padding-left: 0; }}
ul li::before {{ content: "☐ "; color: #666; }}
a {{ color: #4ade80; }}
</style>
</head>
<body>
<h1>🛡️ Secure Code Review Report</h1>
<table>
<tr><th>Application</th><td>{Path(target).name}</td></tr>
<tr><th>Reviewer</th><td>{reviewer}</td></tr>
<tr><th>Date</th><td>{now.strftime('%Y-%m-%d %H:%M')}</td></tr>
<tr><th>Scope</th><td>{metrics.total_files} files, {metrics.total_lines} lines</td></tr>
<tr><th>Overall Risk</th><td class="risk-{risk.lower()}">{risk}</td></tr>
<tr><th>Findings</th><td>{scan_result.critical_count} critical, {scan_result.high_count} high, {scan_result.medium_count} medium, {scan_result.low_count} low</td></tr>
</table>

<h2>Findings</h2>
"""
    if not scan_result.findings:
        html += "<p>✅ No security threats detected.</p>"
    else:
        for i, f in enumerate(scan_result.findings, 1):
            sev_class = f"risk-{f.rule.severity}"
            html += f"""
<h3>{i}. {f.rule.name} <span class="{sev_class}">[{f.rule.severity.upper()}]</span></h3>
<table>
<tr><td><strong>Category</strong></td><td>{f.rule.category.replace('_', ' ').title()}</td></tr>
<tr><td><strong>Location</strong></td><td><code>{f.file_path}:{f.line_number}</code></td></tr>
<tr><td><strong>Description</strong></td><td>{f.rule.description}</td></tr>
</table>
<pre>{f.line_content}</pre>
"""

    html += """
<h2>OWASP Security Checklist</h2>
<p>Manually verify these items for a complete review:</p>
"""
    for cat_id, cat in OWASP_CATEGORIES.items():
        html += f"<h3>{cat['title']}</h3><ul>"
        for check in cat["checks"]:
            html += f"<li>{check}</li>"
        html += "</ul>"

    html += f"""
<h2>References</h2>
<ul>
<li><a href="https://owasp.org/www-project-code-review-guide/">OWASP Code Review Guide</a></li>
<li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html">OWASP Secure Code Review Cheat Sheet</a></li>
<li><a href="https://owasp.org/www-project-top-ten/">OWASP Top 10</a></li>
</ul>
<hr>
<p><em>Generated by BLVKOUT Secure Code Review Scanner on {now.strftime('%Y-%m-%d %H:%M:%S')}</em></p>
</body></html>"""
    return html


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="BLVKOUT Secure Code Review — Generate OWASP-based security review reports")
    parser.add_argument("target", help="File or directory to review")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument("-f", "--format", choices=["md", "html", "json"], default="md",
                        help="Report format (default: md)")
    parser.add_argument("--reviewer", default="BLVKOUT Automated Scanner",
                        help="Reviewer name for the report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not Path(args.target).exists():
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    # Run scan
    scan_result = scan_target(args.target, verbose=args.verbose)
    metrics = gather_metrics(args.target)

    # Generate report
    if args.format == "md":
        report = generate_markdown_report(args.target, scan_result, metrics, args.reviewer)
    elif args.format == "html":
        report = generate_html_report(args.target, scan_result, metrics, args.reviewer)
    elif args.format == "json":
        report = json.dumps({
            "meta": {
                "application": Path(args.target).name,
                "reviewer": args.reviewer,
                "date": datetime.now().isoformat(),
                "scope_files": metrics.total_files,
                "scope_lines": metrics.total_lines,
                "risk_level": compute_risk_level(scan_result),
                "methodology": "OWASP Secure Code Review Cheat Sheet",
            },
            "summary": {
                "critical": scan_result.critical_count,
                "high": scan_result.high_count,
                "medium": scan_result.medium_count,
                "low": scan_result.low_count,
                "total": len(scan_result.findings),
            },
            "findings": [
                {
                    "id": f.rule.id,
                    "name": f.rule.name,
                    "severity": f.rule.severity,
                    "category": f.rule.category,
                    "description": f.rule.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "evidence": f.line_content,
                    "match": f.match,
                }
                for f in scan_result.findings
            ],
            "checklist": {
                cat_id: {"title": cat["title"], "checks": cat["checks"]}
                for cat_id, cat in OWASP_CATEGORIES.items()
            },
            "metrics": {
                "total_files": metrics.total_files,
                "total_lines": metrics.total_lines,
                "languages": metrics.languages,
            },
            "references": [
                "https://owasp.org/www-project-code-review-guide/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html",
                "https://owasp.org/www-project-top-ten/",
                "https://cwe.mitre.org/top25/",
            ],
        }, indent=2)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report saved to: {args.output}", file=sys.stderr)
    else:
        print(report)

    sys.exit(1 if scan_result.critical_count or scan_result.high_count else 0)


if __name__ == "__main__":
    main()
