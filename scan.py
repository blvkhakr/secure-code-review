#!/usr/bin/env python3
"""
BLVKOUT Secure Code Review Scanner

Scans files and directories for malicious code patterns:
- Reverse shells, backdoors
- Data exfiltration
- Crypto miners
- Obfuscated/encoded payloads
- Privilege escalation
- Suspicious network activity
- Supply chain attacks

Supports: Bash, Python, JavaScript, PowerShell, Go, PHP, Ruby, and raw files.

Usage:
    python scan.py <file_or_directory>
    python scan.py script.sh
    python scan.py ./project/
    python scan.py --verbose script.py
    python scan.py --json payload.sh > report.json
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List
from datetime import datetime


# =============================================================================
# Detection Rules
# =============================================================================

@dataclass
class Rule:
    id: str
    name: str
    severity: str  # critical, high, medium, low
    category: str
    description: str
    pattern: str
    languages: List[str]  # ["*"] = all files
    false_positive_hint: str = ""


RULES: List[Rule] = [
    # ===== REVERSE SHELLS & BACKDOORS =====
    Rule("MAL-001", "Bash reverse shell", "critical", "reverse_shell",
         "Bash reverse shell — connects back to attacker",
         r"bash\s+-i\s+>&?\s*/dev/tcp/", ["bash", "sh", "*"]),
    Rule("MAL-002", "Netcat reverse shell", "critical", "reverse_shell",
         "Netcat used for reverse shell",
         r"nc\s+(-e|--exec|-c)\s+(/bin/(ba)?sh|cmd\.exe|powershell)", ["bash", "sh", "*"]),
    Rule("MAL-003", "Python reverse shell", "critical", "reverse_shell",
         "Python socket reverse shell",
         r"socket\.socket\(.*?(subprocess|os\.dup2|pty\.spawn)", ["python", "*"]),
    Rule("MAL-004", "PowerShell reverse shell", "critical", "reverse_shell",
         "PowerShell TCP reverse shell",
         r"(New-Object\s+System\.Net\.Sockets\.TCPClient|Net\.Sockets\.TcpClient)", ["powershell", "ps1", "*"]),
    Rule("MAL-005", "PHP reverse shell", "critical", "reverse_shell",
         "PHP reverse shell via fsockopen",
         r"(fsockopen|pfsockopen)\s*\(.+?\).*?(shell_exec|exec|system|passthru)", ["php", "*"]),
    Rule("MAL-006", "Ruby reverse shell", "critical", "reverse_shell",
         "Ruby TCPSocket reverse shell",
         r"TCPSocket\.(new|open)\s*\(.*?\).*?(exec|spawn|system)", ["ruby", "*"]),

    # ===== DATA EXFILTRATION =====
    Rule("EXFIL-001", "curl/wget pipe to shell", "critical", "data_exfil",
         "Download and execute — common malware delivery",
         r"(curl|wget)\s+.*\|\s*(ba)?sh", ["bash", "sh", "*"]),
    Rule("EXFIL-002", "File upload to external server", "high", "data_exfil",
         "Uploading local files to external server",
         r"(curl|wget)\s+.*(-F\s+|--data-binary\s+@|--upload-file)\s*['\"]?(/etc/|~/|\$HOME|/var/)", ["bash", "sh", "*"]),
    Rule("EXFIL-003", "DNS exfiltration", "high", "data_exfil",
         "Data exfiltration via DNS queries",
         r"(dig|nslookup|host)\s+.*\$\(", ["bash", "sh", "*"]),
    Rule("EXFIL-004", "Base64 decode pipe to shell", "high", "data_exfil",
         "Decoding and executing base64 payload",
         r"(echo|printf)\s+.*\|\s*base64\s+(-d|--decode)\s*\|\s*(ba)?sh", ["bash", "sh", "*"]),
    Rule("EXFIL-005", "Python data exfil", "high", "data_exfil",
         "Python sending sensitive data to external endpoint",
         r"requests\.(post|put)\s*\(.*?(open\(|/etc/|password|secret|token|key)", ["python", "*"]),

    # ===== CRYPTO MINERS =====
    Rule("MINER-001", "Crypto miner binaries", "high", "crypto_miner",
         "Reference to known mining binaries",
         r"(xmrig|cgminer|bfgminer|cpuminer|minerd|ethminer|t-rex|nbminer|phoenixminer)", ["*"]),
    Rule("MINER-002", "Mining pool connection", "high", "crypto_miner",
         "Mining pool connection string",
         r"(stratum\+tcp://|stratum\+ssl://|pool\.(minexmr|supportxmr|hashvault|nanopool))", ["*"]),
    Rule("MINER-003", "Monero wallet address", "medium", "crypto_miner",
         "Monero wallet address — may indicate mining",
         r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}", ["*"]),

    # ===== OBFUSCATION =====
    Rule("OBFUSC-001", "Hex-encoded commands", "high", "obfuscation",
         "Shell commands built from hex strings",
         r"(\\x[0-9a-fA-F]{2}){10,}", ["*"]),
    Rule("OBFUSC-002", "eval with encoded string", "high", "obfuscation",
         "Evaluating decoded/decompressed string",
         r"eval\s*\(\s*(base64|atob|decode|decompress|Buffer\.from|unescape)", ["javascript", "python", "php", "ruby", "*"]),
    Rule("OBFUSC-003", "PowerShell encoded command", "critical", "obfuscation",
         "PowerShell executing base64-encoded commands",
         r"powershell.*(-enc|-EncodedCommand|-e)\s+[A-Za-z0-9+/=]{20,}", ["powershell", "ps1", "bat", "cmd", "*"]),
    Rule("OBFUSC-004", "Python exec/compile obfuscation", "high", "obfuscation",
         "Python exec/compile with encoded data",
         r"exec\s*\(\s*(compile|marshal\.loads|zlib\.decompress|base64\.b64decode)", ["python", "*"]),

    # ===== PRIVILEGE ESCALATION =====
    Rule("PRIVESC-001", "SUID bit manipulation", "critical", "privilege_escalation",
         "Setting SUID bit — allows privilege escalation",
         r"chmod\s+[ugo]*\+?[0-7]*s|chmod\s+(4755|4777|u\+s)", ["bash", "sh", "*"]),
    Rule("PRIVESC-002", "Sudoers modification", "critical", "privilege_escalation",
         "Modifying sudoers for persistent access",
         r"(echo|tee|cat).*>>\s*/etc/sudoers", ["bash", "sh", "*"]),
    Rule("PRIVESC-003", "Password file access", "high", "privilege_escalation",
         "Reading/modifying password files",
         r"(cat|less|more|head|tail)\s+/etc/(passwd|shadow|master\.passwd)", ["bash", "sh", "*"]),
    Rule("PRIVESC-004", "Cron persistence", "high", "privilege_escalation",
         "Adding cron job for persistence",
         r"(crontab|/etc/cron|/var/spool/cron).*(@reboot|curl|wget|bash|python|nc )", ["bash", "sh", "*"]),
    Rule("PRIVESC-005", "Systemd service creation", "high", "privilege_escalation",
         "Creating systemd service for persistence",
         r"(cp|mv|tee|cat).*(/etc/systemd/system/|/lib/systemd/system/).*\.service", ["bash", "sh", "*"]),

    # ===== NETWORK =====
    Rule("NET-001", "Hardcoded IP:port", "medium", "network",
         "Hardcoded IP:port — may indicate C2 server",
         r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", ["*"],
         "May be legitimate (e.g. localhost:8080). Check if IP is external."),
    Rule("NET-002", "SSH key theft", "critical", "network",
         "Accessing SSH private keys",
         r"(cat|cp|scp|curl.*-F).*~?/?\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)", ["bash", "sh", "*"]),
    Rule("NET-003", "Firewall disabling", "high", "network",
         "Disabling firewall rules",
         r"(iptables\s+-F|ufw\s+disable|systemctl\s+stop\s+firewalld|setenforce\s+0)", ["bash", "sh", "*"]),
    Rule("NET-004", "Known C2 frameworks", "critical", "network",
         "Reference to known C2/RAT frameworks",
         r"(meterpreter|cobalt\s*strike|empire|covenant|sliver|havoc|brute\s*ratel)", ["*"]),

    # ===== SUPPLY CHAIN =====
    Rule("SUPPLY-001", "Package install from URL", "medium", "supply_chain",
         "Installing package from URL instead of registry",
         r"(npm install|pip install)\s+https?://", ["bash", "sh", "javascript", "python", "*"]),
    Rule("SUPPLY-002", "Malicious postinstall hook", "high", "supply_chain",
         "Package hook making network requests",
         r'"(postinstall|preinstall|install)":\s*".*(curl|wget|node\s+-e|python\s+-c).*"', ["json", "*"]),
    Rule("SUPPLY-003", "GitHub Actions injection", "high", "supply_chain",
         "Untrusted input in Actions run step",
         r"run:.*\$\{\{\s*github\.event\.(issue|comment|pull_request)\.(title|body)", ["yaml", "yml", "*"]),

    # ===== CREDENTIAL THEFT =====
    Rule("CRED-001", "Env variable harvesting", "high", "credential_theft",
         "Dumping env vars to external destination",
         r"(env|printenv|set)\s*\|.*(curl|wget|nc |base64|/dev/tcp)", ["bash", "sh", "*"]),
    Rule("CRED-002", "AWS credential access", "critical", "credential_theft",
         "Accessing AWS credential files",
         r"(cat|cp|curl.*-F|scp).*~?/?\.aws/(credentials|config)", ["bash", "sh", "*"]),
    Rule("CRED-003", "Secret searching", "medium", "credential_theft",
         "Searching filesystem for tokens/secrets",
         r"(grep|find|rg)\s+.*(password|secret|token|api_key|apikey|AWS_SECRET).*(/|~|\$HOME)", ["bash", "sh", "*"]),
    Rule("CRED-004", "Keychain/keyring access", "high", "credential_theft",
         "Accessing macOS keychain or Linux keyring",
         r"(security\s+find-generic-password|secret-tool\s+lookup|kwallet)", ["bash", "sh", "*"]),
]


# =============================================================================
# Scanner Core
# =============================================================================

@dataclass
class Finding:
    rule: Rule
    file_path: str
    line_number: int
    line_content: str
    match: str


@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_time_ms: float = 0

    @property
    def critical_count(self): return sum(1 for f in self.findings if f.rule.severity == "critical")
    @property
    def high_count(self): return sum(1 for f in self.findings if f.rule.severity == "high")
    @property
    def medium_count(self): return sum(1 for f in self.findings if f.rule.severity == "medium")
    @property
    def low_count(self): return sum(1 for f in self.findings if f.rule.severity == "low")


EXT_MAP = {
    ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".ps1": "powershell", ".psm1": "powershell",
    ".bat": "bat", ".cmd": "cmd",
    ".go": "go", ".php": "php", ".rb": "ruby",
    ".pl": "perl", ".pm": "perl",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json",
    ".tf": "terraform", ".hcl": "terraform",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build", ".next", "target"}
MAX_FILE_SIZE = 5 * 1024 * 1024


def detect_language(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    return EXT_MAP.get(ext, "unknown")


def should_scan(file_path: Path) -> bool:
    if file_path.stat().st_size > MAX_FILE_SIZE or file_path.stat().st_size == 0:
        return False
    try:
        with open(file_path, "rb") as f:
            if b"\x00" in f.read(1024):
                return False
    except (PermissionError, OSError):
        return False
    return True


def scan_file(file_path: Path) -> List[Finding]:
    findings = []
    language = detect_language(file_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()
    except (PermissionError, OSError):
        return findings

    for rule in RULES:
        if "*" not in rule.languages and language not in rule.languages:
            continue
        compiled = re.compile(rule.pattern, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            match = compiled.search(line)
            if match:
                findings.append(Finding(
                    rule=rule,
                    file_path=str(file_path),
                    line_number=i,
                    line_content=line.strip()[:200],
                    match=match.group(0)[:100],
                ))
    return findings


def scan_target(target: str, verbose: bool = False) -> ScanResult:
    start = datetime.now()
    result = ScanResult()
    target_path = Path(target)

    if not target_path.exists():
        result.errors.append(f"Target not found: {target}")
        return result

    files = []
    if target_path.is_file():
        files.append(target_path)
    else:
        for root, dirs, fnames in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in fnames:
                fpath = Path(root) / fname
                if should_scan(fpath):
                    files.append(fpath)

    for fpath in files:
        result.files_scanned += 1
        if verbose:
            print(f"  scanning: {fpath}", file=sys.stderr)
        result.findings.extend(scan_file(fpath))

    result.scan_time_ms = (datetime.now() - start).total_seconds() * 1000
    return result


# =============================================================================
# Output
# =============================================================================

COLORS = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[94m", "low": "\033[90m"}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_results(result: ScanResult, verbose: bool = False, as_json: bool = False):
    if as_json:
        print(json.dumps({
            "scan_time_ms": result.scan_time_ms,
            "files_scanned": result.files_scanned,
            "summary": {"critical": result.critical_count, "high": result.high_count,
                        "medium": result.medium_count, "low": result.low_count, "total": len(result.findings)},
            "findings": [{"rule_id": f.rule.id, "rule_name": f.rule.name, "severity": f.rule.severity,
                          "category": f.rule.category, "description": f.rule.description,
                          "file": f.file_path, "line": f.line_number, "match": f.match,
                          "line_content": f.line_content} for f in result.findings],
            "errors": result.errors,
        }, indent=2))
        return

    print(f"\n{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║     BLVKOUT — Secure Code Review         ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}\n")

    if result.errors:
        for err in result.errors:
            print(f"  {COLORS['critical']}ERROR:{RESET} {err}")
        print()

    if not result.findings:
        print(f"  ✓ {BOLD}No threats detected{RESET}")
        print(f"  Scanned {result.files_scanned} file(s) in {result.scan_time_ms:.0f}ms\n")
        return

    for severity in ["critical", "high", "medium", "low"]:
        findings = [f for f in result.findings if f.rule.severity == severity]
        if not findings:
            continue
        c = COLORS[severity]
        print(f"  {c}{BOLD}[{severity.upper()}]{RESET} — {len(findings)} finding(s)\n")
        for f in findings:
            print(f"    {c}●{RESET} {BOLD}{f.rule.name}{RESET} ({f.rule.id})")
            print(f"      {f.file_path}:{f.line_number}")
            print(f"      {f.rule.description}")
            print(f"      Match: {c}{f.match}{RESET}")
            if verbose and f.rule.false_positive_hint:
                print(f"      ℹ️  {f.rule.false_positive_hint}")
            print()

    print(f"  {'─' * 44}")
    print(f"  {BOLD}Summary:{RESET} {len(result.findings)} finding(s) in {result.files_scanned} file(s)")
    parts = []
    if result.critical_count: parts.append(f"{COLORS['critical']}{result.critical_count} critical{RESET}")
    if result.high_count: parts.append(f"{COLORS['high']}{result.high_count} high{RESET}")
    if result.medium_count: parts.append(f"{COLORS['medium']}{result.medium_count} medium{RESET}")
    if result.low_count: parts.append(f"{COLORS['low']}{result.low_count} low{RESET}")
    print(f"  {' | '.join(parts)}")
    print(f"  Scan time: {result.scan_time_ms:.0f}ms\n")


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="BLVKOUT Secure Code Review — scan for malicious code patterns")
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--list-rules", action="store_true", help="List all detection rules")
    args = parser.parse_args()

    if args.list_rules:
        print(f"\n{'ID':<12} {'Severity':<10} {'Category':<22} {'Name'}")
        print("─" * 80)
        for rule in RULES:
            print(f"{rule.id:<12} {rule.severity:<10} {rule.category:<22} {rule.name}")
        print(f"\nTotal: {len(RULES)} rules\n")
        sys.exit(0)

    if not args.target:
        parser.error("target is required (file or directory to scan)")

    result = scan_target(args.target, verbose=args.verbose)
    print_results(result, verbose=args.verbose, as_json=args.json)
    sys.exit(1 if result.critical_count or result.high_count else 0)


if __name__ == "__main__":
    main()
