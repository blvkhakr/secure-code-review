# BLVKOUT Secure Code Review

A malware and threat detection scanner for source code and scripts. Finds reverse shells, backdoors, crypto miners, data exfiltration, privilege escalation, and supply chain attacks.

**No dependencies.** Pure Python 3. Works on any OS.

## Usage

```bash
# Scan a single file
python scan.py script.sh

# Scan an entire directory
python scan.py ./project/

# Verbose mode (shows false positive hints)
python scan.py -v suspicious.py

# JSON output (for CI/CD pipelines)
python scan.py --json payload.sh > report.json

# List all detection rules
python scan.py --list-rules
```

## What it detects

| Category | Examples |
|---|---|
| Reverse shells | bash, netcat, Python, PowerShell, PHP, Ruby |
| Data exfiltration | curl pipe to shell, DNS exfil, base64 decode+exec |
| Crypto miners | xmrig, mining pools, wallet addresses |
| Obfuscation | hex encoding, eval+decode, PowerShell -enc |
| Privilege escalation | SUID manipulation, sudoers modification, cron persistence |
| Network threats | C2 frameworks, SSH key theft, firewall disabling |
| Supply chain | malicious postinstall hooks, Actions injection |
| Credential theft | AWS creds, env harvesting, keychain access |

## Exit codes

- `0` — no critical or high findings
- `1` — critical or high severity threats detected

## CI/CD Integration

Add to any pipeline:
```yaml
- name: Security scan
  run: python scan.py ./src/ --json > security-report.json
```

## Languages supported

Bash, Python, JavaScript/TypeScript, PowerShell, Go, PHP, Ruby, Perl, YAML, JSON, Terraform, Docker — plus wildcard rules that catch patterns in any text file.

## Adding custom rules

Edit the `RULES` list in `scan.py`. Each rule needs:
- `id` — unique identifier
- `name` — human-readable name
- `severity` — critical, high, medium, or low
- `category` — grouping for output
- `description` — what it means
- `pattern` — regex pattern
- `languages` — which file types to check, or `["*"]` for all
