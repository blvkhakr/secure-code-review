#!/usr/bin/env python3
"""
BLVKOUT Secure Code Review — Web UI

A local web interface for running scans and viewing reports.
No dependencies — uses Python's built-in http.server.

Usage:
    python ui.py                  # Starts on http://localhost:8000
    python ui.py --port 9000      # Custom port
    python ui.py --host 0.0.0.0   # Listen on all interfaces
"""

import os
import sys
import json
import argparse
import webbrowser
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime

from scan import scan_target, RULES
from report import generate_markdown_report, generate_html_report, gather_metrics, compute_risk_level


# =============================================================================
# HTML Template
# =============================================================================

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BLVKOUT — Secure Code Review</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0a0a0a; color: #e0e0e0; min-height: 100vh;
    display: flex; flex-direction: column;
}
header {
    background: #111; border-bottom: 1px solid #222; padding: 20px 40px;
    display: flex; align-items: center; gap: 16px;
}
header h1 { font-size: 1.4rem; color: #fff; font-weight: 600; }
header .badge {
    background: #4ade80; color: #000; font-size: 0.7rem; font-weight: 700;
    padding: 2px 8px; border-radius: 10px; text-transform: uppercase;
}
main { flex: 1; padding: 40px; max-width: 960px; margin: 0 auto; width: 100%; }

/* Scan Form */
.scan-card {
    background: #151515; border: 1px solid #222; border-radius: 12px;
    padding: 32px; margin-bottom: 32px;
}
.scan-card h2 { font-size: 1.1rem; margin-bottom: 16px; color: #ccc; }
.form-row { display: flex; gap: 12px; margin-bottom: 16px; }
.form-row input[type="text"] {
    flex: 1; padding: 12px 16px; border-radius: 8px; border: 1px solid #333;
    background: #0a0a0a; color: #fff; font-size: 0.95rem; outline: none;
    transition: border-color 0.2s;
}
.form-row input[type="text"]:focus { border-color: #4ade80; }
.form-row input[type="text"]::placeholder { color: #555; }
.btn {
    padding: 12px 24px; border-radius: 8px; border: none; cursor: pointer;
    font-size: 0.9rem; font-weight: 600; transition: all 0.2s;
}
.btn-primary { background: #4ade80; color: #000; }
.btn-primary:hover { background: #22c55e; }
.btn-primary:disabled { background: #333; color: #666; cursor: not-allowed; }
.btn-secondary { background: #222; color: #ccc; border: 1px solid #333; }
.btn-secondary:hover { background: #2a2a2a; border-color: #4ade80; }
.options { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.options label { display: flex; align-items: center; gap: 6px; font-size: 0.85rem; color: #888; cursor: pointer; }
.options input[type="checkbox"] { accent-color: #4ade80; }

/* Status */
.status { padding: 12px 16px; border-radius: 8px; margin-bottom: 24px; font-size: 0.9rem; display: none; }
.status.loading { display: block; background: #1a1a2e; border: 1px solid #2a2a4e; color: #60a5fa; }
.status.error { display: block; background: #1a0a0a; border: 1px solid #4e1a1a; color: #ef4444; }
.status.success { display: block; background: #0a1a0a; border: 1px solid #1a4e1a; color: #4ade80; }

/* Results */
.results { display: none; }
.results.visible { display: block; }
.summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin-bottom: 24px;
}
.summary-card {
    background: #151515; border: 1px solid #222; border-radius: 10px;
    padding: 16px; text-align: center;
}
.summary-card .count { font-size: 2rem; font-weight: 700; }
.summary-card .label { font-size: 0.75rem; text-transform: uppercase; color: #888; margin-top: 4px; }
.count-critical { color: #ef4444; }
.count-high { color: #f59e0b; }
.count-medium { color: #60a5fa; }
.count-low { color: #888; }
.count-files { color: #4ade80; }
.risk-badge {
    display: inline-block; padding: 4px 12px; border-radius: 6px;
    font-size: 0.8rem; font-weight: 700; text-transform: uppercase;
}
.risk-CRITICAL { background: #4e1a1a; color: #ef4444; }
.risk-HIGH { background: #4e3a1a; color: #f59e0b; }
.risk-MEDIUM { background: #1a2a4e; color: #60a5fa; }
.risk-LOW { background: #1a1a1a; color: #888; }
.risk-NONE { background: #1a4e1a; color: #4ade80; }

/* Findings Table */
.findings-table { width: 100%; border-collapse: collapse; margin-top: 16px; }
.findings-table th {
    text-align: left; padding: 10px 12px; background: #1a1a1a;
    border-bottom: 1px solid #333; font-size: 0.8rem; color: #888;
    text-transform: uppercase;
}
.findings-table td {
    padding: 10px 12px; border-bottom: 1px solid #1a1a1a;
    font-size: 0.85rem; vertical-align: top;
}
.findings-table tr:hover td { background: #151515; }
.sev { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.sev-critical { background: #4e1a1a; color: #ef4444; }
.sev-high { background: #4e3a1a; color: #f59e0b; }
.sev-medium { background: #1a2a4e; color: #60a5fa; }
.sev-low { background: #1a1a1a; color: #888; }
code.match { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; word-break: break-all; }

/* Export */
.export-bar {
    display: flex; gap: 8px; margin-top: 24px; padding-top: 16px;
    border-top: 1px solid #222;
}

/* Rules modal */
.rules-section { margin-top: 32px; }
.rules-section h3 { font-size: 1rem; color: #ccc; margin-bottom: 12px; }
.rules-count { color: #4ade80; font-weight: 600; }

footer { padding: 20px 40px; text-align: center; color: #444; font-size: 0.8rem; border-top: 1px solid #1a1a1a; }
</style>
</head>
<body>
<header>
    <h1>🛡️ BLVKOUT</h1>
    <span class="badge">Secure Code Review</span>
</header>

<main>
    <div class="scan-card">
        <h2>Scan Target</h2>
        <div class="form-row">
            <input type="text" id="target" placeholder="Enter file or directory path (e.g. C:\\Projects\\myapp)" />
            <button class="btn btn-primary" id="scanBtn" onclick="runScan()">Scan</button>
        </div>
        <div class="options">
            <label><input type="checkbox" id="verbose"> Verbose</label>
            <label><input type="checkbox" id="autoReport" checked> Generate report</label>
        </div>
    </div>

    <div class="status" id="status"></div>

    <div class="results" id="results">
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:20px;">
            <h2 style="color:#fff; font-size:1.1rem;">Results</h2>
            <span class="risk-badge" id="riskBadge"></span>
            <span style="color:#555; font-size:0.8rem;" id="scanTime"></span>
        </div>

        <div class="summary-grid">
            <div class="summary-card"><div class="count count-critical" id="cCritical">0</div><div class="label">Critical</div></div>
            <div class="summary-card"><div class="count count-high" id="cHigh">0</div><div class="label">High</div></div>
            <div class="summary-card"><div class="count count-medium" id="cMedium">0</div><div class="label">Medium</div></div>
            <div class="summary-card"><div class="count count-low" id="cLow">0</div><div class="label">Low</div></div>
            <div class="summary-card"><div class="count count-files" id="cFiles">0</div><div class="label">Files</div></div>
        </div>

        <div id="findingsContainer"></div>

        <div class="export-bar" id="exportBar">
            <button class="btn btn-secondary" onclick="exportReport('md')">Export Markdown</button>
            <button class="btn btn-secondary" onclick="exportReport('html')">Export HTML</button>
            <button class="btn btn-secondary" onclick="exportReport('json')">Export JSON</button>
        </div>
    </div>

    <div class="rules-section">
        <h3>Detection Rules: <span class="rules-count" id="rulesCount">0</span></h3>
        <button class="btn btn-secondary" onclick="toggleRules()">Show Rules</button>
        <div id="rulesTable" style="display:none; margin-top:12px; max-height:400px; overflow-y:auto;"></div>
    </div>
</main>

<footer>BLVKOUT Secure Code Review Scanner — Pure Python, Zero Dependencies</footer>

<script>
let lastScanData = null;

async function runScan() {
    const target = document.getElementById('target').value.trim();
    if (!target) { showStatus('Enter a file or directory path', 'error'); return; }

    const verbose = document.getElementById('verbose').checked;
    const btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    showStatus('Scanning target...', 'loading');
    document.getElementById('results').classList.remove('visible');

    try {
        const params = new URLSearchParams({ target, verbose: verbose ? '1' : '0' });
        const resp = await fetch('/api/scan?' + params);
        const data = await resp.json();

        if (data.error) { showStatus(data.error, 'error'); return; }

        lastScanData = data;
        showStatus(`Scan complete — ${data.summary.total} finding(s) in ${data.files_scanned} file(s)`, 'success');
        renderResults(data);
    } catch (e) {
        showStatus('Request failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Scan';
    }
}

function showStatus(msg, type) {
    const el = document.getElementById('status');
    el.textContent = msg;
    el.className = 'status ' + type;
}

function renderResults(data) {
    document.getElementById('cCritical').textContent = data.summary.critical;
    document.getElementById('cHigh').textContent = data.summary.high;
    document.getElementById('cMedium').textContent = data.summary.medium;
    document.getElementById('cLow').textContent = data.summary.low;
    document.getElementById('cFiles').textContent = data.files_scanned;
    document.getElementById('scanTime').textContent = `${data.scan_time_ms.toFixed(0)}ms`;

    const badge = document.getElementById('riskBadge');
    badge.textContent = data.risk_level;
    badge.className = 'risk-badge risk-' + data.risk_level;

    const container = document.getElementById('findingsContainer');
    if (data.findings.length === 0) {
        container.innerHTML = '<p style="color:#4ade80; padding:20px 0;">✅ No threats detected.</p>';
    } else {
        let html = '<table class="findings-table"><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Match</th></tr></thead><tbody>';
        for (const f of data.findings) {
            html += `<tr>
                <td><span class="sev sev-${f.severity}">${f.severity.toUpperCase()}</span></td>
                <td>${f.rule_name}<br><small style="color:#555">${f.rule_id}</small></td>
                <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${f.file}">${f.file.split(/[/\\\\]/).pop()}</td>
                <td>${f.line}</td>
                <td><code class="match">${escapeHtml(f.match)}</code></td>
            </tr>`;
        }
        html += '</tbody></table>';
        container.innerHTML = html;
    }

    document.getElementById('results').classList.add('visible');
}

function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function exportReport(format) {
    if (!lastScanData) return;
    const target = document.getElementById('target').value.trim();
    const params = new URLSearchParams({ target, format });
    const resp = await fetch('/api/report?' + params);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const ext = format === 'md' ? 'md' : format === 'html' ? 'html' : 'json';
    a.download = `blvkout-report.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
}

async function toggleRules() {
    const el = document.getElementById('rulesTable');
    if (el.style.display === 'none') {
        const resp = await fetch('/api/rules');
        const rules = await resp.json();
        document.getElementById('rulesCount').textContent = rules.length;
        let html = '<table class="findings-table"><thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Category</th></tr></thead><tbody>';
        for (const r of rules) {
            html += `<tr><td>${r.id}</td><td>${r.name}</td><td><span class="sev sev-${r.severity}">${r.severity.toUpperCase()}</span></td><td>${r.category}</td></tr>`;
        }
        html += '</tbody></table>';
        el.innerHTML = html;
        el.style.display = 'block';
    } else {
        el.style.display = 'none';
    }
}

// Load rules count on page load
fetch('/api/rules').then(r => r.json()).then(rules => {
    document.getElementById('rulesCount').textContent = rules.length;
});

// Allow Enter key to trigger scan
document.getElementById('target').addEventListener('keydown', e => {
    if (e.key === 'Enter') runScan();
});
</script>
</body>
</html>"""


# =============================================================================
# HTTP Handler
# =============================================================================

class ScanHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Quieter logging
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] {args[0]}", file=sys.stderr)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "":
            self._serve_html()
        elif path == "/api/scan":
            self._handle_scan(params)
        elif path == "/api/report":
            self._handle_report(params)
        elif path == "/api/rules":
            self._handle_rules()
        else:
            self._respond(404, "text/plain", b"Not found")

    def _serve_html(self):
        self._respond(200, "text/html", HTML_PAGE.encode())

    def _handle_scan(self, params):
        target = params.get("target", [""])[0]
        verbose = params.get("verbose", ["0"])[0] == "1"

        if not target:
            self._json_response({"error": "No target specified"})
            return

        target_path = Path(target)
        if not target_path.exists():
            self._json_response({"error": f"Path not found: {target}"})
            return

        result = scan_target(target, verbose=verbose)
        risk = compute_risk_level(result)

        data = {
            "scan_time_ms": result.scan_time_ms,
            "files_scanned": result.files_scanned,
            "risk_level": risk,
            "summary": {
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "total": len(result.findings),
            },
            "findings": [
                {
                    "rule_id": f.rule.id,
                    "rule_name": f.rule.name,
                    "severity": f.rule.severity,
                    "category": f.rule.category,
                    "description": f.rule.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "match": f.match,
                    "line_content": f.line_content,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }
        self._json_response(data)

    def _handle_report(self, params):
        target = params.get("target", [""])[0]
        fmt = params.get("format", ["md"])[0]

        if not target:
            self._json_response({"error": "No target specified"})
            return

        target_path = Path(target)
        if not target_path.exists():
            self._json_response({"error": f"Path not found: {target}"})
            return

        result = scan_target(target)
        metrics = gather_metrics(target)

        if fmt == "html":
            report = generate_html_report(target, result, metrics)
            self._respond(200, "text/html", report.encode())
        elif fmt == "json":
            from report import compute_risk_level as crl
            report_data = {
                "meta": {
                    "application": Path(target).name,
                    "reviewer": "BLVKOUT Automated Scanner",
                    "date": datetime.now().isoformat(),
                    "risk_level": crl(result),
                },
                "summary": {
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                    "low": result.low_count,
                    "total": len(result.findings),
                },
                "findings": [
                    {
                        "id": f.rule.id, "name": f.rule.name,
                        "severity": f.rule.severity, "file": f.file_path,
                        "line": f.line_number, "evidence": f.line_content,
                    }
                    for f in result.findings
                ],
            }
            self._respond(200, "application/json", json.dumps(report_data, indent=2).encode())
        else:
            report = generate_markdown_report(target, result, metrics)
            self._respond(200, "text/markdown", report.encode())

    def _handle_rules(self):
        rules = [
            {"id": r.id, "name": r.name, "severity": r.severity, "category": r.category, "description": r.description}
            for r in RULES
        ]
        self._json_response(rules)

    def _json_response(self, data):
        body = json.dumps(data, indent=2).encode()
        self._respond(200, "application/json", body)

    def _respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="BLVKOUT Secure Code Review — Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--no-open", action="store_true", help="Don't auto-open browser")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), ScanHandler)
    url = f"http://{args.host}:{args.port}"

    print(f"\n  🛡️  BLVKOUT Secure Code Review")
    print(f"  ─────────────────────────────")
    print(f"  Running at: {url}")
    print(f"  Press Ctrl+C to stop\n")

    if not args.no_open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
