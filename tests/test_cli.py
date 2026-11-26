import http.server
import json
import threading
from typing import ClassVar

import pytest

from vulnreport.cli import EXIT_BREACH, main, push_metrics


def run(fixtures, tmp_path, *extra):
    return main(
        [
            str(fixtures / "app.json"),
            str(fixtures / "clean.json"),
            "--policy",
            str(fixtures / "policy.toml"),
            "--markdown",
            str(tmp_path / "report.md"),
            "--json",
            str(tmp_path / "report.json"),
            "--metrics",
            str(tmp_path / "metrics.prom"),
            "--now",
            "2026-11-26T09:00:00",
            *extra,
        ]
    )


def test_outputs(fixtures, tmp_path):
    assert run(fixtures, tmp_path) == 0
    md = (tmp_path / "report.md").read_text()
    assert "## SLA breaches (1)" in md
    assert "CVE-2026-0001" in md
    assert "## Due within 7 days (1)" in md  # CVE-2026-0002, 3 days left
    assert "## Accepted risks (1)" in md
    assert "Expired risk acceptances (1)" in md
    assert "`public.ecr.aws/example/clean:2.0.0`" in md

    doc = json.loads((tmp_path / "report.json").read_text())
    assert [b["id"] for b in doc["breaches"]] == ["CVE-2026-0001"]
    assert doc["artifacts"]["public.ecr.aws/example/clean:2.0.0"]["total"] == {}

    prom = (tmp_path / "metrics.prom").read_text()
    app = 'artifact="ghcr.io/example/app:1.4.2"'
    assert f'vuln_sla_breaches{{{app},vuln_severity="CRITICAL"}} 1' in prom
    assert f'vuln_findings{{{app},vuln_severity="MEDIUM",fixable="false"}} 1' in prom
    assert f'vuln_oldest_fixable_age_days{{{app},vuln_severity="CRITICAL"}} 55' in prom
    assert "vuln_risk_acceptances_expired 1" in prom


def test_fail_on_breach(fixtures, tmp_path):
    assert run(fixtures, tmp_path, "--fail-on-breach") == EXIT_BREACH


def test_markdown_to_stdout(fixtures, capsys):
    assert main([str(fixtures / "clean.json"), "--markdown", "-", "--fail-on-breach"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Vulnerability report")
    assert "None. ✅" in out


def test_long_tables_are_truncated(tmp_path):
    vulns = [
        {
            "VulnerabilityID": f"CVE-2020-{i:04d}",
            "PkgName": "p",
            "InstalledVersion": "1",
            "FixedVersion": "2",
            "Severity": "HIGH",
            "PublishedDate": "2020-01-01T00:00:00Z",
        }
        for i in range(30)
    ]
    report = tmp_path / "big.json"
    report.write_text(
        json.dumps(
            {"SchemaVersion": 2, "ArtifactName": "big", "Results": [{"Vulnerabilities": vulns}]}
        )
    )
    md = tmp_path / "out.md"
    main([str(report), "--markdown", str(md)])
    assert "… 5 more" in md.read_text()


class _Capture(http.server.BaseHTTPRequestHandler):
    received: ClassVar[list] = []

    def do_PUT(self):
        length = int(self.headers["Content-Length"])
        _Capture.received.append((self.path, self.rfile.read(length).decode()))
        self.send_response(202)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_push_to_pushgateway():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Capture)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    push_metrics(f"http://127.0.0.1:{server.server_port}/", "vuln_x 1\n", job="vuln report")
    thread.join(5)
    server.server_close()
    path, body = _Capture.received[-1]
    assert path == "/metrics/job/vuln%20report"
    assert body == "vuln_x 1\n"


def test_push_rejects_non_http():
    with pytest.raises(ValueError, match="http"):
        push_metrics("file:///etc/passwd", "x 1\n")
