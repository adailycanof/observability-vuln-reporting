import json

import pytest

from vulnreport.model import load_reports, parse_report


def test_parse_flattens_and_dedupes(fixtures):
    findings = parse_report(json.loads((fixtures / "app.json").read_text()))
    ids = [f.vuln_id for f in findings]
    assert ids.count("CVE-2026-0005") == 1
    assert len(findings) == 7


def test_unknown_severity_and_missing_date(fixtures, now):
    findings = parse_report(json.loads((fixtures / "app.json").read_text()))
    weird = next(f for f in findings if f.vuln_id == "CVE-2026-0007")
    assert weird.severity == "UNKNOWN"
    assert weird.published is None
    assert weird.age_days(now) is None


def test_fixable_and_age(fixtures, now):
    findings = {f.vuln_id: f for f in parse_report(json.loads((fixtures / "app.json").read_text()))}
    assert findings["CVE-2026-0001"].fixable
    assert not findings["CVE-2026-0003"].fixable
    assert findings["CVE-2026-0001"].age_days(now) == 55


def test_clean_report_keeps_artifact(fixtures):
    findings, artifacts = load_reports([fixtures / "clean.json"])
    assert findings == []
    assert artifacts == ["public.ecr.aws/example/clean:2.0.0"]


def test_rejects_unknown_schema():
    with pytest.raises(ValueError, match="SchemaVersion"):
        parse_report({"SchemaVersion": 1})


def test_bad_date_is_ignored():
    report = {
        "SchemaVersion": 2,
        "ArtifactName": "x",
        "Results": [
            {
                "Target": "t",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "Severity": "LOW", "PublishedDate": "nope"},
                    {"VulnerabilityID": "CVE-2", "Severity": "LOW", "PublishedDate": "2026-01-01"},
                ],
            }
        ],
    }
    first, second = parse_report(report)
    assert first.published is None
    assert second.published is not None and second.published.tzinfo is not None
