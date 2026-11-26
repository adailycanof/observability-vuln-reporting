"""Parse Trivy JSON (schema v2) into flat findings."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


@dataclass(frozen=True)
class Finding:
    artifact: str
    target: str
    vuln_id: str
    package: str
    installed: str
    fixed: str
    severity: str
    title: str
    published: datetime | None

    @property
    def fixable(self) -> bool:
        return bool(self.fixed)

    def age_days(self, now: datetime) -> int | None:
        if self.published is None:
            return None
        return max(0, (now - self.published).days)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_report(data: dict) -> list[Finding]:
    """Flatten one Trivy report. Duplicate (artifact, vuln, package) rows are merged."""
    if data.get("SchemaVersion") != 2:
        raise ValueError(f"unsupported Trivy SchemaVersion: {data.get('SchemaVersion')!r}")

    artifact = data.get("ArtifactName", "unknown")
    seen: set[tuple[str, str, str]] = set()
    findings: list[Finding] = []

    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            key = (artifact, v["VulnerabilityID"], v.get("PkgName", ""))
            if key in seen:
                continue
            seen.add(key)
            severity = v.get("Severity", "UNKNOWN").upper()
            findings.append(
                Finding(
                    artifact=artifact,
                    target=result.get("Target", ""),
                    vuln_id=v["VulnerabilityID"],
                    package=v.get("PkgName", ""),
                    installed=v.get("InstalledVersion", ""),
                    fixed=v.get("FixedVersion", ""),
                    severity=severity if severity in SEVERITIES else "UNKNOWN",
                    title=v.get("Title", ""),
                    published=_parse_date(v.get("PublishedDate")),
                )
            )
    return findings


def load_reports(paths: list[Path]) -> tuple[list[Finding], list[str]]:
    """Load many Trivy JSON files. Returns findings and the list of scanned artifacts."""
    findings: list[Finding] = []
    artifacts: list[str] = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        artifacts.append(data.get("ArtifactName", path.stem))
        findings.extend(parse_report(data))
    return findings, artifacts
