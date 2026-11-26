"""Remediation SLAs and time-boxed risk acceptances."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date, datetime
from fnmatch import fnmatch
from pathlib import Path

from vulnreport.model import Finding

# Days allowed from CVE publication to remediation, for fixable findings.
DEFAULT_SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}


@dataclass(frozen=True)
class RiskAcceptance:
    vuln_id: str
    artifact: str  # fnmatch pattern
    reason: str
    owner: str
    expires: date

    def matches(self, f: Finding) -> bool:
        return self.vuln_id == f.vuln_id and fnmatch(f.artifact, self.artifact)

    def expired(self, today: date) -> bool:
        return today > self.expires


@dataclass
class Assessment:
    finding: Finding
    sla_days: int | None
    age_days: int | None
    accepted_by: RiskAcceptance | None = None

    @property
    def breached(self) -> bool:
        return (
            self.accepted_by is None
            and self.finding.fixable
            and self.sla_days is not None
            and self.age_days is not None
            and self.age_days > self.sla_days
        )

    @property
    def days_remaining(self) -> int | None:
        if self.sla_days is None or self.age_days is None:
            return None
        return self.sla_days - self.age_days


@dataclass
class Policy:
    sla_days: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SLA_DAYS))
    acceptances: list[RiskAcceptance] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> Policy:
        if path is None:
            return cls()
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        sla = dict(DEFAULT_SLA_DAYS)
        sla.update({k.upper(): int(v) for k, v in raw.get("sla_days", {}).items()})
        acceptances = []
        for i, item in enumerate(raw.get("accept", [])):
            missing = {"id", "artifact", "reason", "owner", "expires"} - item.keys()
            if missing:
                raise ValueError(f"accept[{i}] is missing {sorted(missing)}")
            if not isinstance(item["expires"], date):
                raise ValueError(f"accept[{i}].expires must be a TOML date (YYYY-MM-DD)")
            acceptances.append(
                RiskAcceptance(
                    vuln_id=item["id"],
                    artifact=item["artifact"],
                    reason=item["reason"],
                    owner=item["owner"],
                    expires=item["expires"],
                )
            )
        return cls(sla_days=sla, acceptances=acceptances)

    def assess(self, findings: list[Finding], now: datetime) -> list[Assessment]:
        today = now.date()
        out = []
        for f in findings:
            acceptance = next(
                (a for a in self.acceptances if a.matches(f) and not a.expired(today)), None
            )
            out.append(
                Assessment(
                    finding=f,
                    sla_days=self.sla_days.get(f.severity),
                    age_days=f.age_days(now),
                    accepted_by=acceptance,
                )
            )
        return out

    def expired_acceptances(self, today: date) -> list[RiskAcceptance]:
        return [a for a in self.acceptances if a.expired(today)]
