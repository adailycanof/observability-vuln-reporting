"""Render assessments as Markdown, JSON and Prometheus exposition format."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import date, datetime

from vulnreport.model import SEVERITIES
from vulnreport.policy import Assessment, RiskAcceptance

SEVERITY_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "UNKNOWN": "⬜"}


def summarise(assessments: list[Assessment], artifacts: list[str]) -> dict[str, dict]:
    per: dict[str, dict] = {
        a: {"total": Counter(), "fixable": Counter(), "breached": Counter(), "accepted": 0}
        for a in artifacts
    }
    for a in assessments:
        s = per.setdefault(
            a.finding.artifact,
            {"total": Counter(), "fixable": Counter(), "breached": Counter(), "accepted": 0},
        )
        s["total"][a.finding.severity] += 1
        if a.finding.fixable:
            s["fixable"][a.finding.severity] += 1
        if a.breached:
            s["breached"][a.finding.severity] += 1
        if a.accepted_by:
            s["accepted"] += 1
    return per


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(
    assessments: list[Assessment],
    artifacts: list[str],
    expired: list[RiskAcceptance],
    sla_days: dict[str, int],
    now: datetime,
    top: int = 25,
) -> str:
    per = summarise(assessments, artifacts)
    breaches = sorted(
        (a for a in assessments if a.breached),
        key=lambda a: (SEVERITIES.index(a.finding.severity), a.days_remaining or 0),
    )
    due_soon = sorted(
        (
            a
            for a in assessments
            if not a.breached
            and not a.accepted_by
            and a.finding.fixable
            and a.days_remaining is not None
            and 0 <= a.days_remaining <= 7
        ),
        key=lambda a: a.days_remaining or 0,
    )
    accepted = [a for a in assessments if a.accepted_by]

    sla_text = ", ".join(f"{s} {d}d" for s, d in sla_days.items())
    lines = [
        "# Vulnerability report",
        "",
        f"Generated {now:%Y-%m-%d %H:%M} UTC · {len(artifacts)} artifacts · SLA: {sla_text}",
        "",
        "| | Artifact | Critical | High | Medium | Low | Fixable | SLA breaches | Accepted |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for artifact in sorted(per):
        s = per[artifact]
        n_breach = sum(s["breached"].values())
        status = "❌" if n_breach else ("⚠️" if s["total"]["CRITICAL"] else "✅")
        lines.append(
            f"| {status} | `{artifact}` | {s['total']['CRITICAL']} | {s['total']['HIGH']} "
            f"| {s['total']['MEDIUM']} | {s['total']['LOW']} | {sum(s['fixable'].values())} "
            f"| {n_breach} | {s['accepted']} |"
        )

    def table(rows: list[Assessment], heading: str, empty: str) -> None:
        lines.extend(["", f"## {heading}", ""])
        if not rows:
            lines.append(empty)
            return
        lines.append("| Severity | ID | Artifact | Package | Installed → Fixed | Age | SLA |")
        lines.append("|---|---|---|---|---|---:|---:|")
        for a in rows[:top]:
            f = a.finding
            lines.append(
                f"| {SEVERITY_ICON[f.severity]} {f.severity} | {f.vuln_id} | `{f.artifact}` "
                f"| {_md_escape(f.package)} | {f.installed} → {f.fixed} "
                f"| {a.age_days}d | {a.sla_days}d |"
            )
        if len(rows) > top:
            lines.append(f"| | … {len(rows) - top} more | | | | | |")

    table(breaches, f"SLA breaches ({len(breaches)})", "None. ✅")
    table(due_soon, f"Due within 7 days ({len(due_soon)})", "None.")

    lines.extend(["", f"## Accepted risks ({len(accepted)})", ""])
    if accepted:
        lines.append("| ID | Artifact | Owner | Expires | Reason |")
        lines.append("|---|---|---|---|---|")
        for a in accepted:
            r = a.accepted_by
            if r is None:  # pragma: no cover - filtered above
                continue
            lines.append(
                f"| {r.vuln_id} | `{a.finding.artifact}` | {r.owner} | {r.expires} "
                f"| {_md_escape(r.reason)} |"
            )
    else:
        lines.append("None.")

    if expired:
        lines.extend(["", f"## ⚠️ Expired risk acceptances ({len(expired)})", ""])
        lines.append("These no longer suppress anything and need review or removal:")
        lines.append("")
        lines.extend(
            f"- {r.vuln_id} on `{r.artifact}` (owner {r.owner}, expired {r.expires})"
            for r in expired
        )

    return "\n".join(lines) + "\n"


def to_json(
    assessments: list[Assessment],
    artifacts: list[str],
    expired: list[RiskAcceptance],
    now: datetime,
) -> str:
    per = summarise(assessments, artifacts)
    doc = {
        "generated_at": now.isoformat(),
        "artifacts": {
            k: {
                "total": dict(v["total"]),
                "fixable": dict(v["fixable"]),
                "breached": dict(v["breached"]),
                "accepted": v["accepted"],
            }
            for k, v in sorted(per.items())
        },
        "breaches": [
            {
                "id": a.finding.vuln_id,
                "artifact": a.finding.artifact,
                "severity": a.finding.severity,
                "package": a.finding.package,
                "installed": a.finding.installed,
                "fixed": a.finding.fixed,
                "age_days": a.age_days,
                "sla_days": a.sla_days,
            }
            for a in assessments
            if a.breached
        ],
        "expired_acceptances": [
            {"id": r.vuln_id, "artifact": r.artifact, "owner": r.owner, "expires": str(r.expires)}
            for r in expired
        ],
    }
    return json.dumps(doc, indent=2, default=_json_default) + "\n"


def _json_default(o: object) -> str:
    if isinstance(o, date | datetime):
        return o.isoformat()
    raise TypeError(type(o).__name__)


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def to_prometheus(
    assessments: list[Assessment],
    artifacts: list[str],
    expired: list[RiskAcceptance],
    now: datetime,
) -> str:
    per = summarise(assessments, artifacts)
    oldest: dict[tuple[str, str], int] = defaultdict(int)
    for a in assessments:
        if a.finding.fixable and not a.accepted_by and a.age_days is not None:
            key = (a.finding.artifact, a.finding.severity)
            oldest[key] = max(oldest[key], a.age_days)

    out = [
        # The label is vuln_severity, not severity: alert rules set their own `severity`
        # label for Alertmanager routing, and that would overwrite the CVE severity.
        "# HELP vuln_findings Vulnerabilities found, by artifact, severity and fix availability.",
        "# TYPE vuln_findings gauge",
    ]
    for artifact, s in sorted(per.items()):
        for sev in SEVERITIES:
            fixable = s["fixable"][sev]
            out.append(
                f'vuln_findings{{artifact="{_label(artifact)}",vuln_severity="{sev}",fixable="true"}}'
                f" {fixable}"
            )
            out.append(
                f'vuln_findings{{artifact="{_label(artifact)}",vuln_severity="{sev}",fixable="false"}}'
                f" {s['total'][sev] - fixable}"
            )
    out += [
        "# HELP vuln_sla_breaches Fixable vulnerabilities older than their remediation SLA.",
        "# TYPE vuln_sla_breaches gauge",
    ]
    for artifact, s in sorted(per.items()):
        for sev in SEVERITIES:
            out.append(
                f'vuln_sla_breaches{{artifact="{_label(artifact)}",vuln_severity="{sev}"}}'
                f" {s['breached'][sev]}"
            )
    out += [
        "# HELP vuln_oldest_fixable_age_days Age of the oldest unaccepted fixable finding.",
        "# TYPE vuln_oldest_fixable_age_days gauge",
    ]
    for (artifact, sev), age in sorted(oldest.items()):
        labels = f'artifact="{_label(artifact)}",vuln_severity="{sev}"'
        out.append(f"vuln_oldest_fixable_age_days{{{labels}}} {age}")
    out += [
        "# HELP vuln_risk_acceptances_expired Risk acceptances past their expiry date.",
        "# TYPE vuln_risk_acceptances_expired gauge",
        f"vuln_risk_acceptances_expired {len(expired)}",
        "# HELP vuln_report_timestamp_seconds When this report was generated.",
        "# TYPE vuln_report_timestamp_seconds gauge",
        f"vuln_report_timestamp_seconds {int(now.timestamp())}",
    ]
    return "\n".join(out) + "\n"
