# Vulnerability and patching process

## Sources of findings

| Source | When | Gate |
|---|---|---|
| Trivy in every image build (CI) | Every PR / push | Blocks merge on fixable CRITICAL/HIGH |
| Trivy IaC/config scan (CI) | Every PR | Blocks merge on HIGH/CRITICAL misconfiguration |
| Scheduled scan of running images (`images.txt`) | Daily | Feeds SLA metrics + alerts |
| Dependabot/Renovate | Continuous | Opens update PRs |

The scheduled scan matters because **new CVEs are published against images that were clean when they shipped**.

## SLAs

From CVE publication, for findings that have a fix available:

| Severity | SLA | Alert |
|---|---|---|
| CRITICAL | 7 days | Page, immediately after breach |
| HIGH | 30 days | Security channel |
| MEDIUM | 90 days | Security channel |
| LOW | 180 days | Report only |

Findings without a fix are tracked, not alerted. They become fixable (and start counting) as soon as upstream ships a patch.

## Exceptions

Only through a time-boxed `[[accept]]` entry in `policy.toml`, approved by security in a PR, with an owner, a reason and an expiry date (90 days max for CRITICAL/HIGH). Expiry is enforced: the finding counts again and `RiskAcceptanceExpired` fires.

## Reporting

`vulnreport` produces, from the same data:

- **Markdown** for the weekly summary (GitHub job summary, or paste into the security review)
- **JSON** for audit evidence and other tooling
- **Prometheus metrics** for the dashboard and alerts

Compliance questions ("how many criticals are past SLA, and how long has the oldest been open?") are answered from `vuln_sla_breaches` and `vuln_oldest_fixable_age_days`, with history in Prometheus.

## When a vulnerability becomes an incident

Escalate to the incident process when **any** of these is true:

- It is on the CISA KEV list, or there is public exploit code, **and** the affected component is internet-facing
- There are signs of exploitation (WAF hits, unexpected processes, `VaultPermissionDeniedSpike`, unusual egress)
- A secret may have been exposed: rotate first, investigate second
