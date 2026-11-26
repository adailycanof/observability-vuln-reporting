"""Generate Grafana dashboards as code.

python observability/grafana/build_dashboards.py          # write JSON
python observability/grafana/build_dashboards.py --check  # CI: fail if JSON is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

OUT = Path(__file__).parent / "dashboards"
PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
SEV_COLORS = {"CRITICAL": "dark-red", "HIGH": "orange", "MEDIUM": "yellow", "LOW": "blue"}


class Layout:
    """Places panels left to right on a 24-column grid, wrapping rows."""

    def __init__(self) -> None:
        self.x = self.y = self.row_h = 0
        self.next_id = 1

    def place(self, panel: dict, w: int, h: int) -> dict:
        if self.x + w > 24:
            self.x, self.y, self.row_h = 0, self.y + self.row_h, 0
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        panel["id"] = self.next_id
        self.next_id += 1
        self.x += w
        self.row_h = max(self.row_h, h)
        return panel


def target(expr: str, legend: str = "", ds: dict = PROM, instant: bool = False, **kw) -> dict:
    t = {"datasource": ds, "expr": expr, "refId": "A", "legendFormat": legend, **kw}
    if instant:
        t["instant"] = True
        t["range"] = False
    return t


def stat(title, expr, *, thresholds=None, unit="none", description="", color_mode="background"):
    steps = thresholds or [{"color": "green", "value": None}, {"color": "red", "value": 1}]
    return {
        "type": "stat",
        "title": title,
        "description": description,
        "datasource": PROM,
        "targets": [target(expr, instant=True)],
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "thresholds": {"mode": "absolute", "steps": steps},
                "noValue": "no data",
            },
            "overrides": [],
        },
        "options": {
            "colorMode": color_mode,
            "graphMode": "none",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        },
    }


def severity_overrides() -> list[dict]:
    return [
        {
            "matcher": {"id": "byName", "options": sev},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}],
        }
        for sev, color in SEV_COLORS.items()
    ]


def vulnerability_dashboard() -> dict:
    lay = Layout()
    art = 'artifact=~"$artifact"'
    panels = [
        lay.place(
            stat(
                "Critical SLA breaches",
                f'sum(vuln_sla_breaches{{{art},vuln_severity="CRITICAL"}}) or vector(0)',
                description="Fixable CRITICAL findings older than 7 days. Target: 0.",
            ),
            6,
            4,
        ),
        lay.place(
            stat(
                "All SLA breaches",
                f"sum(vuln_sla_breaches{{{art}}}) or vector(0)",
                thresholds=[
                    {"color": "green", "value": None},
                    {"color": "orange", "value": 1},
                    {"color": "red", "value": 10},
                ],
            ),
            6,
            4,
        ),
        lay.place(
            stat(
                "Fixable critical + high",
                f'sum(vuln_findings{{{art},fixable="true",vuln_severity=~"CRITICAL|HIGH"}})',
                thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
                description="Patchable now: a rebuild on a newer base image clears these.",
            ),
            6,
            4,
        ),
        lay.place(
            stat(
                "Report age",
                "time() - max(vuln_report_timestamp_seconds)",
                unit="s",
                thresholds=[
                    {"color": "green", "value": None},
                    {"color": "orange", "value": 86400},
                    {"color": "red", "value": 172800},
                ],
                description="Stale data must never look like a clean bill of health.",
            ),
            6,
            4,
        ),
        lay.place(
            {
                "type": "timeseries",
                "title": "Fixable findings by severity",
                "datasource": PROM,
                "targets": [
                    target(
                        f'sum by (vuln_severity) (vuln_findings{{{art},fixable="true",'
                        f'vuln_severity!="UNKNOWN"}})',
                        "{{vuln_severity}}",
                    )
                ],
                "fieldConfig": {
                    "defaults": {"custom": {"drawStyle": "line", "fillOpacity": 10}},
                    "overrides": severity_overrides(),
                },
                "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
            },
            12,
            8,
        ),
        lay.place(
            {
                "type": "bargauge",
                "title": "SLA breaches by artifact",
                "datasource": PROM,
                "targets": [
                    target(
                        f"sort_desc(sum by (artifact) (vuln_sla_breaches{{{art}}}) > 0)",
                        "{{artifact}}",
                        instant=True,
                    )
                ],
                "fieldConfig": {
                    "defaults": {
                        "thresholds": {
                            "mode": "absolute",
                            "steps": [
                                {"color": "orange", "value": None},
                                {"color": "red", "value": 10},
                            ],
                        }
                    },
                    "overrides": [],
                },
                "options": {"orientation": "horizontal", "displayMode": "gradient"},
            },
            12,
            8,
        ),
        lay.place(
            {
                "type": "table",
                "title": "Findings by artifact",
                "datasource": PROM,
                "targets": [
                    target(
                        f"sum by (artifact, vuln_severity) (vuln_findings{{{art}}})",
                        instant=True,
                        format="table",
                    )
                ],
                "transformations": [
                    {
                        "id": "groupingToMatrix",
                        "options": {
                            "columnField": "vuln_severity",
                            "rowField": "artifact",
                            "valueField": "Value",
                        },
                    },
                    {
                        "id": "organize",
                        "options": {
                            "indexByName": {
                                "artifact\\vuln_severity": 0,
                                "CRITICAL": 1,
                                "HIGH": 2,
                                "MEDIUM": 3,
                                "LOW": 4,
                                "UNKNOWN": 5,
                            },
                            "renameByName": {"artifact\\vuln_severity": "Artifact"},
                        },
                    },
                ],
                "fieldConfig": {
                    "defaults": {"custom": {"cellOptions": {"type": "auto"}}},
                    "overrides": [
                        {
                            "matcher": {"id": "byName", "options": sev},
                            "properties": [
                                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": color}},
                            ],
                        }
                        for sev, color in SEV_COLORS.items()
                    ],
                },
            },
            16,
            9,
        ),
        lay.place(
            {
                "type": "table",
                "title": "Oldest unpatched finding (days)",
                "datasource": PROM,
                "targets": [
                    target(
                        f"sort_desc(max by (artifact, vuln_severity) "
                        f"(vuln_oldest_fixable_age_days{{{art}}}))",
                        instant=True,
                        format="table",
                    )
                ],
                "transformations": [
                    {
                        "id": "organize",
                        "options": {
                            "excludeByName": {"Time": True},
                            "renameByName": {"Value": "Age (days)", "vuln_severity": "Severity"},
                        },
                    }
                ],
                "fieldConfig": {"defaults": {}, "overrides": []},
            },
            8,
            9,
        ),
        lay.place(
            stat(
                "Expired risk acceptances",
                "max(vuln_risk_acceptances_expired) or vector(0)",
                description="Past their expiry date: renew with a fresh justification or delete.",
            ),
            6,
            4,
        ),
        lay.place(
            {
                "type": "alertlist",
                "title": "Firing security alerts",
                "options": {
                    "alertInstanceLabelFilter": '{team=~"security|platform"}',
                    "stateFilter": {"firing": True, "pending": True},
                    "maxItems": 20,
                    "viewMode": "list",
                    "groupMode": "default",
                    "datasource": "Alertmanager",
                },
            },
            18,
            4,
        ),
    ]
    return {
        "uid": "vuln-management",
        "title": "Vulnerability management",
        "tags": ["security", "trivy", "sla"],
        "timezone": "utc",
        "schemaVersion": 41,
        "refresh": "5m",
        "time": {"from": "now-30d", "to": "now"},
        "templating": {
            "list": [
                {
                    "name": "artifact",
                    "label": "Artifact",
                    "type": "query",
                    "datasource": PROM,
                    "query": {"query": "label_values(vuln_findings, artifact)", "refId": "q"},
                    "refresh": 2,
                    "includeAll": True,
                    "multi": True,
                    "allValue": ".*",
                    "current": {"text": "All", "value": "$__all"},
                }
            ]
        },
        "panels": panels,
    }


def logs(title, expr, h=8, w=24):
    return (
        {
            "type": "logs",
            "title": title,
            "datasource": LOKI,
            "targets": [target(expr, ds=LOKI)],
            "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending"},
        },
        w,
        h,
    )


def audit_dashboard() -> dict:
    lay = Layout()
    vault = '{namespace="vault", container="vault"}'
    k8s = '{job="kubernetes-audit"} | json'
    human = 'user_username!~"system:.*"'
    panels = [
        lay.place(
            stat("Vault sealed pods", "count(vault_core_unsealed == 0) or vector(0)"),
            6,
            4,
        ),
        lay.place(
            stat(
                "Certificates expiring < 7d",
                "count((certmanager_certificate_expiration_timestamp_seconds - time()) < 7*86400)"
                " or vector(0)",
            ),
            6,
            4,
        ),
        lay.place(
            stat(
                "ExternalSecrets failing",
                'count(externalsecret_status_condition{condition="Ready",status="False"} == 1)'
                " or vector(0)",
            ),
            6,
            4,
        ),
        lay.place(
            {
                "type": "stat",
                "title": "Root token uses (24h)",
                "datasource": LOKI,
                "targets": [
                    target(
                        f'sum(count_over_time({vault} |= "\\"type\\":\\"request\\"" | json '
                        f'| auth_display_name="root" [24h])) or vector(0)',
                        ds=LOKI,
                        instant=True,
                    )
                ],
                "fieldConfig": {
                    "defaults": {
                        "thresholds": {
                            "mode": "absolute",
                            "steps": [
                                {"color": "green", "value": None},
                                {"color": "red", "value": 1},
                            ],
                        }
                    },
                    "overrides": [],
                },
                "options": {"colorMode": "background", "graphMode": "none"},
            },
            6,
            4,
        ),
        lay.place(
            {
                "type": "timeseries",
                "title": "Vault requests: allowed vs denied",
                "datasource": LOKI,
                "targets": [
                    target(
                        f'sum(count_over_time({vault} |= "\\"type\\":\\"response\\"" '
                        f'!= "permission denied" [$__auto]))',
                        "allowed",
                        ds=LOKI,
                    ),
                    {
                        **target(
                            f'sum(count_over_time({vault} |= "\\"type\\":\\"response\\"" '
                            f'|= "permission denied" [$__auto]))',
                            "denied",
                            ds=LOKI,
                        ),
                        "refId": "B",
                    },
                ],
                "fieldConfig": {
                    "defaults": {
                        "custom": {
                            "drawStyle": "bars",
                            "fillOpacity": 60,
                            "stacking": {"mode": "normal"},
                        }
                    },
                    "overrides": [
                        {
                            "matcher": {"id": "byName", "options": "denied"},
                            "properties": [
                                {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}
                            ],
                        }
                    ],
                },
            },
            12,
            8,
        ),
        lay.place(
            {
                "type": "table",
                "title": "Secret reads by humans (24h)",
                "datasource": LOKI,
                "targets": [
                    target(
                        f"sum by (user_username, objectRef_namespace) (count_over_time({k8s} "
                        f'| objectRef_resource="secrets" | verb=~"get|list|watch" '
                        f"| {human} [24h]))",
                        ds=LOKI,
                        instant=True,
                    )
                ],
                "fieldConfig": {"defaults": {}, "overrides": []},
            },
            12,
            8,
        ),
        lay.place(
            *logs(
                "Denied Vault requests",
                f'{vault} |= "\\"type\\":\\"response\\"" |= "permission denied" | json '
                "| line_format `{{.request_path}} by {{.auth_display_name}} "
                "({{.auth_metadata_service_account_namespace}}/"
                "{{.auth_metadata_service_account_name}}): {{.error}}`",
            )
        ),
        lay.place(
            *logs(
                "Exec, port-forward and RBAC changes by humans",
                f'{k8s} | {human} | objectRef_subresource=~"exec|portforward|attach" '
                'or objectRef_resource=~"clusterrolebindings|rolebindings|clusterroles|roles" '
                "| line_format `{{.verb}} {{.objectRef_resource}}/{{.objectRef_name}} "
                "in {{.objectRef_namespace}} by {{.user_username}}`",
            )
        ),
    ]
    return {
        "uid": "security-audit",
        "title": "Security audit",
        "tags": ["security", "audit", "vault", "loki"],
        "timezone": "utc",
        "schemaVersion": 41,
        "refresh": "1m",
        "time": {"from": "now-24h", "to": "now"},
        "panels": panels,
    }


DASHBOARDS = {
    "vulnerability-management.json": vulnerability_dashboard,
    "security-audit.json": audit_dashboard,
}


def render(fn) -> str:
    return json.dumps(fn(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 if committed JSON is stale")
    args = ap.parse_args()
    stale = []
    OUT.mkdir(exist_ok=True)
    for name, fn in DASHBOARDS.items():
        path = OUT / name
        content = render(fn)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(name)
        else:
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path}")
    if stale:
        print(f"stale dashboards, run build_dashboards.py: {', '.join(stale)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
