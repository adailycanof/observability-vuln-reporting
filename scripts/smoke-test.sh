#!/usr/bin/env bash
# End-to-end proof that the pipeline works, against the compose stack:
#   Trivy JSON -> vulnreport -> Pushgateway -> Prometheus rule -> Alertmanager
#   Vault audit log line -> Loki -> Loki ruler -> Alertmanager
#   Grafana has both dashboards and all datasources provisioned
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PROM=http://127.0.0.1:9090
AM=http://127.0.0.1:9093
LOKI=http://127.0.0.1:3100
GRAFANA=http://127.0.0.1:3000
failed=0

ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m  ✗\033[0m %s\n' "$*"; failed=1; }
wait_for() { # wait_for <seconds> <description> <cmd...>
  local timeout=$1 desc=$2
  shift 2
  for ((i = 0; i < timeout; i += 3)); do
    if "$@" >/dev/null 2>&1; then ok "$desc"; return 0; fi
    sleep 3
  done
  bad "$desc (timed out after ${timeout}s)"
}

# shellcheck disable=SC2329 # invoked through wait_for
am_has_alert() { curl -fsS "$AM/api/v2/alerts?filter=alertname=\"$1\"" | jq -e 'length > 0'; }

echo "==> Prometheus"
n_rules=$(curl -fsS "$PROM/api/v1/rules" | jq '[.data.groups[].rules[]] | length')
if [[ $n_rules -ge 11 ]]; then ok "$n_rules recording/alerting rules loaded"; else bad "only $n_rules rules loaded"; fi

echo "==> vulnreport -> Pushgateway -> Prometheus -> Alertmanager"
PYTHONPATH=src python3 -m vulnreport tests/fixtures/app.json tests/fixtures/clean.json \
  --policy tests/fixtures/policy.toml --push http://127.0.0.1:9091
wait_for 60 "Prometheus scraped vuln_sla_breaches" \
  bash -c "curl -fsS '$PROM/api/v1/query?query=vuln_sla_breaches' | jq -e '.data.result | length > 0'"
wait_for 90 "VulnerabilitySLABreachCritical reached Alertmanager" am_has_alert VulnerabilitySLABreachCritical
if curl -fsS "$AM/api/v2/alerts?filter=alertname=\"VulnerabilitySLABreachCritical\"" |
  jq -e '.[0].labels.artifact == "ghcr.io/example/app:1.4.2"' >/dev/null; then
  ok "alert carries the artifact label"
else
  bad "alert is missing the artifact label"
fi

echo "==> Vault audit log -> Loki -> Loki ruler -> Alertmanager"
wait_for 120 "Loki is ready" bash -c "curl -fsS '$LOKI/ready' | grep -qx ready"
wait_for 60 "Loki ruler loaded the security-audit rules" \
  bash -c "curl -fsS '$LOKI/loki/api/v1/rules' | grep -q VaultRootTokenUsed"
ts=$(date +%s%N)
line='{"type":"request","time":"2026-11-26T10:00:00Z","auth":{"display_name":"root","policies":["root"]},"request":{"operation":"read","path":"secret/data/demo/app"}}'
jq -nc --arg ts "$ts" --arg line "$line" \
  '{streams: [{stream: {namespace: "vault", container: "vault"}, values: [[$ts, $line]]}]}' |
  curl -fsS -X POST -H 'Content-Type: application/json' --data-binary @- "$LOKI/loki/api/v1/push"
wait_for 30 "audit line is queryable in Loki" \
  bash -c "curl -fsSG '$LOKI/loki/api/v1/query_range' --data-urlencode 'query={namespace=\"vault\"} | json | auth_display_name=\"root\"' | jq -e '.data.result | length > 0'"
wait_for 120 "VaultRootTokenUsed reached Alertmanager" am_has_alert VaultRootTokenUsed

echo "==> Grafana"
wait_for 60 "Grafana is healthy" curl -fsS "$GRAFANA/api/health"
for uid in vuln-management security-audit; do
  wait_for 30 "dashboard $uid provisioned" curl -fsS "$GRAFANA/api/dashboards/uid/$uid"
done
for ds in prometheus loki alertmanager; do
  wait_for 30 "datasource $ds provisioned" curl -fsS "$GRAFANA/api/datasources/uid/$ds"
done

exit "$failed"
