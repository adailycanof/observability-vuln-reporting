# Runbook: VaultPermissionDeniedSpike

**Alert:** more than 10 denied Vault requests in 5 minutes, sustained for 5 minutes.
**Two very different causes:** a broken deploy (common) or someone probing for secrets (rare, serious).

## Who is being denied?

Grafana → Security → **Security audit → Denied Vault requests** shows path, identity and error. Or in Loki:

```logql
{namespace="vault"} |= "\"type\":\"response\"" |= "permission denied" | json
  | line_format "{{.request_path}} {{.auth_metadata_service_account_namespace}}/{{.auth_metadata_service_account_name}}"
```

## Decide

| Pattern | Meaning | Action |
|---|---|---|
| One ServiceAccount, one path, started right after a deploy | Policy/role drift: the app needs a new path | Fix the Vault policy through a PR; never widen it by hand |
| One identity walking many unrelated paths (`secret/data/*`, `sys/*`) | **Enumeration** | Treat as a security incident: revoke the identity's tokens, isolate the workload |
| Denials from a human token | Mistyped path, or someone looking around | Ask them; if unexplained, incident |

## Contain (incident case)

```bash
# revoke every token issued through the Kubernetes auth mount for that role
vault token revoke -mode=path auth/kubernetes/login
# or remove the role from its policies while you investigate
vault write auth/kubernetes/role/<role> token_policies=default
```

Keep the audit log as evidence: export the Loki query result before retention expires.
