# Runbook: ExternalSecretSyncFailing

**Alert:** an ExternalSecret has been not Ready for 15 minutes.
**Impact:** the Kubernetes Secret keeps its last good value, so the app keeps running. But rotations made in Vault are **not** reaching the cluster. If a secret was rotated because it leaked, the leaked value is still live.

## Diagnose

```bash
kubectl -n <ns> describe externalsecret <name>     # status.conditions[].message
kubectl -n <ns> describe secretstore <store>        # store-level auth problems show here
kubectl -n external-secrets logs deploy/external-secrets --since=30m | grep <name>
```

| Message | Fix |
|---|---|
| `permission denied` | Vault policy no longer covers the path; fix the policy in Git |
| `secret not found` | Path or key renamed in Vault; fix `remoteRef`/`extract.key` |
| `could not get provider client` / login failed | Vault role binding or audience mismatch for the store's ServiceAccount |
| connection refused / timeout | Vault down, or a NetworkPolicy blocks the external-secrets namespace |

## Force a sync after the fix

```bash
kubectl -n <ns> annotate externalsecret <name> force-sync="$(date +%s)" --overwrite
```
