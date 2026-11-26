# Runbook: VaultSealed

**Alert:** `vault_core_unsealed == 0` on a Vault pod for 1m. **Severity:** critical (page).
**Impact:** while sealed, Vault serves nothing. External Secrets keeps the last synced values, so running apps are fine, but rotations stop, cert-manager cannot issue or renew, and anything that reads Vault directly fails.

## Diagnose

```bash
kubectl -n vault get pods
kubectl -n vault exec vault-0 -- vault status          # Sealed: true? HA mode? Raft peers?
kubectl -n vault logs vault-0 --tail=200 | grep -v '"type":"'   # skip audit lines
```

| Symptom | Likely cause |
|---|---|
| Pod restarted recently | Normal after a restart **without auto-unseal**: unseal it |
| `failed to unseal ... kms` in logs | Auto-unseal KMS key unreachable: check IAM role / KMS key policy / VPC endpoint |
| Only one pod sealed, others fine | That node lost its Raft data or cannot reach peers; check PVC and `vault operator raft list-peers` |

## Unseal (Shamir, lab / no auto-unseal)

Key holders each run this, entering their own share at the prompt so it never lands in shell history:

```bash
kubectl -n vault exec -it vault-0 -- vault operator unseal
```

## Verify

- `vault status` shows `Sealed: false`
- `ExternalSecretSyncFailing` and `CertificateNotReady` alerts clear (Alertmanager inhibits them while VaultSealed fires)

## Afterwards

If the seal was not caused by a planned restart, open an incident. Look at the audit log for `sys/seal` calls:
`{namespace="vault"} |= "sys/seal"`
