# Runbook: CertificateExpiringSoon / CertificateNotReady

cert-manager normally renews well before expiry (for example, a 24h certificate renews 8h early). If a certificate is within 7 days of expiry, or not Ready for 15 minutes, renewal is failing.

## Diagnose

```bash
kubectl -n <ns> describe certificate <name>                  # Ready condition + reason
kubectl -n <ns> get certificaterequest --sort-by=.metadata.creationTimestamp | tail -3
kubectl -n <ns> describe certificaterequest <latest>          # the actual error from the issuer
kubectl -n cert-manager logs deploy/cert-manager --since=1h | grep <name>
```

| Error | Cause | Fix |
|---|---|---|
| `permission denied` from Vault | Vault role/policy changed, or the Issuer's ServiceAccount token audience no longer matches the role | Compare `vault read auth/kubernetes/role/<role>` with the Issuer; fix through Git |
| `role ... not allowed to issue for ...` | A DNS name in the Certificate is outside the PKI role's `allowed_domains` | Fix the Certificate, or widen the role after review |
| `Vault is sealed` / connection refused | Vault down | [vault-sealed.md](vault-sealed.md) |
| ACME `rate limited` | Too many failed issuances against Let's Encrypt | Wait; fix the root cause first; use staging for testing |

## Force a retry after the fix

```bash
cmctl renew -n <ns> <name>
```

## Verify

`kubectl -n <ns> get certificate <name>` shows Ready=True and a new `notAfter`.
