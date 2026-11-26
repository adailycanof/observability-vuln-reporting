# Runbook: VaultRootTokenUsed

**Alert:** a request authenticated with a root token. **Severity:** critical.
Root tokens should only exist during a recorded break-glass procedure (`vault operator generate-root`) and be revoked as soon as it ends.

## Respond

1. **Is there an approved break-glass change in progress?** Check the change calendar or incident channel.
   - Yes: confirm with the person running it, note the alert in the change record, and make sure the token is revoked when they finish.
   - No: continue as a security incident.
2. See what root did:
   ```logql
   {namespace="vault"} |= "\"type\":\"request\"" | json | auth_display_name="root"
     | line_format "{{.time}} {{.request_operation}} {{.request_path}} from {{.request_remote_address}}"
   ```
3. Revoke every root token:
   ```bash
   vault token revoke -self                     # if you hold it
   vault list auth/token/accessors              # find others; revoke by accessor
   ```
4. If root was used without authorisation, assume every secret it read is compromised: rotate those secrets (the request paths above), and review how the unseal/recovery keys were exposed.
