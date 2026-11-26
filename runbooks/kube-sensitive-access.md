# Runbook: KubeSecretReadByHuman / KubeExecIntoPod / KubeRBACChangedByHuman

These fire on Kubernetes API audit events made by a **human** (any user not matching `system:*`).
In a GitOps cluster people do not need to read Secrets, exec into pods, or change RBAC by hand. When it happens, it should be explainable.

## Respond

1. Identify who, what and when (Grafana → Security audit, or):
   ```logql
   {job="kubernetes-audit"} | json | user_username="<user>"
     | line_format "{{.requestReceivedTimestamp}} {{.verb}} {{.objectRef_resource}}/{{.objectRef_name}} -n {{.objectRef_namespace}} from {{.sourceIPs}}"
   ```
2. Ask the user. Legitimate reasons: an active incident (should be in the incident channel) or an approved break-glass.
3. Unexplained:
   - **Secret read**: rotate the secrets that were read (rotate in Vault; External Secrets syncs within a minute).
   - **Exec**: check what was run; consider the pod compromised, replace it (`kubectl rollout restart`).
   - **RBAC change**: Argo CD self-heal reverts drift, but check what the binding allowed while it existed.
   - Suspend the identity at the IdP and start the incident process.

## Reduce the noise properly

Do not just raise thresholds. Remove the standing permission instead (no `get secrets` in human roles) and give people a just-in-time elevation path that is logged.
