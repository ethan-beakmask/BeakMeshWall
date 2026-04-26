# Nginx Management (P6 subsystem)

> Normative supplement to `docs/ROADMAP-CONFIG-MANAGEMENT.md`. All conditions
> here are binding for any agent or central code touching nginx config.

---

## 1. Scope

BeakMeshWall manages a small, file-bounded slice of nginx configuration. The
goal is identical to firewall management: **a single canonical source of
truth** that the agent can re-emit deterministically and a drift detector
can verify.

Nginx is treated as an **independent subsystem**: it has its own schema,
its own driver-equivalent module, and its own entry in the per-node
`drift_policies` map (`nginx`).

---

## 2. Managed area boundary

| Path | Owner |
|------|-------|
| `/etc/nginx/conf.d/beakmeshwall/*.conf` | BeakMeshWall (managed) |
| `/etc/nginx/sites-available/*` | User |
| `/etc/nginx/sites-enabled/*` | User |
| `/etc/nginx/nginx.conf` and other top-level files | User |

The agent **never** writes outside `/etc/nginx/conf.d/beakmeshwall/`.

### 2.1 Activation prerequisite (deployment-time contract)

For any of BMW's nginx output to take effect, the user's nginx config must
include the BMW directory:

```nginx
server {
    # ... user's existing directives ...
    include /etc/nginx/conf.d/beakmeshwall/*.conf;
}
```

BMW does not insert this line. It is a one-time deployment step performed
by the operator. Without this `include`, BMW's rules are written to disk
but ignored by nginx.

### 2.2 Per-node enablement

The `nodes.nginx_managed` flag (boolean, default `false`) controls whether
central pushes nginx tasks to a node and runs nginx drift detection.
Toggle via the API or UI.

---

## 3. Stage α schema (current)

A single rule type: per-IP access control. One JSON object per rule,
validated by `central/app/schemas/nginx_rule.json`.

| Field | Required | Type | Allowed values | Notes |
|-------|----------|------|---------------|-------|
| `stage` | no | string | `"alpha"` | Future stages will add their own value |
| `action` | yes | string | `allow` \| `deny` | Maps directly to nginx `allow` / `deny` |
| `src` | yes | string | IPv4 / CIDR / `all` | Same regex as firewall `src` plus the literal `all` |
| `comment` | no | string | ≤ 255 chars | Embedded in BMW-ID line |

### 3.1 Fingerprint

`BMW-ID` for an nginx rule is `sha256({A:action, S:src})[:8]`. Comment is
excluded so re-comments do not change the id. Python and Go must produce
byte-identical fingerprints (same field order, same separators).

---

## 4. File layout

### 4.1 access.conf (Stage α)

Single file: `/etc/nginx/conf.d/beakmeshwall/access.conf`.

Generated deterministically by central. Format:

```nginx
# MANAGED BY BeakMeshWall - DO NOT EDIT MANUALLY / 由 BeakMeshWall 管理，請勿手動編輯
# Source: BeakMeshWall central, see docs/NGINX-MANAGEMENT.md

# BMW-ID=4a39e43d: block scanner farm
deny 1.2.3.4;

# BMW-ID=8be0a712: allow internal
allow 10.0.0.0/8;

# BMW-ID=f0c9d83e:
allow all;
```

Ordering rule (for determinism):
1. `deny` rules first, sorted lexicographically by `src`.
2. `allow` rules second, sorted lexicographically by `src`.
3. `allow all` (if present) last.

### 4.2 Future stages

| Stage | File added |
|-------|------------|
| β | `/etc/nginx/conf.d/beakmeshwall/ratelimit.conf` |
| γ | `/etc/nginx/conf.d/beakmeshwall/path_acl.conf` |

Each file has its own header, its own BMW-ID set, and its own drift
detection scope.

---

## 5. Apply / remove flow

```
Operator                  Central                   Agent
   |                         |                         |
   |--- POST /nginx/rules/apply --->                   |
   |     {node_id, rule}     |                         |
   |                         | validate(schema)        |
   |                         | upsert managed_rule     |
   |                         | regen full access.conf  |
   |                         |   from active rules     |
   |                         | enqueue task            |
   |                         |   action=apply_nginx_access
   |                         |   payload={path, content}
   |                         |                         |
   |                         |       <--- poll --------|
   |                         |       --- task -------->|
   |                         |                         | mkdir parent dir
   |                         |                         | write tmp file
   |                         |                         | nginx -t -c tmp
   |                         |                         |   reject + revert if fail
   |                         |                         | mv tmp -> live
   |                         |                         | nginx -s reload
   |                         |       <--- report ------|
   |                         |       (success + actual_ids)
   |                         |                         |
   |                         | sync managed_rules      |
   |                         | drift detect            |
```

Remove follows the same path: central marks the rule removed, regenerates
the full file, and pushes it.

### 5.1 nginx -t pre-flight

The agent **must** run `nginx -t` (or equivalent) on the new file before
overwriting the live one. If the test fails:

1. Do not touch the live file.
2. Do not reload nginx.
3. Report task failure with the test output.

This prevents BMW from breaking the user's nginx with a bad rule.

### 5.2 Backup

Before overwriting, the agent copies the previous content to
`$BMW_DRIFT_BACKUP_DIR/nginx-access-<UTC-timestamp>.conf` so recovery is
possible. Same backup discipline as firewall reconcile.

---

## 6. Drift detection

### 6.1 Agent side

Agent's nginx `Collect()` returns:

```json
{
  "managed_path": "/etc/nginx/conf.d/beakmeshwall",
  "files": {
    "access.conf": {
      "exists": true,
      "managed_ids": ["4a39e43d", "8be0a712", "f0c9d83e"],
      "content_hash": "sha256:..."
    }
  }
}
```

`managed_ids` is computed by **re-fingerprinting the parsed entries**, not
by reading the `BMW-ID=` comments. This catches the case where an operator
edits a rule but leaves the comment intact.

### 6.2 Central side

Central runs `detect_and_handle(node, "nginx", actual_ids)` with the union
of `managed_ids` across all BMW nginx files. The same DriftEvent / policy
machinery as firewall (per-node-per-subsystem policy, notification,
overwrite reconcile).

---

## 7. Non-goals (intentionally out of scope)

- Editing user `nginx.conf` or any user-authored site config.
- Auto-injecting the `include` line. Operators must add it themselves.
- TLS certificate management.
- Upstream / load balancer configuration.
- Stages β and γ until α is stable in production.
