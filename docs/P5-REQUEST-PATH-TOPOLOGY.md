# P5: Request Path Topology

## Overview

Add a **Request Path Topology** view that shows how external requests
traverse each layer of the network stack on a managed node:

```
Firewall (nftables/iptables)  -->  Reverse Proxy (nginx)  -->  Application Service
```

The topology is built from configuration files (static analysis), not from
log correlation. The agent reads firewall rules, nginx server blocks, and
listening sockets, then reports them together. Central joins the three
layers by port number and renders a single table view.

## Goals

1. One table shows every externally reachable path on a node.
2. Compliance check: flag services that bypass the three-layer architecture.
3. Zero intrusion: read configs and sockets, never modify nginx or services.

## Non-Goals

- Log-based traffic analysis (future phase).
- Load-balancer / upstream pool visualization (future phase).
- Nginx configuration management -- this is observation only.

---

## Nginx Config Compliance Specification

### File Rules

- One server block per file.
- Files in `/etc/nginx/sites-enabled/` with `.conf` suffix.
- Symlink from `sites-available/`.

### Required BMW Metadata Tags

Every server block must begin with these comment tags before `listen`:

```nginx
server {
    # bmw:service_name = <display name>
    # bmw:project = <project directory name>
    # bmw:type = <production|development|tool>
    # bmw:backend = <127.0.0.1:port>

    listen <addr>:<port>;
    ...
}
```

### Location Rules

- `location = /` must `return 444` (exact match, root only).
- `location /` proxies all other paths to the backend.
- `proxy_pass` target must match `bmw:backend`.

### Prohibited

- `upstream` blocks (first version does not support load balancing).
- Multiple server blocks in one file.
- `0.0.0.0` bindings in applications or nginx listen directives.

### Non-Compliant Handling

Files without `bmw:` tags are reported as `non_compliant`. The agent
records the filename but does not attempt to parse them. Central shows
a warning banner for the node.

---

## Agent Architecture: Module System

### Current State

```
agent/internal/
  driver/        # Firewall-specific (nftables, iptables)
    driver.go    # Driver interface
    nftables/
  client/        # HTTP communication with Central
  config/        # YAML config loader
```

### Target State

```
agent/internal/
  module/                  # Unified module interface
    module.go              # Module interface definition
    firewall/              # Wraps existing driver
      firewall.go
    nginx/                 # NEW: nginx config collector
      nginx.go
    service/               # NEW: listening socket collector
      service.go
  driver/                  # Unchanged -- firewall drivers
    driver.go
    nftables/
  client/                  # Unchanged
  config/                  # Extended with modules section
```

### Module Interface

```go
// Module collects state from one subsystem on the node.
type Module interface {
    // Name returns the module identifier (e.g. "firewall", "nginx", "service").
    Name() string

    // Collect gathers current state and returns a JSON-serializable value.
    Collect() (interface{}, error)
}

// Executor is optionally implemented by modules that can execute tasks.
type Executor interface {
    // Execute runs a task and returns a result.
    Execute(action string, payload map[string]interface{}) (success bool, detail string)
}
```

Only the firewall module implements `Executor`. Nginx and service modules
are collect-only (observation, no modification).

### Config Extension

```yaml
central:
  url: http://192.168.0.16:5100
  token: <token>
agent:
  hostname: my-server
  poll_interval: 30
firewall:
  driver: nftables
  table: inet beakmeshwall
modules:
  firewall: true
  nginx: true
  service: true
nginx:
  config_path: /etc/nginx/sites-enabled   # default
```

---

## Collector Specifications

### Service Collector

Runs `ss -tlnp` and parses each LISTEN line.

Output structure:
```json
{
  "listeners": [
    {
      "bind": "127.0.0.1",
      "port": 8000,
      "process": "gunicorn",
      "pid": 1839
    }
  ]
}
```

### Nginx Collector

Reads `*.conf` from the configured nginx path. For each file:
1. Check for `bmw:` tags -- if absent, add to `non_compliant_files` and skip.
2. Parse tags, `listen`, `location`, `proxy_pass`, `return` directives.
3. Build structured output.

Output structure:
```json
{
  "config_path": "/etc/nginx/sites-enabled",
  "compliant": true,
  "servers": [
    {
      "file": "beakplatform.conf",
      "service_name": "BeakPlatform",
      "project": "BeakPlatform",
      "type": "production",
      "backend": "127.0.0.1:8000",
      "listen_addr": "192.168.0.16",
      "listen_port": 8000,
      "server_name": "_",
      "locations": [
        {"path": "= /", "action": "return 444"},
        {"path": "/", "action": "proxy_pass", "target": "127.0.0.1:8000"},
        {"path": "/static/", "action": "proxy_pass", "target": "127.0.0.1:8000"}
      ]
    }
  ],
  "non_compliant_files": ["legacy.conf"]
}
```

### Firewall Module (existing, wrapped)

Wraps the existing `driver.GetState()` call. Output unchanged.

---

## Report Payload Extension

The agent report payload expands from:

```json
{ "fw_state": {...}, "task_results": [...] }
```

To:

```json
{
  "fw_state": {...},
  "nginx_state": {...},
  "service_state": {...},
  "task_results": [...]
}
```

Central stores all state in `Node.config_json` as a merged object.
Backward compatible: agents without nginx/service modules simply omit
those keys.

---

## Central: Topology API

### Endpoint

```
GET /api/v1/topology/<node_id>
```

Requires login (session) or API key.

### Response

Joins three layers by port number:

```json
{
  "node_id": 1,
  "hostname": "ethan-vm",
  "paths": [
    {
      "external_port": 8000,
      "firewall": {
        "action": "accept",
        "rule_summary": "allow 192.168.0.0/24"
      },
      "nginx": {
        "service_name": "BeakPlatform",
        "project": "BeakPlatform",
        "type": "production",
        "listen": "192.168.0.16:8000",
        "server_name": "_",
        "locations": [
          {"path": "= /", "action": "return 444"},
          {"path": "/", "action": "proxy_pass", "target": "127.0.0.1:8000"}
        ]
      },
      "service": {
        "bind": "127.0.0.1",
        "port": 8000,
        "process": "gunicorn",
        "pid": 1839
      },
      "status": "ok"
    }
  ],
  "warnings": [
    {"type": "no_nginx", "port": 22, "detail": "sshd listens on 0.0.0.0:22 without nginx proxy"},
    {"type": "non_compliant", "files": ["legacy.conf"]}
  ]
}
```

### Status Logic

| Firewall | Nginx | Service (127.0.0.1) | Status |
|----------|-------|---------------------|--------|
| ACCEPT   | Yes   | Yes                 | `ok` (green) |
| ACCEPT   | Yes   | No (process down)   | `service_down` (red) |
| ACCEPT   | No    | Yes (0.0.0.0)       | `no_proxy` (red) |
| ACCEPT   | No    | Yes (127.0.0.1)     | `no_proxy` (yellow) |
| No rule  | Yes   | Yes                 | `no_firewall` (yellow) |
| --       | --    | --                  | Infrastructure services (SSH, SMB, PG) listed separately |

---

## Central: Topology UI

### Page Location

Sidebar: add **Topology** link between Nodes and Logout.

Route: `GET /topology/<node_id>`

### Table Design

Main table -- one row per external port path:

```
+--------+-----------+----------+-----------+----------+---------+--------+
| Status | Ext. Port | Firewall | Nginx     | Backend  | Process | Type   |
+--------+-----------+----------+-----------+----------+---------+--------+
| [ok]   | 8000      | ACCEPT   | port-base | :8000    | gunicorn| prod   |
| [ok]   | 80        | ACCEPT   | app.beak..| :8000    | gunicorn| prod   |
| [warn] | 22        | ACCEPT   | --        | direct   | sshd    | infra  |
+--------+-----------+----------+-----------+----------+---------+--------+
```

Click a row to expand location detail below it.

Non-compliant files shown as a warning alert at the top of the page.

---

## Future Considerations

### Dual-Agent Mutual Monitoring

Rather than a single monolithic agent, a future version could split into
two lean agents that monitor each other:

- **Agent A**: firewall + nginx modules
- **Agent B**: service + system modules

Benefits:
- Non-normal termination detection: each agent watches the other's process.
- Mutual restart on crash.
- Rolling upgrade: upgrade A while B keeps reporting, then vice versa.

This is not required for P5 but the module interface is designed to support
this split without code changes -- each agent simply enables different modules.

### Log-Based Traffic Overlay

Once the static topology table is in place, a future phase can add:
- nginx access log parsing (request count, status codes per location).
- nftables counter data (packets/bytes per rule, already collected).
- Overlay onto the topology table as additional columns.

---

## Development Sequence

| Step | Task | Scope |
|------|------|-------|
| 1 | Agent module interface + firewall wrapper | agent refactor |
| 2a | Service Collector | agent new module |
| 2b | Nginx Collector | agent new module (parallel with 2a) |
| 3 | Expand report payload + Central receiver | agent + central |
| 4 | Topology API endpoint | central |
| 5 | Topology UI page | central |
| 6 | Update ARCHITECTURE.md | docs |
