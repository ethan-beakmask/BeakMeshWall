# BeakMeshWall

Multi-host firewall management center. Manage firewall rules across multiple hosts from a single web interface.

BeakMeshWall deploys lightweight Go agents on managed nodes that pull firewall rules from a central Flask server. Rules are abstracted through a unified driver layer supporting nftables, iptables, and pf.

## Features

- **Node Management** -- Register and monitor managed hosts with real-time connection status
- **Rule Management** -- Create, edit, and delete firewall rules through a web UI
- **Policy Templates** -- Reusable rule sets for quick deployment across multiple nodes
- **Rule Sync & Diff** -- Compare desired vs. actual firewall state, one-click sync
- **Threat Feed API** -- REST API for external systems to submit IP block requests
- **Audit Log** -- Complete history of all rule changes
- **External Table View** -- Read-only display of Docker/LXC firewall tables

## Architecture

```
Central Server (Flask)        Agent (Go) on each managed node
┌──────────────────────┐      ┌───────────────────────┐
│ Web UI + REST API    │      │ Pull tasks from       │
│ Rule Engine          │←────→│ Central every 30s     │
│ Threat Feed API      │ mTLS │ Execute via Driver    │
│ Local Auth / API Key │      │ Report results back   │
└──────────────────────┘      └───────────────────────┘
                                │
                              ┌─┴──────────────────┐
                              │ Driver Plugin       │
                              │ nftables / iptables │
                              └────────────────────┘
```

### Key Design Decisions

- **Standalone**: No external authentication dependency. Built-in local auth + API key for system-to-system trust
- **Pull-based**: Agents initiate outbound connections -- no inbound ports required on managed nodes
- **Table ownership**: BeakMeshWall only manages `inet beakmeshwall` table (priority -150). Docker/LXC tables are observed read-only
- **Separation of concerns**: External systems decide *when* to block; BeakMeshWall executes *how* to block

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full design details.

## Project Structure

```
BeakMeshWall/
├── central/            # Central Server (Python/Flask)
│   └── app/
│       ├── auth/       # Authentication (local auth, API key)
│       ├── api/        # REST API endpoints
│       ├── models/     # Database models (PostgreSQL)
│       ├── services/   # Business logic
│       ├── templates/  # Jinja2 templates
│       └── static/     # CSS, JS (Bootstrap, Alpine.js)
├── agent/              # Agent (Go)
│   ├── cmd/            # Entry point
│   └── internal/
│       ├── client/     # Central API client
│       ├── config/     # Agent configuration
│       └── driver/     # Firewall driver interface
│           └── nftables/
├── docs/               # Documentation
└── deploy/             # Deployment scripts and configs
```

## Prerequisites

- Python 3.10+
- Go 1.21+
- PostgreSQL 15+
- nftables (on managed nodes)

## Quick Start

> Under development. See [Roadmap](#roadmap) for current status.

### Central Server

```bash
cd central
pip install -r requirements.txt
python run.py --host 0.0.0.0 --port 5000
```

### Agent

```bash
cd agent
go build -o beakmeshwall-agent ./cmd/beakmeshwall-agent/
sudo ./beakmeshwall-agent --config /etc/beakmeshwall/agent.yaml
```

## Threat Feed API

External systems can submit IP block/unblock requests:

```bash
# Block an IP
curl -X POST https://central:5000/api/v1/threat/block \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.50","reason":"brute_force","duration":3600}'

# Unblock
curl -X DELETE https://central:5000/api/v1/threat/block/203.0.113.50 \
  -H "X-API-Key: YOUR_KEY"

# List blocked IPs
curl https://central:5000/api/v1/threat/block \
  -H "X-API-Key: YOUR_KEY"
```

## Roadmap

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Project skeleton, documentation | Current |
| P1 | Central API + Agent registration/heartbeat + mTLS | Planned |
| P2 | nftables driver + rule CRUD + Threat Feed API | Planned |
| P3 | Counters, external table observation, audit log | Planned |
| P4 | iptables/pf drivers, optional OIDC integration | Planned |

## License

[Apache License 2.0](LICENSE)
