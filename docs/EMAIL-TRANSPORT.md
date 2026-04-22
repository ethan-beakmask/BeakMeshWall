# Email Transport -- Deployment Guide

Agent v0.4.0 introduces an email transport for environments where
direct HTTP connectivity to Central Server is not available
(e.g. network-isolated subnets, air-gapped environments).

## How It Works

```
Agent (Go)          Gmail              Central (Python)
  Collect       ->  SMTP send      ->  IMAP receive
  AES encrypt       encrypted .enc     AES decrypt
  base64 attach     attachment         write to PostgreSQL
```

- Agent collects module data on each `poll_interval` cycle
- Report JSON is encrypted with AES-256-GCM, attached as `.enc` file
- Sent via Gmail SMTP (App Password authentication)
- Central's `email_receiver.py` reads Gmail via IMAP, decrypts, writes to DB
- Same DB schema as HTTP transport -- no schema changes needed

## Encryption

- Algorithm: AES-256-GCM (authenticated encryption)
- Key: 32 bytes (64 hex characters), shared between agent and receiver
- Each message has a unique random 12-byte nonce
- Payload includes hostname, node token, timestamp, and full report data

## Limitations

- **One-way only**: agent reports state, cannot receive tasks from Central
- **Not real-time**: delivery depends on Gmail latency (typically seconds)
- **No task execution**: `block_ip`, `add_rule` etc. require HTTP transport

## Key Management

| Key / Credential | Per-host? | How to generate |
|------------------|-----------|-----------------|
| AES-256 key | Per environment (dev/prod) | `python3 -c "import os; print(os.urandom(32).hex())"` |
| Gmail App Password | Per Gmail account | Google Account > Security > 2-Step Verification > App passwords |
| Node token | Per host (auto) | Central Web UI or `-register` flag |

When deploying Central Server and agents in the same network (e.g. both
inside a corporate LAN), use the default HTTP transport instead -- no AES
key or Gmail credentials needed. Email transport is specifically for
cases where agents cannot reach Central over the network.

---

## Deployment Steps

### Step 1: Generate AES-256 Key (on Central server)

```bash
python3 -c "import os; print(os.urandom(32).hex())"
```

Save the output. Both agent and receiver need the same key.

### Step 2: Agent Config (on each monitored host)

Copy `bmw-agent` binary + `config.yaml` to the target host.

```yaml
central:
  token: "<from Step 3>"

agent:
  hostname: ""               # empty = auto-detect
  poll_interval: 300          # 5 min recommended for email

transport:
  type: email
  email:
    smtp_host: smtp.gmail.com
    smtp_port: 587
    username: beakmask2026@gmail.com
    app_password: xxxx xxxx xxxx xxxx
    to: beakmask2026@gmail.com
    encrypt_key: <64 hex chars from Step 1>

modules:
  firewall: false             # adjust per host
  nginx: false
  service: true
  sysinfo: true               # ISO 27001 account audit
```

### Step 3: Register Node (on Central Web UI)

Since email-mode agents cannot HTTP-register, manually create the node
in Central Web UI or DB:

- Set hostname, os_type, fw_driver
- Copy the generated token into agent config `central.token`

### Step 4: Compile Agent

```bash
cd agent/

# Linux:
go build -o bmw-agent ./cmd/bmw-agent/

# Windows (cross-compile):
GOOS=windows GOARCH=amd64 go build -o bmw-agent.exe ./cmd/bmw-agent/
```

### Step 5: Start Agent

```bash
./bmw-agent -config config.yaml
```

Verify Gmail receives `[BMW-REPORT]` emails.

### Step 6: Start Email Receiver (on Central server)

```bash
cd central/

# One-shot test:
venv/bin/python tools/email_receiver.py --once \
  --username beakmask2026@gmail.com \
  --app-password "xxxx xxxx xxxx xxxx" \
  --encrypt-key <64 hex chars from Step 1>

# Daemon mode (production):
venv/bin/python tools/email_receiver.py --daemon --interval 60 \
  --username beakmask2026@gmail.com \
  --app-password "xxxx xxxx xxxx xxxx" \
  --encrypt-key <64 hex chars from Step 1>
```

### Step 7: Verify

```sql
SELECT id, hostname, last_seen_at,
       config_json::json->'system_info'->'users'
FROM nodes WHERE id = <node_id>;
```

---

## Notes

- AES key: generate one per environment (dev/prod), not per host
- Gmail App Password: Google Account > Security > 2-Step Verification > App passwords
- Agent `poll_interval` 300s (5 min) is recommended for email mode
- Receiver uses IMAP UNFLAGGED filter; processed emails get Flagged
- Same sender/receiver Gmail account works (tested)
- Transport selection is config-only, no recompile needed to switch
- Email transport is one-way (report only), no task execution

## Files

| File | Description |
|------|-------------|
| `agent/internal/crypto/crypto.go` | AES-256-GCM encrypt/decrypt |
| `agent/internal/transport/email.go` | SMTP email sender |
| `agent/internal/config/config.go` | Transport config structure |
| `agent/config-email-example.yaml` | Agent config example |
| `central/tools/email_receiver.py` | IMAP receiver + decrypt + DB write |
| `central/tools/test_crypto_compat.py` | Go/Python crypto compatibility test |
