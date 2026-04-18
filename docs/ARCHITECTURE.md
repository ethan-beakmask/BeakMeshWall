# BeakMeshWall -- Multi-Host Firewall Management Center

獨立運行的多主機防火牆集中管理平台，不依賴外部認證系統。

## 架構總覽

```
┌──────────────────────────────────────────────────┐
│                 Central Server                    │
│          Flask + Jinja2 / Alpine.js / Bootstrap   │
│                                                   │
│  ┌──────────┐  ┌───────────┐  ┌──────────────┐  │
│  │ Local    │  │ Rule      │  │ Threat Feed  │  │
│  │ Auth     │  │ Engine    │  │ API          │  │
│  └──────────┘  └───────────┘  └──────────────┘  │
│  ┌──────────────────────────────────────────┐    │
│  │    Unified Firewall Abstract Layer       │    │
│  └──────────────────────────────────────────┘    │
└────────────┬────────────────┬────────────────────┘
             │  Pull (HTTPS + mTLS)
    ┌────────┴────┐   ┌──────┴──────┐
    │ Agent (Go)  │   │ Agent (Go)  │
    │ nftables    │   │ iptables    │
    │ Driver      │   │ Driver      │
    └─────────────┘   └─────────────┘
```

## 三層架構

### 1. Central Server (Python/Flask)

管理介面與 API 伺服器。

- **Local Auth**: 內建帳號密碼認證，獨立運行不依賴外部 SSO
- **API Key Auth**: System-to-System 信任機制，供外部系統呼叫
- **Node Inventory**: 受管節點清冊，即時連線狀態
- **Rule Engine**: 規則 CRUD、策略範本、規則推送與同步
- **Threat Feed API**: 接收外部系統的 IP 阻擋請求
- **Audit Log**: 所有規則變更完整記錄

Web UI: Flask + Jinja2 + Alpine.js + Bootstrap

### 2. Unified Firewall Abstract Layer

標準化指令介面，Driver Plugin SPI:

| 指令 | 說明 |
|------|------|
| `block_ip` | 阻擋指定 IP |
| `unblock_ip` | 解除 IP 阻擋 |
| `add_rule` | 新增防火牆規則 |
| `delete_rule` | 刪除防火牆規則 |
| `sync_rules` | 同步規則（預期 vs 實際） |
| `diff_rules` | 比對規則差異 |
| `get_counters` | 取得規則命中計數 |
| `list_tables` | 列出所有 table（含 external） |

### 3. Agent + Driver (Go)

部署在受管節點的執行元件。

- **通訊方式**: Pull-based，Agent 定期向 Central 拉取指令
- **預設間隔**: 30 秒（可設定）
- **認證**: mTLS 雙向憑證認證
- **Driver**: 依節點 OS 自動選擇

| Driver | 優先級 | 狀態 |
|--------|--------|------|
| nftables | 1 | 優先開發 |
| iptables | 2 | 規劃中 |
| pf | 3 | 規劃中 |

## 核心設計決策

### nftables Table 所有權模型

Agent 與 Docker/LXC 等子系統共存策略:

| Table | 管理者 | BeakMeshWall 權限 | 備註 |
|-------|--------|---------------|------|
| `inet beakmeshwall` (pri -150) | BeakMeshWall | 完全管理，唯一會 flush 的 table | priority -150 先於 Docker/LXC 評估 |
| Docker tables | Docker | 唯讀觀察，標記 `external:docker` | ip nat/filter/raw, ip6 nat/filter |
| LXC tables | LXC | 唯讀觀察，標記 `external:lxc` | inet lxc, ip lxc |

**原則**: 各子系統管理自己的 nft table，BeakMeshWall 不碰。Agent 回報所有 table 但區分 managed/external，Central UI 對 external table 唯讀顯示禁止編輯。

### 認證模型

```
              ┌─────────────────┐
  瀏覽器 ────→│ Local Auth      │  帳號密碼登入（預設）
              │ (session-based) │
              └─────────────────┘

              ┌─────────────────┐
  外部系統 ──→│ API Key Auth    │  System-to-System 信任
  (如         │ (header-based)  │  X-API-Key: xxx
  BeakPlatform)└─────────────────┘

              ┌─────────────────┐
  未來可選 ──→│ OIDC Provider   │  SSO 對接（非必要）
              └─────────────────┘
```

### Threat Feed API

接收外部系統的 IP 阻擋/解除請求:

```
POST   /api/v1/threat/block     建立 IP 阻擋
DELETE /api/v1/threat/block/{ip} 解除 IP 阻擋
GET    /api/v1/threat/block      查詢阻擋清單
```

Request body (POST):
```json
{
  "source": "beakplatform",
  "ip": "203.0.113.50",
  "reason": "brute_force",
  "detail": "login_fail_10_in_5m",
  "duration": 3600
}
```

- 認證方式: API Key (header `X-API-Key`)
- API Key 可綁定權限範圍（僅 threat 操作 / 完整管理）
- 阻擋規則透過下次 Agent pull 生效
- 所有操作記入 audit log

### 與 BeakPlatform 的整合方式

BeakMeshWall 不依賴 BeakPlatform，但可選擇性整合:

| 整合點 | 方式 | 說明 |
|--------|------|------|
| 登入失敗 IP 阻擋 | BeakPlatform 呼叫 Threat Feed API | BeakPlatform 自行判斷閾值後送出 |
| 管理員免登入操作 | API Key + 權限綁定 | BeakPlatform 後端持有 API Key |
| 使用者 SSO | OIDC (未來) | 非必要，不影響核心功能 |

**關鍵原則**: 判斷邏輯在來源系統（誰產生事件誰判斷），BeakMeshWall 只負責執行防火牆操作。

## Agent Pull 流程

```
Agent                          Central
  │                               │
  ├── GET /api/v1/agent/poll ────→│  mTLS 認證
  │                               │  回傳: pending rules, block list, config
  │←── 200 { tasks: [...] } ─────┤
  │                               │
  │  執行規則變更                   │
  │  回報執行結果                   │
  │                               │
  ├── POST /api/v1/agent/report ─→│
  │←── 200 ──────────────────────┤
  │                               │
  │  (等待 30 秒)                  │
  │                               │
  └── GET /api/v1/agent/poll ────→│  下一輪
```

## Agent Module Architecture

The agent uses a modular plugin architecture. Each module implements
`Collect()` to gather subsystem state and optionally `Execute()` to
run tasks.

```
Agent
├── module/                  Unified module interface
│   ├── module.go            Module + Executor interfaces
│   ├── firewall/            Wraps firewall drivers (nftables/iptables)
│   ├── nginx/               Reads BMW-compliant nginx configs
│   └── service/             Discovers listening sockets (ss -tlnp)
├── driver/                  Firewall driver implementations
│   ├── driver.go            Driver interface
│   └── nftables/
├── client/                  HTTP communication with Central
└── config/                  YAML config with module toggles
```

Modules are enabled/disabled via config:
```yaml
modules:
  firewall: true
  nginx: true
  service: true
```

All module states are reported in a single `POST /api/v1/agent/report`:
- `fw_state` -- firewall rules (managed + external tables)
- `nginx_state` -- BMW-compliant server blocks + non-compliant warnings
- `service_state` -- listening sockets with process info

## 開發階段

| 階段 | 內容 | 交付物 |
|------|------|--------|
| P0 | Repo 骨架、文件、LICENSE | GitHub 可公開的專案結構 |
| P1 | Central API + Local Auth + Agent 註冊/心跳 + mTLS | 節點上下線可見 |
| P2 | nftables Driver + 規則 CRUD + Threat Feed API | 核心功能可用 |
| P3 | Counters 回報 + External Table 觀察 + Audit Log | 運維完整 |
| P4 | iptables/pf Driver + OIDC 可選對接 | 擴展完成 |
| P5 | Request Path Topology | 三層路徑拓撲觀察 |

## 開發環境

- Central: 192.168.0.16 (家用主機)
- 測試節點: LXC 容器 (lxcbr0 10.0.3.0/24)
- 家用主機本身也是受管節點 (self-manage)
