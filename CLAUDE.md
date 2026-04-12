# BeakMeshWall -- 專案開發規範

## 專案定位
獨立的多主機防火牆集中管理平台。不依賴 BeakPlatform 或任何外部認證系統即可運行。

## 技術棧

| 元件 | 技術 |
|------|------|
| Central Server | Python 3.10+ / Flask / Jinja2 / Alpine.js / Bootstrap |
| Agent | Go 1.21+ |
| Database | PostgreSQL 15+ |
| 通訊 | Pull-based (Agent -> Central), mTLS |

## 架構原則
- BeakMeshWall 獨立運行，Local Auth 為預設認證方式
- API Key 機制供外部系統 (System-to-System) 呼叫
- Agent pull-based 通訊，不需在受管節點開 inbound port
- nftables table 所有權: BeakMeshWall 只管 `inet beakmeshwall` table (priority -150)
- External tables (Docker/LXC) 唯讀觀察，絕不修改
- 判斷邏輯歸來源系統，BeakMeshWall 只負責執行防火牆操作

## 目錄結構
- `central/` -- Flask 應用程式 (Central Server)
- `agent/` -- Go Agent (部署於受管節點)
- `docs/` -- 架構文件、API 文件
- `deploy/` -- 部署腳本與設定範例

## 開發階段
- **P0**: Repo 骨架、文件 (done)
- **P1**: Central API + Local Auth + Agent 註冊/心跳 + mTLS (done)
- **P2**: nftables Driver + 規則 CRUD + Threat Feed API (done)
- **P3**: Counters 回報 + External Table 觀察 + Audit Log (done)
- **P4**: iptables/pf Driver + OIDC 可選對接 (done)

## 開發環境
- Central: 192.168.0.16
- 測試節點: LXC 容器 (lxcbr0 10.0.3.0/24)
- Web UI 一律使用 LAN IP，不用 localhost

## 注意事項
- 此專案計畫放上 GitHub，程式碼中不得有硬編碼的密碼、Token、IP
- 所有認證資訊透過組態檔或環境變數載入
- README.md 以英文撰寫（面向 GitHub 國際社群）
- 程式碼註解以英文撰寫
- docs/ 下的設計文件可用中文
