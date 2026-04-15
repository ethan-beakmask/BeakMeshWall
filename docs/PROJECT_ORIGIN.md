# BeakMeshWall -- 專案緣由與定位

## 起源

BeakPlatform 是多租戶權限管理平台，其登入頁面遭受帳號密碼猜測攻擊（暴力破解）。
防禦策略分為兩層：

- **帳號鎖定**：由 BeakPlatform 自身負責（應用層防禦）
- **IP 阻擋**：交給 OS 防火牆執行（網路層防禦）

IP 阻擋需要一個集中管理各主機防火牆的系統，BeakMeshWall 因此誕生。

## 定位

企業級多主機防火牆集中管理平台。
Agent 安裝在各受管主機上，由 Central Server 統一管理。

## Agent 功能範圍

Agent 安裝在 OS 上，規劃的功能模組：

1. **防火牆控制**（目前優先開發）
2. 系統排程控制（未來）
3. 主機資產收集與變更管理，包含帳號（未來）

## 防火牆管理項目

### 基本功能
- 規則的遠端增刪改
- 組態異動告警（Central Dashboard + Email + Telegram alert）
- 全企業規則統一調整（批次推送）

### 重點功能
- **黑白名單管制系統**：集中管理全企業的 IP 黑白名單
- **動態黑名單 EDL (External Dynamic List)**：
  - 結合 BeakPlatform 登入失敗資料
  - 由 BeakPlatform 編輯 EDL 內容
  - 生效機制：BeakPlatform 呼叫 Central API 觸發即時更新，
    Agent 透過 pull 機制取得變更並套用

## 目標 OS 與防火牆

| OS | 防火牆 | 優先級 |
|----|--------|--------|
| Ubuntu (Linux) | nftables | 1 -- 優先開發 |
| Windows | Windows Firewall | 2 |
| macOS / BSD | pf | 3 |

## 架構概要

```
BeakPlatform                  BeakMeshWall Central            Agent (各主機)
  |                                |                              |
  | 登入失敗 -> 編輯 EDL          |                              |
  | POST /api/threat/block -----> |  存入 DB                     |
  |                                |                              |
  |                                | <-- GET /poll (定期) ------- |
  |                                |  回傳: pending tasks         |
  |                                |                              |
  |                                | <-- POST /report ---------- |
  |                                |  Agent 回報執行結果           |
  |                                |                              |
  |                                |  異動 -> alert (mail/tg)    |
```

## 設計原則

- Agent pull-based 通訊，受管節點不需開 inbound port
- 判斷邏輯歸來源系統，BeakMeshWall 只負責執行防火牆操作
- 獨立運行，不依賴 BeakPlatform 或任何外部認證系統
- 計畫開源到 GitHub，程式碼不含硬編碼的認證資訊
