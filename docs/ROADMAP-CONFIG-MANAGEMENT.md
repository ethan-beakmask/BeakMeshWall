# Configuration Management Roadmap

> 本文件為**規範性文件**，定義 BeakMeshWall 對受管子系統（防火牆、nginx 等）組態的接管規則與推進順序。
> 後續所有 Claude 對話必須依循本文件條款。違反條款的指令必須拒絕，除非用戶明確要求先更新本文件。

---

## 1. 問題定義與設計前提

### 1.1 為什麼需要統一語法
BeakMeshWall 為傳統（非 AI）程式，必須以固定格式解析與寫入組態檔才能保證運作正確。Linux 網路系統（防火牆、nginx）原生語法自由度高，相同目的可有多種寫法，導致：

- 解析複雜度高、誤判風險高
- 用戶與系統交叉編輯時無法協調
- 漂移偵測難以可靠進行

故本專案**必須**選定統一格式，介入後接管組態檔的所屬部分。

### 1.2 用戶層級決策
本專案採用 **L2 層級**（nftables 子集，含命名 set、ct state、限速、log）。

- L2 涵蓋約 90% 常見企業需求
- L2 schema 自然涵蓋 L1 用例（基本 5-tuple），不另開 schema
- L3（完整 nft 語法）不採用，避免 BMW 退化為 nft 文字編輯器

---

## 2. 核心原則（四面向契約）

### 2.1 管轄邊界
每個受管子系統**必須**明確區分「BMW 管轄區」與「用戶自由區」。

| 子系統 | 管轄區 | 用戶自由區 |
|--------|--------|-----------|
| nftables | `inet beakmeshwall` table（priority -150） | 其他所有 table（含 Docker、LXC） |
| iptables | BMW 自建 chain（命名前綴 `BMW-`） | INPUT/FORWARD/OUTPUT 內非 BMW chain 的規則 |
| Windows Firewall | rule 名稱前綴 `BMW-` 者 | 其他所有 rule |
| nginx | `/etc/nginx/conf.d/beakmeshwall/*.conf`（BMW 專屬目錄） | `sites-available` / `sites-enabled` 等用戶撰寫區 |

**用戶自由區絕對不可修改**（不可妥協項，見 §7）。

### 2.2 格式統一
- 規則由 Central 以**單一規範格式**（JSON schema 描述）下發給 Agent
- Agent 將 schema 翻譯為各家 driver 的原生語法執行
- 翻譯結果**必須具確定性**：同一份 schema 永遠產出相同的原生語法字串（利於漂移偵測）

### 2.3 接管後互斥（社會性強制）
- 用戶通常持有 root 權限，**無法以檔案權限阻擋編輯**
- 強制方式：管轄區檔頭/註解**必須**含警示字串

警示字串有兩個版本，依介質長度限制擇一：

| 版本 | 字串 | 用於 |
|------|------|------|
| 完整 | `MANAGED BY BeakMeshWall - DO NOT EDIT MANUALLY / 由 BeakMeshWall 管理，請勿手動編輯` | 無長度限制處：nginx 檔案 header、Windows Firewall rule 的 Description 欄、文件 |
| 短 | `BMW-DO-NOT-EDIT` | 有長度限制處：nftables 規則 comment（hard cap 128 byte）、iptables 規則 `--comment`（256 byte） |

短版必須與 BMW-ID 並排（`BMW-DO-NOT-EDIT :: BMW-ID=<fp> :: <user>`），讓人類掃過時仍能識別這條規則屬於 BMW；完整警示則在文件層補齊語意。

- 若用戶仍編輯，由漂移偵測機制（§2.4）處理

### 2.4 漂移處理（可配置）
系統**必須**提供「漂移處理策略開關」，每個受管子系統獨立設定。

| 策略 | 行為 |
|------|------|
| `detect-only` | 偵測到漂移僅記錄，不通知、不覆寫 |
| `notify`（預設） | 偵測到漂移寄送通知，不覆寫 |
| `overwrite` | 偵測到漂移寄送通知，自動以期望狀態覆寫，**並備份原檔** |

- 漂移備份路徑：`/opt/tmp/beakmeshwall-drift-backup/<子系統>-<節點>-<時戳>.bak`
- 全域預設值可被節點層級覆蓋
- 通知通道：BMW 既有 email transport（見 `docs/EMAIL-TRANSPORT.md`）

---

## 3. 防火牆規則 Schema

### 3.1 階段劃分

| 階段 | 欄位範圍 | 累加說明 |
|------|---------|---------|
| **A** | action, direction, proto, src, dst, sport, dport, comment | 基本 5-tuple，等價 L1 |
| **B** | + state（new/established/related）, log（bool + level） | 在 A 之上累加 |
| **C** | + rate_limit（count/period/burst）, src_set / dst_set（命名 set） | 在 B 之上累加 |

### 3.2 Schema 設計約束
- Schema **必須**用 JSON Schema 撰寫，存於 `central/app/schemas/firewall_rule.json`
- 欄位**必須**前向相容：新階段加欄位時，舊階段規則無需遷移
- 每個欄位**必須**標註 `supported_by: [...]`（capability flag），列出支援該欄位的 driver
- Central 在規則建立/編輯時**必須**驗證：規則使用的欄位被目標節點的 driver 支援；不支援則拒絕，回傳明確錯誤

### 3.3 Driver 支援矩陣（強制）

| Driver | 階段 A | 階段 B | 階段 C |
|--------|:------:|:------:|:------:|
| nftables | 必須支援 | 必須支援 | 必須支援 |
| iptables | 必須支援 | 必須支援 | 必須支援（需 ipset） |
| Windows Firewall | 必須支援 | **不支援，凍結** | **不支援，凍結** |

Windows Firewall driver **永遠停留在階段 A**，B/C 不擴充（原因：無原生限速、無 ipset 對應、stateful 語意差異大）。

---

## 4. 接管控制面（階段 D）

跨子系統通用框架，**必須**先於 nginx 納管之前完成。

### 4.1 管轄標記
- 每個 BMW 寫入的檔案/規則段必須帶警示字串（見 §2.3）
- 並帶機器可讀標籤：
  - nftables：`comment "BMW-managed"` 屬性
  - iptables：chain 名前綴 `BMW-`
  - Windows Firewall：rule 名前綴 `BMW-`
  - nginx：檔名位於 `/etc/nginx/conf.d/beakmeshwall/`

### 4.2 漂移偵測
- 由 Agent 排程計算管轄區實際狀態的指紋（hash）
- 排程週期**必須**可由用戶於節點層級設定
  - 預設值：5 分鐘
  - 允許範圍：1 ~ 60 分鐘（防止過密造成負載、過鬆造成偵測延遲）
- Agent 回報指紋給 Central
- Central 與期望狀態比對，不一致即為漂移

### 4.3 漂移處理開關
- 顆粒度：**每節點 + 每子系統獨立設定**
- 全域預設值可被節點層級覆蓋
- 設定值：`detect-only` / `notify` / `overwrite`（見 §2.4）

### 4.4 變更通知
通知內容**必須**包含：

- 節點識別（hostname / agent_id）
- 子系統名稱
- 漂移摘要（diff，期望 vs 實際）
- 已執行動作（僅記錄 / 已通知 / 已覆寫並備份）
- 備份路徑（若有覆寫）

---

## 5. 子系統適用範圍

### 5.1 防火牆
- Driver：nftables、iptables、Windows Firewall
- 共用 §3 schema
- 各家階段支援度見 §3.3

### 5.2 nginx
- **獨立 schema**，**禁止**與防火牆 schema 混用
- 管轄區：`/etc/nginx/conf.d/beakmeshwall/*.conf`
- 用戶 `sites-available` / `sites-enabled` 不動
- 部署前提：用戶的 server / location 區塊必須含 `include /etc/nginx/conf.d/beakmeshwall/*.conf;`，否則 BMW 寫入無效
- 節點啟用方式：`nodes.nginx_managed` 旗標控制（預設 false，由 UI/API 開啟）
- 細節於 `docs/NGINX-MANAGEMENT.md`

#### 5.2.1 nginx 階段路線
階段內的範圍由小到大；下一階段必須先完成上一階段。

| 階段 | 範圍 | 對應 nginx 機制 | 狀態 |
|------|------|----------------|------|
| **α** | IP allow / deny list | nginx access module（`allow` / `deny` 指令） | 規劃中（先做） |
| **β** | α + rate limit zone | `limit_req_zone` + `limit_req` | 待排 |
| **γ** | α + β + IP-based 路由白名單（特定 path 限 IP） | 條件式 `if` 或 `map` | 待排 |

α/β/γ 的詳細欄位、檔案布局與漂移處理規則以 `docs/NGINX-MANAGEMENT.md` 為準。

---

## 6. 推進順序（強制）

```
[現在點]
   │
   ├──── 階段 A：防火牆 schema 骨幹 + 三家 driver A 級翻譯
   │       │
   │       └ 並行
   │
   └──── 階段 D：接管控制面（管轄標記、漂移偵測、處理開關、通知）
              │
              ▼
         nginx 納管（套用 D 框架，獨立 schema）
              │
              ▼
         階段 B：防火牆 stateful + log（nftables/iptables 擴充，Windows 不動）
              │
              ▼
         階段 C：防火牆 rate limit + named set（nftables/iptables 擴充，Windows 不動）
```

**未經本文件更新，不得**：

- 跳階段（例如先做 B 再回頭做 A）
- 合併階段
- 在 D 落地前納管 nginx
- 擴充 Windows Firewall 至 B 或 C

---

## 7. 不可妥協項

下列條款為強制性，違反即視為錯誤實作：

1. **用戶自由區永不修改**（防火牆既有 chain/table、nginx 既有 site config 等）
2. **規則 schema 每個欄位必須標 capability flag**
3. **漂移處理 `overwrite` 動作必須先備份**
4. **Windows Firewall driver 凍結在階段 A**，B/C 不擴充
5. **nginx schema 獨立**，不得併入防火牆 schema
6. **管轄區檔頭/規則必須含警示字串**：完整版於 nginx 檔案、Windows Description；短版 `BMW-DO-NOT-EDIT` 於 nftables/iptables 規則 comment（受介質長度限制，見 §2.3）
7. **Schema 翻譯結果必須具確定性**（同 schema 永遠產出同字串）

---

## 8. 變更與審核

- 本文件為規範性文件，任何階段範圍、層級、順序、不可妥協項的調整**必須**先修改本文件，再執行對應實作
- Claude 在後續對話中應主動參考本文件
- 用戶下達與本文件條款衝突的指令時，Claude **必須**先指出衝突點，由用戶決定是修改本文件或撤回指令，**不得**逕行執行
- 本文件異動須在 git commit message 註明「ROADMAP 變更」字樣以利追溯

---

## 附錄 A：當前實作差距（對照本規範）

> 此節為現況快照，異動後須更新（或刪除）。最後更新：2026-04-27

- ✓ 防火牆 schema 階段 A（5-tuple）+ B（state+log）+ C（rate_limit+named set）：完成
- ✓ JSON Schema + capability flag 機制：完成（`central/app/schemas/firewall_rule.json` + `driver_capabilities.json` + `services/rule_validator.py`）
- ✓ nftables driver：階段 A/B/C 全支援（含 named set CRUD）
- ✓ iptables driver：階段 A/B/C 全支援（rate 用 `-m limit`，set 用 ipset）
- ✓ Windows Firewall driver：凍結於階段 A，B/C 欄位由 capability layer 拒絕
- ✓ 接管控制面（D）：BMW-ID 標記、漂移偵測、per-node-per-subsystem 政策、SMTP/log fallback 通知、cleanup_unmanaged + 備份
- ✓ nginx 階段 α：獨立 schema、`/etc/nginx/conf.d/beakmeshwall/access.conf` 寫入、nginx -t pre-flight、reload、漂移偵測整合
- ✓ UI：4 頁 dashboard（Firewall Rules / Nginx Rules / Named Sets / Drift Events）+ live task polling + agent stale banner
- ◐ nginx 階段 β（rate limit）：待排
- ◐ nginx 階段 γ（path ACL）：待排
- ◐ 文件：本文件條款已對齊實作；`docs/NGINX-MANAGEMENT.md` 為 nginx 詳細規範

### 待排功能：通道工具（cloudflared 等）偵測與納管提示

**動機**：對外服務的真正 SSOT 不只是 nginx —— 凡是「能對外開洞」的通道工具都會繞過
nginx 的 path/server_name 規則。本機 2026-05-05 即發生過 `kb.beakmask.org` 透過
cloudflared 直連 container（bypass nginx）導致 nginx 安全規則無效的事件，詳見
BeakBroodNest atom id 4166（含 cloudflared 為 SSOT 的後補規則）。

**功能範圍**：

1. **偵測**（通用框架，不單做 cloudflared）：在受管節點上偵測下列「對外開洞」工具的
   存在，列出已配置的對外通道：
   - cloudflared：`/etc/cloudflared/config.yml`、systemd `cloudflared.service`、進程命令列
   - frp / frpc：`/etc/frp/`、進程
   - ngrok：常駐進程（無固定設定路徑）
   - tailscale funnel：`tailscale funnel status` 輸出
   - bore / localtunnel：進程匹配
   - reverse SSH（`ssh -R`）：netstat / ss 反查

2. **特徵摘要**：對每個被偵測到的工具，列出：
   - 設定檔路徑與最後修改時間
   - 已配置的 hostname → service 對應（如 cloudflared ingress）
   - 是否 bypass nginx（service 指向 `localhost:80` 視為經 nginx；其餘為直連）

3. **管制提示（強制人為決策，不自動納管）**：
   - 通道工具種類繁多、設定形式各異，BMW 不假設能管全部
   - 偵測到時提示用戶「此節點存在通道 X，是否納入 BMW 管制？」
   - 用戶決定「納入」後再進入 schema / driver 設計階段（後續開發）
   - 用戶決定「不納入」應記錄理由（可能是合法外部服務，也可能是合規敏感的私設通道）

4. **合規觸發**：偵測到「未經登錄但有對外通道」屬高優先告警 —— 可能是企業內違法
   私設通道（員工私架 ngrok 把內網服務 expose 出去等）。BMW 不直接處置，但須通知
   管理員。

**強制設計約束**：

- **不自動修改**任何通道工具的設定檔，僅偵測與提示（與 nginx 納管的 §2.2 per-node
  enablement 同精神，但更嚴：cloudflared 等沒有「BMW 管轄區子目錄」的 affordance）
- **白名單比對**：管理員可在 BMW 維護「合法通道清單」（e.g. `cloudflared/ssh.beakmask.org`），
  偵測結果與白名單 diff 後才告警
- **與 nginx 對外清單合併呈現**：UI 應同時列出 cloudflared ingress 與 nginx server_name，
  並標明哪些 hostname 經 nginx、哪些直連，幫助管理員看見 SSOT 全貌

**與其他項目的依賴**：
- 須在 D 階段（接管控制面）完成後執行；agent module 化（P5 已完成）為前置
- 與下一節「防火牆 → nginx → 磁碟路徑」獨立，但兩者都會用到「對外清單合併」UI

---

### 待排功能：「防火牆 → nginx → 磁碟路徑」一鍵發布

允許用戶以單一表單描述「對外開一個 port、用 nginx 反代或靜態檔服務一段磁碟路徑」，
BMW 自動同時產生：
1. 防火牆規則（放行該 port 給指定來源）
2. nginx server / location 區塊（指向 `root` 或 `proxy_pass`）

**強制設計約束：**

- **port 黑名單**：此功能在任何「對外 port」欄位都必須預設拒絕 Chromium / Firefox 的 unsafe ports 清單，
  避免使用者開了一個 port 卻發現瀏覽器拒連（curl 通、Chrome `ERR_UNSAFE_PORT`）。
  - 完整清單與背景見 BeakBroodNest 知識原子（id 4165, title「Chromium / Firefox unsafe ports 黑名單」）
  - UI 必須在欄位下方顯示「為何不能用」說明，**而非靜默拒絕**
  - 後端 schema validator 也要擋（capability layer 同步），不依賴 UI 唯一防線
  - 黑名單應放在 `central/app/schemas/` 下做為共用常數，未來 nginx 階段 β/γ 與其他「面向瀏覽器」功能共用
  - 例外允許：用戶明確勾選「我知道，且僅給 curl/API 用」時可放行（該 server 區塊應同時加上 `# WARNING: blocked by browsers` 註解）
- 此功能跨防火牆 + nginx 兩個 schema，**不得**將兩 schema 合併實作；應以「同一交易批次」分別下發兩種規則
- 漂移處理沿用 §4 的 D 框架；若用戶手動把 port 改到黑名單裡，視為 user-side intent，BMW 不自動回退但需通知

### 經由實機測試發現並修正的真實 bug

- nft 規則 comment 上限 128 byte，先前以完整警示字串嵌入會 overflow → 引入 `ManagedTagShort = "BMW-DO-NOT-EDIT"` 給長度受限的介質使用（commit `33dbc3d`，本文件 §2.3 已對齊）
- UI Remove 按鈕的 `@click="removeRule({{ rule|tojson }})"` 在 HTML 雙引號 attribute 內被 JSON 內含的雙引號破壞 → 改為單引號 attribute（同 commit）
