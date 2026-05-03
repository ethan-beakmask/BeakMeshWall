#!/bin/bash
# =============================================================================
# BeakMeshWall 安裝與升級腳本
# 適用於 Ubuntu 22.04 / 24.04 LTS
# =============================================================================
#
# 用法:
#   sudo bash install.sh                                顯示此說明
#   sudo bash install.sh central install                Central Server 全新安裝
#   sudo bash install.sh central upgrade                Central Server 升級 (保留資料)
#   sudo bash install.sh central status                 查看 Central 服務狀態
#   sudo bash install.sh central uninstall              移除 Central
#   sudo bash install.sh agent install                  Agent 全新安裝
#   sudo bash install.sh agent upgrade                  Agent 升級
#   sudo bash install.sh agent status                   查看 Agent 服務狀態
#   sudo bash install.sh agent uninstall                移除 Agent
#
# 環境變數 (可選):
#
#   通用:
#     GITHUB_REPO         clone URL (預設 https://github.com/ethan-beakmask/BeakMeshWall.git)
#     GIT_BRANCH          分支 (預設 main)
#     GITHUB_TOKEN        Private repo 用 PAT (未設定就嘗試匿名 clone)
#
#   Central:
#     CENTRAL_DIR         安裝目錄 (預設 /opt/beakmeshwall)
#     CENTRAL_PORT        Nginx 對外 port (預設 5101，被佔用時自動找空 port)
#     DB_NAME             PostgreSQL DB 名稱 (預設 beakmeshwall)
#     DB_USER             DB 使用者 (預設 beakmeshwall)
#     DB_PASS             DB 密碼 (預設自動產生隨機 32 hex)
#     ADMIN_USERNAME      初始管理員帳號 (預設 admin)
#     ADMIN_PASSWORD      初始管理員密碼 (未設定則互動式輸入)
#
#   Agent:
#     AGENT_DIR           Agent 工作目錄 (預設 /opt/beakmeshwall-agent)
#     CENTRAL_URL         Agent 連向的 Central URL (例 http://192.168.0.16:5101)
#     AGENT_HOSTNAME      Agent hostname (預設使用 `hostname`)
#     AGENT_TOKEN         Agent token (升級時自動沿用既有，全新安裝若未指定則執行 -register)
#
# =============================================================================

set -e

# === Script self-version (用於驗證 self-replacement 是否生效) ===
INSTALL_SH_VERSION="0.2.1"

# 保存原始入口參數，供 sync_repo 後 self-replacement 重新執行使用
BMW_ORIG_ARGV=("$@")

# === 預設值 ===
GITHUB_REPO="${GITHUB_REPO:-https://github.com/ethan-beakmask/BeakMeshWall.git}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Central
CENTRAL_DIR="${CENTRAL_DIR:-/opt/beakmeshwall}"
CENTRAL_PORT="${CENTRAL_PORT:-5101}"
DB_NAME="${DB_NAME:-beakmeshwall}"
DB_USER="${DB_USER:-beakmeshwall}"
DB_PASS="${DB_PASS:-}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
CENTRAL_SERVICE_NAME="beakmeshwall-central"
CENTRAL_SERVICE_USER="beakmeshwall"
NGINX_VHOST_NAME="beakmeshwall-central"
HEALTH_TIMEOUT=60

# Agent
AGENT_DIR="${AGENT_DIR:-/opt/beakmeshwall-agent}"
ETC_DIR="/etc/beakmeshwall"
AGENT_BINARY="/usr/local/bin/bmw-agent"
AGENT_CONFIG="$ETC_DIR/agent.yaml"
AGENT_SERVICE_NAME="beakmeshwall-agent"
CENTRAL_URL="${CENTRAL_URL:-}"
AGENT_HOSTNAME="${AGENT_HOSTNAME:-}"
AGENT_TOKEN="${AGENT_TOKEN:-}"

# === 顏色 ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_step()  { echo -e "${BLUE}[$1]${NC} $2"; }

# =============================================================================
# 共用函式
# =============================================================================

usage() {
    cat <<EOF
BeakMeshWall 安裝與升級腳本

用法:
  sudo bash install.sh                            顯示此說明
  sudo bash install.sh central install            Central Server 全新安裝
  sudo bash install.sh central upgrade            Central Server 升級 (保留資料)
  sudo bash install.sh central status             查看 Central 服務狀態
  sudo bash install.sh central uninstall          移除 Central
  sudo bash install.sh agent install              Agent 全新安裝
  sudo bash install.sh agent upgrade              Agent 升級
  sudo bash install.sh agent status               查看 Agent 服務狀態
  sudo bash install.sh agent uninstall            移除 Agent

環境變數:
  通用    GITHUB_REPO=$GITHUB_REPO
          GIT_BRANCH=$GIT_BRANCH
  Central CENTRAL_DIR=$CENTRAL_DIR
          CENTRAL_PORT=$CENTRAL_PORT (被佔用時自動找空 port)
          DB_NAME=$DB_NAME / DB_USER=$DB_USER
          ADMIN_USERNAME=$ADMIN_USERNAME / ADMIN_PASSWORD=<未設定>
  Agent   AGENT_DIR=$AGENT_DIR
          CENTRAL_URL=<必填，例 http://192.168.0.16:5101>
          AGENT_HOSTNAME=<未設定則使用 \`hostname\`>
EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此腳本需要 root 權限執行"
        echo "  用法: sudo bash $0 $*"
        exit 1
    fi
}

check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log_warn "此腳本針對 Ubuntu 22.04/24.04 設計，其他系統可能需要調整"
    fi
}

is_port_in_use() {
    ss -tlnH "sport = :$1" 2>/dev/null | grep -q . && return 0
    return 1
}

find_free_port() {
    local port=$1
    local max_try=100
    local i=0
    while [ $i -lt $max_try ]; do
        if ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        port=$((port + 1))
        i=$((i + 1))
    done
    return 1
}

build_clone_url() {
    # 私有 repo 透過 GITHUB_TOKEN 注入認證；公開 repo 直接用原 URL
    if [ -n "$GITHUB_TOKEN" ] && [[ "$GITHUB_REPO" == https://github.com/* ]]; then
        echo "https://${GITHUB_TOKEN}@${GITHUB_REPO#https://}"
    else
        echo "$GITHUB_REPO"
    fi
}

# 從指定路徑 clone/同步 repo (代碼重用：central 與 agent 共用)
sync_repo() {
    local target_dir="$1"
    local clone_url
    clone_url="$(build_clone_url)"

    # 允許 root 操作非 root 擁有的 repo
    git config --global --add safe.directory "$target_dir" 2>/dev/null || true

    if [ -d "$target_dir/.git" ]; then
        cd "$target_dir"
        git remote set-url origin "$clone_url"
        git fetch origin "$GIT_BRANCH"
        git reset --hard "origin/$GIT_BRANCH"
        log_info "程式碼已同步至: $(git log --oneline -1)"
    else
        if [ -d "$target_dir" ] && [ "$(ls -A "$target_dir" 2>/dev/null)" ]; then
            local backup="${target_dir}.bak.$(date +%s)"
            mv "$target_dir" "$backup"
            log_warn "既有目錄非 git repo，已備份至: $backup"
        fi
        git clone --branch "$GIT_BRANCH" "$clone_url" "$target_dir"
        cd "$target_dir"
        log_info "程式碼 clone 完成: $(git log --oneline -1)"
    fi

    maybe_reexec_with_synced_install_sh "$target_dir"
}

# sync_repo 後若 repo 內 install.sh 與目前執行中版本不同，自動重新執行新版
# 防止「拿舊 install.sh 跑 upgrade，repo 已是新版但 install.sh 邏輯仍是舊的」
maybe_reexec_with_synced_install_sh() {
    local target_dir="$1"
    local script_path
    script_path="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    local new_script="$target_dir/install.sh"

    if [ ! -f "$new_script" ]; then
        return 0
    fi
    if [ "$script_path" = "$new_script" ]; then
        return 0
    fi
    if cmp -s "$script_path" "$new_script" 2>/dev/null; then
        return 0
    fi
    if [ "${BMW_INSTALL_REEXEC:-0}" = "1" ]; then
        log_warn "已 reexec 過一次，仍與 repo 內 install.sh 不同，繼續使用目前版本"
        return 0
    fi
    log_info "切換到 repo 內最新 install.sh ($new_script)，重新執行"
    export BMW_INSTALL_REEXEC=1
    exec bash "$new_script" "${BMW_ORIG_ARGV[@]}"
}

ensure_packages() {
    local pkgs=("$@")
    local missing=()
    for p in "${pkgs[@]}"; do
        if ! dpkg -l "$p" 2>/dev/null | grep -q "^ii"; then
            missing+=("$p")
        fi
    done
    if [ ${#missing[@]} -eq 0 ]; then
        log_info "套件齊全: ${pkgs[*]}"
        return 0
    fi
    log_info "安裝套件: ${missing[*]}"
    timeout 120 apt-get update -q || log_warn "apt update 逾時，嘗試直接安裝"
    apt-get install -y -q "${missing[@]}"
}

# =============================================================================
# Central -- 安裝
# =============================================================================

resolve_central_ports() {
    NGINX_PORT="$CENTRAL_PORT"
    if is_port_in_use "$NGINX_PORT"; then
        local new_port
        new_port=$(find_free_port "$NGINX_PORT")
        if [ -z "$new_port" ]; then
            log_error "找不到可用 nginx port (從 $NGINX_PORT 起)"
            exit 1
        fi
        log_warn "Port $NGINX_PORT 已被佔用，改用 $new_port"
        NGINX_PORT="$new_port"
    fi

    APP_PORT=$((NGINX_PORT + 1))
    if is_port_in_use "$APP_PORT"; then
        APP_PORT=$(find_free_port "$((NGINX_PORT + 2))")
        if [ -z "$APP_PORT" ]; then
            log_error "找不到 gunicorn 可用 port"
            exit 1
        fi
    fi

    HEALTH_URL="http://127.0.0.1:${APP_PORT}/api/v1/health"
}

ensure_central_user() {
    if ! id -u "$CENTRAL_SERVICE_USER" >/dev/null 2>&1; then
        useradd --system --home-dir "$CENTRAL_DIR" --no-create-home --shell /usr/sbin/nologin "$CENTRAL_SERVICE_USER"
        log_info "系統帳號 $CENTRAL_SERVICE_USER 已建立"
    fi
}

central_fix_ownership() {
    chown -R "$CENTRAL_SERVICE_USER:$CENTRAL_SERVICE_USER" "$CENTRAL_DIR"
    mkdir -p /opt/tmp
    chmod 1777 /opt/tmp
}

central_health_check() {
    log_info "Central 健康檢查 (最多 ${HEALTH_TIMEOUT}s)..."
    local elapsed=0
    while [ $elapsed -lt $HEALTH_TIMEOUT ]; do
        if curl -sf "$HEALTH_URL" 2>/dev/null | grep -q '"status":"ok"'; then
            log_info "健康檢查通過"
            sleep 3
            if systemctl is-active --quiet "$CENTRAL_SERVICE_NAME"; then
                log_info "服務穩定性驗證通過"
                return 0
            fi
            log_error "服務在健康檢查後崩潰"
            journalctl -u "$CENTRAL_SERVICE_NAME" -n 30 --no-pager 2>/dev/null || true
            return 1
        fi
        sleep 3
        elapsed=$((elapsed + 3))
        printf "."
    done
    echo ""
    log_error "健康檢查逾時 (${HEALTH_TIMEOUT}s)"
    journalctl -u "$CENTRAL_SERVICE_NAME" -n 30 --no-pager 2>/dev/null || true
    return 1
}

setup_postgres_central() {
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null | grep -q 1 || \
        sudo -u postgres psql -c "CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASS';" >/dev/null
    sudo -u postgres psql -c "ALTER ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASS';" >/dev/null

    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null | grep -q 1; then
        sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >/dev/null
        log_info "PostgreSQL 資料庫已建立 ($DB_NAME)"
    else
        log_info "PostgreSQL 資料庫已存在 ($DB_NAME)"
    fi
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >/dev/null
}

write_central_env() {
    local secret_key
    secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    cat > "$CENTRAL_DIR/.env" <<ENVEOF
# BeakMeshWall Central -- 自動產生於 $(date '+%Y-%m-%d %H:%M')
BMW_SECRET_KEY=$secret_key
BMW_DATABASE_URI=postgresql://$DB_USER:$DB_PASS@127.0.0.1:5432/$DB_NAME
BMW_AGENT_POLL_INTERVAL=5
BMW_SESSION_LIFETIME=3600
BMW_EDL_EXPORT_DIR=$CENTRAL_DIR/edl_export
BMW_DRIFT_BACKUP_DIR=/opt/tmp/beakmeshwall-drift-backup
BMW_NOTIFY_LOG_PATH=/opt/tmp/beakmeshwall-central-drift_notifications.log

# Gunicorn
GUNICORN_BIND=127.0.0.1:$APP_PORT
GUNICORN_WORKERS=3
GUNICORN_TIMEOUT=120

# Nginx 對外 port (供 status 顯示)
NGINX_PORT=$NGINX_PORT
ENVEOF
    chmod 600 "$CENTRAL_DIR/.env"
    chown "$CENTRAL_SERVICE_USER:$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/.env"
}

setup_central_venv() {
    sudo -u "$CENTRAL_SERVICE_USER" python3 -m venv "$CENTRAL_DIR/venv"
    sudo -u "$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/venv/bin/pip" install --upgrade pip wheel -q
    sudo -u "$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/venv/bin/pip" install -r "$CENTRAL_DIR/central/requirements.txt" -q
    # gunicorn 不在 requirements.txt（dev 不需要），install.sh 額外裝
    sudo -u "$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/venv/bin/pip" install gunicorn -q
}

run_central_migrations() {
    sudo -u "$CENTRAL_SERVICE_USER" bash -c "
        set -a; source '$CENTRAL_DIR/.env'; set +a
        export FLASK_APP=app
        cd '$CENTRAL_DIR/central'
        '$CENTRAL_DIR/venv/bin/flask' db upgrade
    "
}

create_admin_if_missing() {
    # 若 users 表為空，互動式建立 admin
    local user_count
    user_count=$(sudo -u "$CENTRAL_SERVICE_USER" bash -c "
        set -a; source '$CENTRAL_DIR/.env'; set +a
        export FLASK_APP=app
        cd '$CENTRAL_DIR/central'
        '$CENTRAL_DIR/venv/bin/python3' -c \"
from app import create_app
from app.extensions import db
from app.models.user import User
app = create_app()
with app.app_context():
    print(User.query.count())
\"" 2>/dev/null | tail -1)

    if [ "${user_count:-0}" != "0" ]; then
        log_info "已存在 $user_count 位使用者，跳過 admin 建立"
        return 0
    fi

    if [ -z "$ADMIN_PASSWORD" ]; then
        while true; do
            read -s -p "請輸入管理員 ($ADMIN_USERNAME) 初始密碼 (>= 8 字元): " ADMIN_PASSWORD
            echo ""
            if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
                log_error "密碼長度不足"
                continue
            fi
            read -s -p "請再輸入一次確認: " confirm
            echo ""
            if [ "$ADMIN_PASSWORD" != "$confirm" ]; then
                log_error "兩次密碼不一致"
                continue
            fi
            break
        done
    fi

    sudo -u "$CENTRAL_SERVICE_USER" bash -c "
        set -a; source '$CENTRAL_DIR/.env'; set +a
        export FLASK_APP=app
        cd '$CENTRAL_DIR/central'
        '$CENTRAL_DIR/venv/bin/flask' create-admin --username '$ADMIN_USERNAME' --password '$ADMIN_PASSWORD'
    "
    log_info "管理員 $ADMIN_USERNAME 已建立"
}

write_central_systemd() {
    cat > "/etc/systemd/system/${CENTRAL_SERVICE_NAME}.service" <<SVCEOF
[Unit]
Description=BeakMeshWall Central (Gunicorn)
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=$CENTRAL_SERVICE_USER
Group=$CENTRAL_SERVICE_USER
WorkingDirectory=$CENTRAL_DIR/central
EnvironmentFile=$CENTRAL_DIR/.env
ExecStart=$CENTRAL_DIR/venv/bin/gunicorn \\
    --bind 127.0.0.1:$APP_PORT \\
    --workers 3 \\
    --timeout 120 \\
    --access-logfile - \\
    --error-logfile - \\
    "app:create_app()"
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable "$CENTRAL_SERVICE_NAME"
}

write_central_nginx() {
    local server_ip
    server_ip=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/ {print $7; exit}')
    server_ip="${server_ip:-127.0.0.1}"

    cat > "/etc/nginx/sites-available/$NGINX_VHOST_NAME" <<NGXEOF
# BeakMeshWall Central reverse proxy
# 自動產生於 $(date '+%Y-%m-%d %H:%M')

server {
    listen $server_ip:$NGINX_PORT;
    listen 127.0.0.1:$NGINX_PORT;
    server_name _;

    client_max_body_size 4M;

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location = / {
        return 444;
    }

    location /bmw/ {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location = /bmw {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_set_header Host \$host;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /static/ {
        proxy_pass http://127.0.0.1:$APP_PORT;
    }

    location / {
        return 444;
    }
}
NGXEOF
    ln -sf "/etc/nginx/sites-available/$NGINX_VHOST_NAME" "/etc/nginx/sites-enabled/$NGINX_VHOST_NAME"
    nginx -t
    systemctl reload nginx
}

central_install() {
    check_root
    check_ubuntu

    echo "============================================"
    echo "  BeakMeshWall Central 全新安裝"
    echo "============================================"

    # 偵測既有安裝 -> 自動切到 upgrade
    if [ -f "$CENTRAL_DIR/.env" ] && systemctl list-unit-files 2>/dev/null | grep -q "^${CENTRAL_SERVICE_NAME}.service"; then
        log_warn "偵測到既有安裝於 $CENTRAL_DIR"
        read -p "切換為升級模式？(Y/n): " ans
        if [[ ! "$ans" =~ ^[nN]$ ]]; then
            central_upgrade
            return $?
        fi
        log_warn "繼續強制重新安裝（既有 DB 資料會保留，使用者帳號可能殘留）"
    fi

    log_step "1/9" "解析 port..."
    resolve_central_ports
    echo "  Nginx port:  $NGINX_PORT"
    echo "  Gunicorn:    127.0.0.1:$APP_PORT"
    echo "  安裝目錄:    $CENTRAL_DIR"
    echo "  資料庫:      $DB_NAME"

    log_step "2/9" "安裝系統套件..."
    ensure_packages python3 python3-venv python3-pip postgresql postgresql-contrib nginx git curl libpq-dev
    systemctl enable --now postgresql nginx >/dev/null

    log_step "3/9" "建立 service user..."
    ensure_central_user

    log_step "4/9" "取得程式碼..."
    mkdir -p "$CENTRAL_DIR"
    sync_repo "$CENTRAL_DIR"
    central_fix_ownership

    log_step "5/9" "建立 Python venv 並安裝相依套件..."
    setup_central_venv

    log_step "6/9" "設定 PostgreSQL..."
    if [ -z "$DB_PASS" ]; then
        DB_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    fi
    setup_postgres_central
    write_central_env
    central_fix_ownership

    log_step "7/9" "執行 alembic migrations..."
    run_central_migrations

    log_step "8/9" "建立 systemd service + nginx vhost..."
    write_central_systemd
    write_central_nginx

    log_step "9/9" "啟動服務..."
    systemctl restart "$CENTRAL_SERVICE_NAME"
    central_health_check

    create_admin_if_missing

    local server_ip
    server_ip=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/ {print $7; exit}')
    server_ip="${server_ip:-127.0.0.1}"

    echo ""
    echo "============================================"
    log_info "Central 全新安裝完成"
    echo "  URL:           http://$server_ip:$NGINX_PORT/bmw/"
    echo "  Health:        http://$server_ip:$NGINX_PORT/api/v1/health"
    echo "  管理員:        $ADMIN_USERNAME"
    echo "  DB:            $DB_NAME (使用者: $DB_USER)"
    echo "  Service:       systemctl status $CENTRAL_SERVICE_NAME"
    echo "  日誌:          journalctl -u $CENTRAL_SERVICE_NAME -f"
    echo "============================================"
}

# =============================================================================
# Central -- 升級
# =============================================================================

central_upgrade() {
    check_root

    if [ ! -d "$CENTRAL_DIR/.git" ] || [ ! -f "$CENTRAL_DIR/.env" ]; then
        log_error "$CENTRAL_DIR 沒有現有安裝，請先執行 central install"
        exit 1
    fi

    echo "============================================"
    echo "  BeakMeshWall Central 升級"
    echo "============================================"

    # 從既有 .env 讀回 port 與 DB 設定，供 health_check 使用
    set -a; source "$CENTRAL_DIR/.env"; set +a
    APP_PORT=$(echo "$GUNICORN_BIND" | sed 's/.*://')
    HEALTH_URL="http://127.0.0.1:${APP_PORT}/api/v1/health"

    log_step "1/5" "拉取最新程式碼..."
    sync_repo "$CENTRAL_DIR"
    central_fix_ownership

    log_step "2/5" "更新 Python 相依套件..."
    sudo -u "$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/venv/bin/pip" install --upgrade pip -q
    sudo -u "$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/venv/bin/pip" install -r "$CENTRAL_DIR/central/requirements.txt" -q
    sudo -u "$CENTRAL_SERVICE_USER" "$CENTRAL_DIR/venv/bin/pip" install gunicorn -q

    log_step "3/5" "執行 migrations..."
    run_central_migrations

    log_step "4/5" "重新寫入 systemd unit (覆寫，沿用既有 .env 中的 port)..."
    APP_PORT=$(echo "$GUNICORN_BIND" | sed 's/.*://')
    write_central_systemd
    # nginx vhost 不重寫 (用戶可能手動調過)；如需重寫 -> central uninstall + install

    log_step "5/5" "重啟服務..."
    systemctl restart "$CENTRAL_SERVICE_NAME"
    central_health_check

    echo ""
    echo "============================================"
    log_info "Central 升級完成 (版本: $(cd "$CENTRAL_DIR" && git log --oneline -1))"
    echo "============================================"
}

# =============================================================================
# Central -- 狀態
# =============================================================================

central_status() {
    echo "=== BeakMeshWall Central 狀態 ==="

    if systemctl is-active --quiet "$CENTRAL_SERVICE_NAME" 2>/dev/null; then
        log_info "Service: 運行中"
        systemctl status "$CENTRAL_SERVICE_NAME" --no-pager -l 2>/dev/null | head -10
    else
        log_warn "Service: 未運行"
    fi

    if [ -f "$CENTRAL_DIR/.env" ]; then
        local port
        port=$(grep '^GUNICORN_BIND=' "$CENTRAL_DIR/.env" | sed 's/.*://')
        if [ -n "$port" ]; then
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/api/v1/health" 2>/dev/null)
            if [ "$code" = "200" ]; then
                log_info "Health: 200 OK"
            else
                log_warn "Health: HTTP $code"
            fi
        fi
    fi

    if systemctl is-active --quiet postgresql 2>/dev/null; then
        log_info "PostgreSQL: 運行中"
    else
        log_warn "PostgreSQL: 未運行"
    fi

    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Nginx: 運行中"
    else
        log_warn "Nginx: 未運行"
    fi

    if [ -d "$CENTRAL_DIR/.git" ]; then
        echo "  版本: $(cd "$CENTRAL_DIR" && git log --oneline -1)"
    fi
}

# =============================================================================
# Central -- 移除
# =============================================================================

central_uninstall() {
    check_root
    echo "=== BeakMeshWall Central 移除 ==="
    log_warn "此操作將移除:"
    echo "  - systemd service ($CENTRAL_SERVICE_NAME)"
    echo "  - Nginx vhost ($NGINX_VHOST_NAME)"
    echo "  - 安裝目錄 ($CENTRAL_DIR)"
    echo "  - PostgreSQL 資料庫 ($DB_NAME) 與使用者 ($DB_USER)"
    echo "  - 系統帳號 ($CENTRAL_SERVICE_USER)"
    read -p "確定移除？(輸入 YES 確認): " ans
    if [ "$ans" != "YES" ]; then
        echo "取消"
        exit 0
    fi

    systemctl stop "$CENTRAL_SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$CENTRAL_SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${CENTRAL_SERVICE_NAME}.service"
    systemctl daemon-reload

    rm -f "/etc/nginx/sites-enabled/$NGINX_VHOST_NAME"
    rm -f "/etc/nginx/sites-available/$NGINX_VHOST_NAME"
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true

    sudo -u postgres psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$DB_NAME' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || true
    sudo -u postgres psql -c "DROP ROLE IF EXISTS $DB_USER;" 2>/dev/null || true

    rm -rf "$CENTRAL_DIR"

    if id -u "$CENTRAL_SERVICE_USER" >/dev/null 2>&1; then
        userdel "$CENTRAL_SERVICE_USER" 2>/dev/null || true
    fi

    log_info "Central 移除完成"
}

# =============================================================================
# Agent -- 安裝
# =============================================================================

ensure_agent_token() {
    # 升級時優先沿用既有 token
    if [ -z "$AGENT_TOKEN" ] && [ -f "$AGENT_CONFIG" ]; then
        AGENT_TOKEN=$(grep -E '^\s*token:' "$AGENT_CONFIG" 2>/dev/null | sed -E 's/.*token:\s*"?([^"]*)"?.*/\1/' | head -1)
        if [ -n "$AGENT_TOKEN" ]; then
            log_info "沿用既有 agent token"
        fi
    fi
}

write_agent_config() {
    local hostname="${AGENT_HOSTNAME:-$(hostname)}"
    local fw_driver="nftables"
    if ! command -v nft >/dev/null 2>&1; then
        log_warn "nft 未安裝，agent 將無法管理防火牆規則"
    fi

    mkdir -p "$ETC_DIR"
    cat > "$AGENT_CONFIG" <<YAMLEOF
# BeakMeshWall Agent -- 自動產生於 $(date '+%Y-%m-%d %H:%M')
central:
  url: $CENTRAL_URL
  token: "${AGENT_TOKEN}"

agent:
  hostname: $hostname
  poll_interval: 5

transport:
  type: http

firewall:
  driver: $fw_driver
  table: inet beakmeshwall

modules:
  firewall: true
  nginx: true
  service: true
  sysinfo: true

nginx:
  config_path: /etc/nginx/sites-enabled
YAMLEOF
    chmod 600 "$AGENT_CONFIG"
}

build_agent_binary() {
    if ! command -v go >/dev/null 2>&1; then
        log_error "未偵測到 Go (go command)。請先安裝 Go 1.22+：apt-get install -y golang-go"
        exit 1
    fi

    local go_ver
    go_ver=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $go_ver"

    cd "$AGENT_DIR/agent"
    log_info "編譯 bmw-agent..."
    go build -o /tmp/bmw-agent.new ./cmd/bmw-agent
    install -m 0755 /tmp/bmw-agent.new "$AGENT_BINARY"
    rm -f /tmp/bmw-agent.new
    log_info "Binary 已安裝: $AGENT_BINARY ($("$AGENT_BINARY" -version 2>&1 | head -1))"
}

register_agent_if_needed() {
    ensure_agent_token

    if [ -n "$AGENT_TOKEN" ]; then
        log_info "已有 agent token，跳過註冊"
        return 0
    fi

    if [ -z "$CENTRAL_URL" ]; then
        log_error "CENTRAL_URL 未設定，無法註冊。請設定環境變數，例:"
        echo "  CENTRAL_URL=http://192.168.0.16:5101 sudo bash install.sh agent install"
        exit 1
    fi

    log_info "向 Central ($CENTRAL_URL) 註冊..."
    local register_out
    # 用一份臨時 config 做 register（token 為空）
    write_agent_config
    register_out=$("$AGENT_BINARY" -config "$AGENT_CONFIG" -register 2>&1)
    echo "$register_out"

    AGENT_TOKEN=$(echo "$register_out" | grep -E '^Token:' | awk '{print $2}')
    if [ -z "$AGENT_TOKEN" ]; then
        log_error "註冊失敗，無法取得 token"
        exit 1
    fi
    log_info "註冊成功，token: ${AGENT_TOKEN:0:8}..."
    write_agent_config
}

write_agent_systemd() {
    cat > "/etc/systemd/system/${AGENT_SERVICE_NAME}.service" <<SVCEOF
[Unit]
Description=BeakMeshWall Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=root
ExecStart=$AGENT_BINARY -config $AGENT_CONFIG
Restart=always
RestartSec=10

NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable "$AGENT_SERVICE_NAME"
}

agent_health_check() {
    log_info "Agent 健康檢查..."
    sleep 3
    if ! systemctl is-active --quiet "$AGENT_SERVICE_NAME"; then
        log_error "Agent service 未啟動"
        journalctl -u "$AGENT_SERVICE_NAME" -n 30 --no-pager 2>/dev/null || true
        return 1
    fi
    sleep 5
    if ! systemctl is-active --quiet "$AGENT_SERVICE_NAME"; then
        log_error "Agent service 啟動後崩潰"
        journalctl -u "$AGENT_SERVICE_NAME" -n 30 --no-pager 2>/dev/null || true
        return 1
    fi
    log_info "Agent 運行中"
    return 0
}

agent_install() {
    check_root
    check_ubuntu

    if [ -z "$CENTRAL_URL" ]; then
        log_error "CENTRAL_URL 未設定"
        echo "  例: CENTRAL_URL=http://192.168.0.16:5101 sudo bash $0 agent install"
        exit 1
    fi

    echo "============================================"
    echo "  BeakMeshWall Agent 全新安裝"
    echo "============================================"

    if [ -f "$AGENT_CONFIG" ] && systemctl list-unit-files 2>/dev/null | grep -q "^${AGENT_SERVICE_NAME}.service"; then
        log_warn "偵測到既有 agent 安裝"
        read -p "切換為升級模式？(Y/n): " ans
        if [[ ! "$ans" =~ ^[nN]$ ]]; then
            agent_upgrade
            return $?
        fi
    fi

    log_step "1/6" "安裝系統套件..."
    ensure_packages git curl golang-go nftables iproute2

    log_step "2/6" "取得程式碼..."
    mkdir -p "$AGENT_DIR" "$ETC_DIR"
    sync_repo "$AGENT_DIR"

    log_step "3/6" "編譯 agent binary..."
    build_agent_binary

    log_step "4/6" "註冊 / 寫入設定..."
    register_agent_if_needed

    log_step "5/6" "建立 systemd service..."
    write_agent_systemd

    log_step "6/6" "啟動服務..."
    systemctl restart "$AGENT_SERVICE_NAME"
    agent_health_check

    echo ""
    echo "============================================"
    log_info "Agent 全新安裝完成"
    echo "  Hostname:   ${AGENT_HOSTNAME:-$(hostname)}"
    echo "  Central:    $CENTRAL_URL"
    echo "  Config:     $AGENT_CONFIG"
    echo "  Binary:     $AGENT_BINARY"
    echo "  Service:    systemctl status $AGENT_SERVICE_NAME"
    echo "  日誌:       journalctl -u $AGENT_SERVICE_NAME -f"
    echo "============================================"
}

agent_upgrade() {
    check_root

    if [ ! -d "$AGENT_DIR/.git" ] || [ ! -f "$AGENT_CONFIG" ]; then
        log_error "$AGENT_DIR 沒有現有安裝，請先執行 agent install"
        exit 1
    fi

    echo "============================================"
    echo "  BeakMeshWall Agent 升級"
    echo "============================================"

    log_step "1/3" "拉取最新程式碼..."
    sync_repo "$AGENT_DIR"

    log_step "2/3" "重新編譯 binary..."
    build_agent_binary

    log_step "3/3" "重啟服務..."
    write_agent_systemd  # 冪等
    systemctl restart "$AGENT_SERVICE_NAME"
    agent_health_check

    echo ""
    echo "============================================"
    log_info "Agent 升級完成 (版本: $(cd "$AGENT_DIR" && git log --oneline -1))"
    echo "============================================"
}

agent_status() {
    echo "=== BeakMeshWall Agent 狀態 ==="

    if systemctl is-active --quiet "$AGENT_SERVICE_NAME" 2>/dev/null; then
        log_info "Service: 運行中"
        systemctl status "$AGENT_SERVICE_NAME" --no-pager -l 2>/dev/null | head -10
    else
        log_warn "Service: 未運行"
    fi

    if [ -f "$AGENT_CONFIG" ]; then
        local central
        central=$(grep -E '^\s*url:' "$AGENT_CONFIG" | sed -E 's/.*url:\s*//' | head -1)
        echo "  Central:  $central"
    fi

    if [ -d "$AGENT_DIR/.git" ]; then
        echo "  版本:     $(cd "$AGENT_DIR" && git log --oneline -1)"
    fi

    if [ -x "$AGENT_BINARY" ]; then
        echo "  Binary:   $("$AGENT_BINARY" -version 2>&1 | head -1)"
    fi
}

agent_uninstall() {
    check_root
    echo "=== BeakMeshWall Agent 移除 ==="
    log_warn "此操作將移除:"
    echo "  - systemd service ($AGENT_SERVICE_NAME)"
    echo "  - Binary ($AGENT_BINARY)"
    echo "  - 設定檔 ($AGENT_CONFIG)"
    echo "  - 工作目錄 ($AGENT_DIR)"
    echo "  - 注意: nftables table 'inet beakmeshwall' 不會自動清除"
    read -p "確定移除？(輸入 YES 確認): " ans
    if [ "$ans" != "YES" ]; then
        echo "取消"
        exit 0
    fi

    systemctl stop "$AGENT_SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$AGENT_SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${AGENT_SERVICE_NAME}.service"
    systemctl daemon-reload

    rm -f "$AGENT_BINARY"
    rm -f "$AGENT_CONFIG"
    rm -rf "$AGENT_DIR"

    log_info "Agent 移除完成 (nftables table 需手動清: nft delete table inet beakmeshwall)"
}

# =============================================================================
# 入口
# =============================================================================

if [ $# -eq 0 ]; then
    usage
    exit 0
fi

log_info "install.sh version: $INSTALL_SH_VERSION${BMW_INSTALL_REEXEC:+ (reexec)}"

COMPONENT="${1:-}"
ACTION="${2:-}"

case "$COMPONENT" in
    central)
        case "$ACTION" in
            install)   central_install ;;
            upgrade)   central_upgrade ;;
            status)    central_status ;;
            uninstall) central_uninstall ;;
            *)         usage; exit 1 ;;
        esac
        ;;
    agent)
        case "$ACTION" in
            install)   agent_install ;;
            upgrade)   agent_upgrade ;;
            status)    agent_status ;;
            uninstall) agent_uninstall ;;
            *)         usage; exit 1 ;;
        esac
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
