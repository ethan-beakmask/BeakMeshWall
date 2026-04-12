#!/bin/bash
# init-db.sh -- Initialize PostgreSQL database for BeakMeshWall
# Must be run as a user with PostgreSQL superuser access (postgres or via sudo).
set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_DB_USER="beakmeshwall"
readonly DEFAULT_DB_NAME="beakmeshwall"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Initialize the PostgreSQL database and user for BeakMeshWall Central Server.
This script is idempotent -- it checks for existing DB/user before creating.

Must be run as a user with PostgreSQL superuser access.
Typical usage:
  sudo -u postgres ${SCRIPT_NAME} --db-password <password>

Options:
  --db-user NAME       Database user name (default: ${DEFAULT_DB_USER})
  --db-name NAME       Database name (default: ${DEFAULT_DB_NAME})
  --db-password PASS   Password for the database user (will prompt if omitted)
  --help               Show this help message

Examples:
  sudo -u postgres ${SCRIPT_NAME} --db-password secretpass
  sudo -u postgres ${SCRIPT_NAME} --db-user myapp --db-name myapp_db --db-password secretpass
EOF
    exit 0
}

error() {
    echo "[ERROR] $1" >&2
    exit 1
}

info() {
    echo "[INFO] $1"
}

warn() {
    echo "[WARN] $1"
}

# -- Parse arguments --
DB_USER="${DEFAULT_DB_USER}"
DB_NAME="${DEFAULT_DB_NAME}"
DB_PASSWORD=""

if [[ $# -eq 0 ]]; then
    usage
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db-user)
            [[ -z "${2:-}" ]] && error "--db-user requires a value"
            DB_USER="$2"
            shift 2
            ;;
        --db-name)
            [[ -z "${2:-}" ]] && error "--db-name requires a value"
            DB_NAME="$2"
            shift 2
            ;;
        --db-password)
            [[ -z "${2:-}" ]] && error "--db-password requires a value"
            DB_PASSWORD="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            error "Unknown option: $1. Use --help for usage."
            ;;
    esac
done

# -- Prompt for password if not provided --
if [[ -z "${DB_PASSWORD}" ]]; then
    read -rsp "Enter password for database user '${DB_USER}': " DB_PASSWORD
    echo ""
    [[ -z "${DB_PASSWORD}" ]] && error "Password cannot be empty"
fi

# -- Check dependencies --
command -v psql >/dev/null 2>&1 || error "psql is required but not found in PATH"

# -- Check if PostgreSQL is accessible --
if ! psql -c "SELECT 1" >/dev/null 2>&1; then
    error "Cannot connect to PostgreSQL. Ensure you are running as a PostgreSQL superuser (e.g., sudo -u postgres $0 ...)"
fi

# -- Create user (idempotent) --
if psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
    warn "User '${DB_USER}' already exists, skipping creation."
    info "Updating password for existing user '${DB_USER}'..."
    psql -c "ALTER USER \"${DB_USER}\" WITH PASSWORD '${DB_PASSWORD}';"
else
    info "Creating database user '${DB_USER}'..."
    psql -c "CREATE USER \"${DB_USER}\" WITH PASSWORD '${DB_PASSWORD}';"
fi

# -- Create database (idempotent) --
if psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    warn "Database '${DB_NAME}' already exists, skipping creation."
else
    info "Creating database '${DB_NAME}'..."
    psql -c "CREATE DATABASE \"${DB_NAME}\" OWNER \"${DB_USER}\";"
fi

# -- Grant privileges --
info "Granting privileges on '${DB_NAME}' to '${DB_USER}'..."
psql -c "GRANT ALL PRIVILEGES ON DATABASE \"${DB_NAME}\" TO \"${DB_USER}\";"

# -- Grant schema privileges (PostgreSQL 15+ requires explicit schema grants) --
psql -d "${DB_NAME}" -c "GRANT ALL ON SCHEMA public TO \"${DB_USER}\";"

echo ""
echo "============================================================"
echo " Database initialization complete"
echo "============================================================"
echo "  Database: ${DB_NAME}"
echo "  User:     ${DB_USER}"
echo ""
echo "Connection string:"
echo "  postgresql://${DB_USER}:<password>@localhost:5432/${DB_NAME}"
echo ""
echo "Set the DB_PASSWORD environment variable for the Central Server,"
echo "or configure it in the beakmeshwall.ini config file."
echo "============================================================"
