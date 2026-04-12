#!/bin/bash
# download-vendor.sh -- Download frontend vendor assets for offline use
# Downloads Bootstrap CSS/JS and Alpine.js to the static vendor directory.
set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"

# -- Configurable versions --
BOOTSTRAP_VERSION="${BOOTSTRAP_VERSION:-5.3.3}"
ALPINE_VERSION="${ALPINE_VERSION:-3.14.8}"

# -- Paths --
readonly BASE_DIR="${VENDOR_DIR:-central/app/static/vendor}"
readonly BOOTSTRAP_CSS_DIR="${BASE_DIR}/bootstrap/css"
readonly BOOTSTRAP_JS_DIR="${BASE_DIR}/bootstrap/js"
readonly ALPINE_DIR="${BASE_DIR}/alpine"

# -- Download URLs --
readonly BOOTSTRAP_CSS_URL="https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_VERSION}/dist/css/bootstrap.min.css"
readonly BOOTSTRAP_JS_URL="https://cdn.jsdelivr.net/npm/bootstrap@${BOOTSTRAP_VERSION}/dist/js/bootstrap.bundle.min.js"
readonly ALPINE_JS_URL="https://cdn.jsdelivr.net/npm/alpinejs@${ALPINE_VERSION}/dist/cdn.min.js"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Download frontend vendor assets (Bootstrap + Alpine.js) for offline use.
Files are saved to ${BASE_DIR}/.

Versions can be overridden via environment variables:
  BOOTSTRAP_VERSION  (default: ${BOOTSTRAP_VERSION})
  ALPINE_VERSION     (default: ${ALPINE_VERSION})
  VENDOR_DIR         (default: central/app/static/vendor)

Options:
  --help    Show this help message

Examples:
  ${SCRIPT_NAME}
  BOOTSTRAP_VERSION=5.3.2 ${SCRIPT_NAME}
  VENDOR_DIR=/opt/beakmeshwall/central/app/static/vendor ${SCRIPT_NAME}
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

download_file() {
    local url="$1"
    local dest="$2"
    local desc="$3"

    info "Downloading ${desc}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "${dest}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${dest}" "${url}"
    else
        error "Neither curl nor wget found in PATH"
    fi

    # Verify file was downloaded and is not empty
    if [[ ! -s "${dest}" ]]; then
        rm -f "${dest}"
        error "Download failed or file is empty: ${desc} (${url})"
    fi

    local size
    size=$(stat -c%s "${dest}" 2>/dev/null || stat -f%z "${dest}" 2>/dev/null || echo "unknown")
    info "  Saved: ${dest} (${size} bytes)"
}

# -- Parse arguments --
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            ;;
        *)
            error "Unknown option: $1. Use --help for usage."
            ;;
    esac
done

# -- Create directories --
info "Creating vendor directories..."
mkdir -p "${BOOTSTRAP_CSS_DIR}" "${BOOTSTRAP_JS_DIR}" "${ALPINE_DIR}"

# -- Download Bootstrap --
download_file "${BOOTSTRAP_CSS_URL}" "${BOOTSTRAP_CSS_DIR}/bootstrap.min.css" "Bootstrap ${BOOTSTRAP_VERSION} CSS"
download_file "${BOOTSTRAP_JS_URL}" "${BOOTSTRAP_JS_DIR}/bootstrap.bundle.min.js" "Bootstrap ${BOOTSTRAP_VERSION} JS (bundled with Popper)"

# -- Download Alpine.js --
download_file "${ALPINE_JS_URL}" "${ALPINE_DIR}/alpine.min.js" "Alpine.js ${ALPINE_VERSION}"

echo ""
echo "============================================================"
echo " Vendor assets downloaded successfully"
echo "============================================================"
echo "  Bootstrap ${BOOTSTRAP_VERSION}:"
echo "    CSS: ${BOOTSTRAP_CSS_DIR}/bootstrap.min.css"
echo "    JS:  ${BOOTSTRAP_JS_DIR}/bootstrap.bundle.min.js"
echo ""
echo "  Alpine.js ${ALPINE_VERSION}:"
echo "    JS:  ${ALPINE_DIR}/alpine.min.js"
echo ""
echo "Include in templates:"
echo '  <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.min.css">'
echo '  <script src="/static/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>'
echo '  <script defer src="/static/vendor/alpine/alpine.min.js"></script>'
echo "============================================================"
