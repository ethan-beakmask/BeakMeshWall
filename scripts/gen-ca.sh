#!/bin/bash
# gen-ca.sh -- Generate a self-signed CA for BeakMeshWall mTLS
# This CA is used to sign agent client certificates.
set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_OUTPUT_DIR="./certs/ca"
readonly CA_KEY_BITS=4096
readonly CA_VALID_DAYS=3650  # ~10 years
readonly CA_SUBJECT="/CN=BeakMeshWall CA/O=BeakMeshWall"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Generate a self-signed Certificate Authority for BeakMeshWall mTLS.

Options:
  --output-dir DIR   Directory to store CA cert and key (default: ${DEFAULT_OUTPUT_DIR})
  --help             Show this help message

Examples:
  ${SCRIPT_NAME}
  ${SCRIPT_NAME} --output-dir /etc/beakmeshwall/ca
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

# -- Parse arguments --
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            [[ -z "${2:-}" ]] && error "--output-dir requires a directory path"
            OUTPUT_DIR="$2"
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

# -- Check dependencies --
command -v openssl >/dev/null 2>&1 || error "openssl is required but not found in PATH"

# -- Create output directory --
mkdir -p "${OUTPUT_DIR}"
info "Output directory: ${OUTPUT_DIR}"

CA_KEY="${OUTPUT_DIR}/ca.key"
CA_CERT="${OUTPUT_DIR}/ca.crt"

# -- Guard against overwriting existing CA --
if [[ -f "${CA_KEY}" || -f "${CA_CERT}" ]]; then
    error "CA files already exist in ${OUTPUT_DIR}. Remove them manually to regenerate."
fi

# -- Generate CA private key --
info "Generating CA private key (${CA_KEY_BITS}-bit RSA)..."
openssl genrsa -out "${CA_KEY}" "${CA_KEY_BITS}" 2>/dev/null
chmod 600 "${CA_KEY}"

# -- Generate CA certificate --
info "Generating CA certificate (valid ${CA_VALID_DAYS} days)..."
openssl req -new -x509 \
    -key "${CA_KEY}" \
    -out "${CA_CERT}" \
    -days "${CA_VALID_DAYS}" \
    -subj "${CA_SUBJECT}" \
    -sha256

chmod 644 "${CA_CERT}"

# -- Verify --
info "Verifying CA certificate..."
openssl x509 -in "${CA_CERT}" -noout -text | grep -E "Subject:|Not After" | sed 's/^/  /'

echo ""
echo "============================================================"
echo " CA generation complete"
echo "============================================================"
echo "  CA Key:  ${CA_KEY}"
echo "  CA Cert: ${CA_CERT}"
echo ""
echo "Next steps:"
echo "  1. Keep ca.key secure -- it signs all agent certificates."
echo "  2. Use scripts/gen-agent-cert.sh to issue agent certificates."
echo "  3. Copy ca.crt to the Central Server's TLS config."
echo "============================================================"
