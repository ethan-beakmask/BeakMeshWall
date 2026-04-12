#!/bin/bash
# gen-agent-cert.sh -- Generate and sign an agent client certificate
# Uses the CA created by gen-ca.sh to issue mTLS client certificates.
set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly AGENT_KEY_BITS=2048
readonly CERT_VALID_DAYS=365  # 1 year

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} --ca-dir DIR --agent-name NAME [OPTIONS]

Generate a client certificate for a BeakMeshWall agent, signed by the CA.

Required:
  --ca-dir DIR        Directory containing ca.crt and ca.key
  --agent-name NAME   Agent hostname (used as certificate CN)

Options:
  --output-dir DIR    Directory to store agent cert/key (default: ./certs/agents/<agent-name>)
  --help              Show this help message

Examples:
  ${SCRIPT_NAME} --ca-dir ./certs/ca --agent-name firewall-node-01
  ${SCRIPT_NAME} --ca-dir /etc/beakmeshwall/ca --agent-name web-proxy --output-dir /tmp/agent-certs
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
CA_DIR=""
AGENT_NAME=""
OUTPUT_DIR=""

if [[ $# -eq 0 ]]; then
    usage
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca-dir)
            [[ -z "${2:-}" ]] && error "--ca-dir requires a directory path"
            CA_DIR="$2"
            shift 2
            ;;
        --agent-name)
            [[ -z "${2:-}" ]] && error "--agent-name requires a hostname"
            AGENT_NAME="$2"
            shift 2
            ;;
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

# -- Validate required arguments --
[[ -z "${CA_DIR}" ]] && error "--ca-dir is required"
[[ -z "${AGENT_NAME}" ]] && error "--agent-name is required"

# -- Check dependencies --
command -v openssl >/dev/null 2>&1 || error "openssl is required but not found in PATH"

# -- Validate CA files --
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"
[[ -f "${CA_KEY}" ]] || error "CA key not found: ${CA_KEY}"
[[ -f "${CA_CERT}" ]] || error "CA cert not found: ${CA_CERT}"

# -- Set output directory --
if [[ -z "${OUTPUT_DIR}" ]]; then
    OUTPUT_DIR="./certs/agents/${AGENT_NAME}"
fi
mkdir -p "${OUTPUT_DIR}"

AGENT_KEY="${OUTPUT_DIR}/agent.key"
AGENT_CSR="${OUTPUT_DIR}/agent.csr"
AGENT_CERT="${OUTPUT_DIR}/agent.crt"
AGENT_CA_COPY="${OUTPUT_DIR}/ca.crt"

# -- Guard against overwriting --
if [[ -f "${AGENT_KEY}" || -f "${AGENT_CERT}" ]]; then
    error "Agent cert files already exist in ${OUTPUT_DIR}. Remove them manually to regenerate."
fi

# -- Generate agent private key --
info "Generating agent private key (${AGENT_KEY_BITS}-bit RSA) for '${AGENT_NAME}'..."
openssl genrsa -out "${AGENT_KEY}" "${AGENT_KEY_BITS}" 2>/dev/null
chmod 600 "${AGENT_KEY}"

# -- Generate CSR --
info "Generating CSR with CN=${AGENT_NAME}..."
openssl req -new \
    -key "${AGENT_KEY}" \
    -out "${AGENT_CSR}" \
    -subj "/CN=${AGENT_NAME}/O=BeakMeshWall Agent"

# -- Sign with CA --
info "Signing certificate with CA (valid ${CERT_VALID_DAYS} days)..."
openssl x509 -req \
    -in "${AGENT_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${AGENT_CERT}" \
    -days "${CERT_VALID_DAYS}" \
    -sha256

chmod 644 "${AGENT_CERT}"

# -- Copy CA cert for agent use --
cp "${CA_CERT}" "${AGENT_CA_COPY}"
chmod 644 "${AGENT_CA_COPY}"

# -- Clean up CSR (no longer needed) --
rm -f "${AGENT_CSR}"

# -- Verify --
info "Verifying agent certificate..."
openssl verify -CAfile "${CA_CERT}" "${AGENT_CERT}"

echo ""
echo "============================================================"
echo " Agent certificate generation complete"
echo "============================================================"
echo "  Agent Key:  ${AGENT_KEY}"
echo "  Agent Cert: ${AGENT_CERT}"
echo "  CA Cert:    ${AGENT_CA_COPY}"
echo ""
echo "Deploy these files to the agent node:"
echo "  scp ${AGENT_KEY} ${AGENT_CERT} ${AGENT_CA_COPY} <agent-host>:/etc/beakmeshwall/"
echo ""
echo "Then configure agent.yaml with the file paths."
echo "============================================================"
