#!/usr/bin/env bash

set -euo pipefail

# Environment variable that defines which directory to use the kustomization file for deployment.
DEPLOYMENT_DIR="${DEPLOYMENT_DIR:-overlays}"
OVERLAYS_DIR="overlays"

k8s_cnf_dir="$(dirname ${BASH_SOURCE[0]})"

if [ "$(uname -m)" == "s390x" ] && [ -n "${IBM_SE_CREDS_DIR:-}" ]; then
    # We are using the ibm-se overlay
    echo "ibm-se overlay being used as IBM_SE_CREDS_DIR was set"
    OVERLAYS_DIR="${OVERLAYS_DIR}/ibm-se"
    DEPLOYMENT_DIR="${DEPLOYMENT_DIR}/ibm-se"
    export NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
    envsubst <"${k8s_cnf_dir}/${OVERLAYS_DIR}/pv.yaml" | kubectl apply -f -
fi

# Fail the script if the key.bin file does not exist.
key_file="${k8s_cnf_dir}/${OVERLAYS_DIR}/key.bin"
[[ -f "${key_file}" ]] || {
    echo "key.bin not found at ${k8s_cnf_dir}/${OVERLAYS_DIR}/"
    exit 1
}

# Create a file kbs.pem if it does not exist.
kbs_cert="${k8s_cnf_dir}/base/kbs.pem"
[[ -f "${kbs_cert}" ]] || {
    openssl genpkey -algorithm ed25519 >"${k8s_cnf_dir}/base/kbs.key"
    openssl pkey -in "${k8s_cnf_dir}/base/kbs.key" -pubout -out "${kbs_cert}"
}


if [[ "${DEPLOYMENT_DIR}" == "nodeport" || "${DEPLOYMENT_DIR}" == "overlays" ]]; then
    kubectl apply -k "${k8s_cnf_dir}/${DEPLOYMENT_DIR}"
else
    kubectl apply -k "${k8s_cnf_dir}/${DEPLOYMENT_DIR}"
fi
