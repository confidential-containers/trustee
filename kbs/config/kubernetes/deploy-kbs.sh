#!/usr/bin/env bash

set -euo pipefail

# Environment variable that defines which directory to use the kustomization file for deployment.
DEPLOYMENT_DIR="${DEPLOYMENT_DIR:-overlays}"

k8s_cnf_dir="$(dirname ${BASH_SOURCE[0]})"
ARCH=$(uname -m)

# Fail the script if the key.bin file does not exist.
key_file="${k8s_cnf_dir}/overlays/${ARCH}/key.bin"
[[ -f "${key_file}" ]] || {
    echo "key.bin not found at ${k8s_cnf_dir}/overlays/${ARCH}/"
    exit 1
}

# Create a file kbs.pem if it does not exist.
kbs_cert="${k8s_cnf_dir}/base/kbs.pem"
[[ -f "${kbs_cert}" ]] || {
    openssl genpkey -algorithm ed25519 >"${k8s_cnf_dir}/base/kbs.key"
    openssl pkey -in "${k8s_cnf_dir}/base/kbs.key" -pubout -out "${kbs_cert}"
}

if [ "${ARCH}" == "s390x" ]; then
    if [ -n "${IBM_SE_CREDS_DIR:-}" ]; then
    export NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
    envsubst <"${k8s_cnf_dir}/overlays/s390x/pv.yaml" | kubectl apply -f -
    else
        echo "IBM_SE_CREDS_DIR is empty" >&2
        exit 1
    fi
fi

if [[ "${DEPLOYMENT_DIR}" == "nodeport" || "${DEPLOYMENT_DIR}" == "overlays" ]]; then
    kubectl apply -k "${k8s_cnf_dir}/${DEPLOYMENT_DIR}/${ARCH}"
else
    kubectl apply -k "${k8s_cnf_dir}/${DEPLOYMENT_DIR}"
fi
