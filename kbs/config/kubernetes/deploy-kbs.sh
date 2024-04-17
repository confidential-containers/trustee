#!/usr/bin/env bash

set -euo pipefail

# Environment variable that defines which directory to use the kustomization file for deployment.
DEPLOYMENT_DIR="${DEPLOYMENT_DIR:-overlays}"

k8s_cnf_dir="$(dirname ${BASH_SOURCE[0]})"

# Fail the script if the key.bin file does not exist.
key_file="${k8s_cnf_dir}/overlays/key.bin"
[[ -f "${key_file}" ]] || {
    echo "key.bin file does not exist"
    exit 1
}

# Create a file kbs.pem if it does not exist.
kbs_cert="${k8s_cnf_dir}/base/kbs.pem"
[[ -f "${kbs_cert}" ]] || {
    openssl genpkey -algorithm ed25519 >"${k8s_cnf_dir}/base/kbs.key"
    openssl pkey -in "${k8s_cnf_dir}/base/kbs.key" -pubout -out "${kbs_cert}"
}

kubectl apply -k "./${k8s_cnf_dir}/${DEPLOYMENT_DIR}"
