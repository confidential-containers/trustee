#!/bin/bash

set -eu
set -o pipefail

RIM=${RIM:?must be set to the expected RIM value (b64-encoded)}

_d="$(dirname "$(readlink -f "$0")")"

source "${_d}/func.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

rv="${tmp_dir}/rim-rv.json"

cat << EOF > "${rv}"
{
  "cca.realm.cca-realm-initial-measurement": [
    "${RIM}"
  ]
}
EOF

blob="${tmp_dir}/blob.json"

payload=$(cat "${rv}" | ${_base64})
cat << EOF > "${blob}"
{
    "version" : "0.1.0",
    "type": "sample",
    "payload": "$payload"
}
EOF

echo ">>> submitting ${blob} to RVPS"

"${_d}"/../../../../../target/release/rvps-tool register -p ${blob} -a http://rvps:50003

echo ">>> success!"