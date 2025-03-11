#!/bin/bash -x
#
# TODO
# * check that evcli is in PATH as a precondition

set -euo pipefail

_d="$(dirname $(readlink -f $0))"

source "${_d}/func.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

kbs="kbs:8080"
cookie_jar="${tmp_dir}/cookie.txt"

cp /dev/null ${cookie_jar}

echo ">>> sending auth"

# -f means fail if HTTP status [45]xx
nonce=$(curl -X POST http://${kbs}/kbs/v0/auth \
     -sS \
     -c ${cookie_jar} \
     -H 'Content-Type: application/json' \
     -d @${_d}/../misc/kbs-request.json | jq .nonce | ${_sed} -e 's/"//g')

echo ">>> got nonce: $nonce"
echo ">>> cookies:"
grep -v "^#" ${cookie_jar}

echo ">>> preparing token"

p_cpak=${_d}/../misc/cpak-pub.json
s_cpak=${_d}/../misc/cpak-priv.json
s_rak=${_d}/../misc/rak-priv.json
golden=${_d}/../misc/cca-example-token.cbor
token="${tmp_dir}/t.cbor"

nonce_hex=$(cat << EOF | tr -d '\n' | tr -d '[:space:] ' | shasum -a 384 | cut -d' ' -f1
{
  "nonce": "$nonce",
  "tee-pubkey": {
    "alg": "RSA",
    "e": "AQAB",
    "kty": "RSA",
    "n": "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ"
  }
}
EOF
)"00000000000000000000000000000000"

nonce_b64=$(echo $nonce_hex | xxd -p -r | ${_base64})

echo ">>> computed nonce: $nonce_b64"

evcli cca create -r ${s_rak} -p ${s_cpak} -t ${token} -c <(evcli cca check -k ${p_cpak} -t ${golden} \
  | tail -n +2 \
  | jq --arg n "$nonce_b64" '."cca-realm-delegated-token"."cca-realm-challenge" = $n')

vectoken="$(${_tokenise} ${token})"

attreq="${tmp_dir}/a.json"

cat << EOF > $attreq
{
  "tee-pubkey": {
    "alg": "RSA",
    "e": "AQAB",
    "kty": "RSA",
    "n": "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ"
  },
  "tee-evidence": "{ \"token\": [ $vectoken ] }"
}
EOF

echo ">>> sending attestation"
echo ">>> cookies:"
grep -v "^#" ${cookie_jar}

curl -X POST http://${kbs}/kbs/v0/attest \
     -sS \
     -b ${cookie_jar} \
     -H 'Content-Type: application/json' \
     -d @${attreq} | jq .

echo ">>> success!"
