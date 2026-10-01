#!/bin/ash
set -euxo pipefail

KEY_DIR="/opt/confidential-containers/kbs/user-keys"
cd "${KEY_DIR}"

# Token-signing cert validity in days; defaults to 90 instead of openssl's silent 30.
TOKEN_CERT_DAYS="${TOKEN_CERT_DAYS:-90}"

# Root CA cert validity in days; default unchanged at 10 years.
CA_CERT_DAYS="${CA_CERT_DAYS:-3650}"

if [ ! -s private.key ]; then
  openssl genpkey -algorithm ed25519 > private.key
  openssl pkey -in private.key -pubout -out public.pub
fi

if [ ! -s admin-token ]; then
  b64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
  }

  header='{"alg":"EdDSA","typ":"JWT"}'
  iat="$(date +%s)"
  exp="$((iat + 315360000))" # 10 years
  payload="{\"iss\":\"TrusteeInDocker\",\"sub\":\"admin\",\"aud\":[\"KBS\"],\"role\":\"admin\",\"iat\":${iat},\"exp\":${exp}}"

  h64="$(printf '%s' "${header}" | b64url)"
  p64="$(printf '%s' "${payload}" | b64url)"
  signing_input="$(mktemp)"
  printf '%s' "${h64}.${p64}" > "${signing_input}"
  sig="$(openssl pkeyutl -sign -inkey private.key -rawin -in "${signing_input}" | b64url)"
  rm -f "${signing_input}"
  printf '%s.%s.%s\n' "${h64}" "${p64}" "${sig}" > admin-token
  chmod 644 admin-token
  echo "Generated ${KEY_DIR}/admin-token (10 years validity)."
fi

if [ ! -s token.key ]; then
  openssl genrsa -traditional -out ca.key 2048
  openssl req -new -key ca.key -out ca-req.csr -subj "/O=CNCF/OU=CoCo/CN=KBS-compose-root"
  openssl req -x509 -days "${CA_CERT_DAYS}" -key ca.key -in ca-req.csr -out ca-cert.pem
  openssl ecparam -name prime256v1 -genkey -noout -out token.key
  openssl req -new -key token.key -out token-req.csr -subj "/O=CNCF/OU=CoCo/CN=CoCo-AS"
  openssl x509 -req -days "${TOKEN_CERT_DAYS}" -in token-req.csr -CA ca-cert.pem -CAkey ca.key -CAcreateserial -out token-cert.pem -extensions req_ext
  cat token-cert.pem ca-cert.pem > token-cert-chain.pem
fi
