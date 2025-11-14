#!/bin/bash

# Usage: ./generate_keypair.sh <LOOKUP_LABEL> <PIN> <PKCS11_MODULE_PATH>
# Example: ./generate_keypair.sh trustee-test 123456 /usr/lib/softhsm/libsofthsm2.so

LOOKUP_LABEL="$1"
USER_PIN="$2"
MODULE_PATH="$3"

if [ -z "$LOOKUP_LABEL" ] || [ -z "$USER_PIN" ] || [ -z "$MODULE_PATH" ]; then
  echo "Usage: $0 <LOOKUP_LABEL> <PIN> <PKCS11_MODULE_PATH>"
  exit 1
fi




echo "Generating RSA 4096-bit key pair with LOOKUP_LABEL:"
echo ">$LOOKUP_LABEL<"

pkcs11-tool --module "$MODULE_PATH" \
  --login --pin "$USER_PIN" \
  --keypairgen \
  --key-type rsa:4096 \
  --label "$LOOKUP_LABEL" \
  --usage-decrypt
if [ $? -eq 0 ]; then
  echo "Key pair generated successfully."
else
  echo "Failed to generate key pair."
  exit 2
fi