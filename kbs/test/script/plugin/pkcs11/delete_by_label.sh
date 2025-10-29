#!/bin/bash

# Usage: ./delete_by_label.sh <LOOKUP_LABEL> <PIN> <PKCS11_MODULE_PATH>
# Example: ./delete_by_label.sh trustee-test 123456 /usr/lib/softhsm/libsofthsm2.so

LOOKUP_LABEL="$1"
USER_PIN="$2"
MODULE_PATH="$3"

if [ -z "$LOOKUP_LABEL" ] || [ -z "$USER_PIN" ] || [ -z "$MODULE_PATH" ]; then
  echo "Usage: $0 <LOOKUP_LABEL> <PIN> <PKCS11_MODULE_PATH>"
  exit 1
fi

echo "Deleting RSA key pair with LOOKUP_LABEL:"
echo ">$LOOKUP_LABEL<"

# Delete keys
pkcs11-tool --module "$MODULE_PATH" \
  --login --pin "$USER_PIN" \
  --delete-object --label "$LOOKUP_LABEL" --type privkey
pkcs11-tool --module "$MODULE_PATH" \
  --login --pin "$USER_PIN" \
  --delete-object --label "$LOOKUP_LABEL" --type pubkey

if [ $? -eq 0 ]; then
  echo "Key pair deleted successfully."
else
  echo "Failed to delete key pair."
  exit 2
fi