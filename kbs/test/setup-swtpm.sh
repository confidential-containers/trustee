#!/bin/bash

set -euo pipefail

# Execute this script with root privileges as both swtpm_setup and modprobe
# needs root pivileges

WORK_DIR="./work"
TRUSTED_TPM_KEYS_DIR="$WORK_DIR"/tpm_trusted_keys
TPM_STATE_DIR="/tmp/tpmdir"

setup_swtpm() {
    modprobe tpm_vtpm_proxy
    mkdir -p "$TPM_STATE_DIR"

    swtpm_setup --tpm2 \
                --tpmstate "$TPM_STATE_DIR" \
                --createek --decryption \
                --create-ek-cert \
                --create-platform-cert \
                --pcr-banks - \
                --display

    swtpm chardev --tpm2 \
                --tpmstate dir="$TPM_STATE_DIR" \
                --vtpm-proxy \
                --daemon \
                --log file="$TPM_STATE_DIR"/tpm.log,level=20 \
                --flags not-need-init \
		--pid file="$TPM_STATE_DIR"/swtpm.pid
}

stop_swtpm() {
    kill -9 $(cat "$TPM_STATE_DIR"/swtpm.pid)
    echo "Deleting TPM state dir: $TPM_STATE_DIR"
    rm -rf "$TPM_STATE_DIR"
    echo "Deleting TPM keys"
    rm -rf "$TRUSTED_TPM_KEYS_DIR"
    rm -rf "$WORK_DIR/ak.ctx"
}

generate_ak() {
    echo "Generating TPM Attestation Key at persistent handle 0x81010002..."
    
    mkdir -p "$TRUSTED_TPM_KEYS_DIR"
    # Create an AK using the EK context at 0x81010001
    tpm2_createak -C 0x81010001 -c "$WORK_DIR/ak.ctx" -G rsa -g sha256 -s rsassa -u "$TRUSTED_TPM_KEYS_DIR/ak.pub" -f pem
    
    # Persist AK at handle 0x81010002
    tpm2_evictcontrol -c "$WORK_DIR/ak.ctx" 0x81010002 -T device:/dev/tpm0
    
    echo "AK created and persisted at handle 0x81010002"
    
}

# If $1 is setup, run setup; if $1 is cleanup, run cleanup
if [ "$1" == "setup" ]; then
    echo "Setting up swtpm..."
    setup_swtpm
    # Sleep for sometime for the swtpm to be properly initialized
    sleep 5
    generate_ak
    echo "swtpm setup complete."
elif [ "$1" == "cleanup" ]; then
    echo "Cleaning up swtpm..."
    stop_swtpm
    echo "swtpm cleanup complete."
else
    echo "Usage: $0 {setup|cleanup}"
    exit 1
fi


