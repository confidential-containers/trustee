#!/bin/bash

set -euo pipefail

WORK_DIR="./work"
TPM_STATE_DIR="/tmp/tpmdir"

setup_swtpm() {
    sudo modprobe tpm_vtpm_proxy
    sudo mkdir -p "$TPM_STATE_DIR"

    sudo swtpm_setup --tpm2 \
                --tpmstate $TPM_STATE_DIR" \
                --createek --decryption \
                --create-ek-cert \
                --create-platform-cert \
                --pcr-banks - \
                --display

    sudo swtpm chardev --tpm2 \
                --tpmstate dir=$TPM_STATE_DIR" \
                --vtpm-proxy \
                --daemon \
                --log file=$TPM_STATE_DIR"/tpm.log,level=20 \
                --flags not-need-init
}

stop_swtpm() {
    sudo pkill swtpm

    sudo rm -rf "$TPM_STATE_DIR"
}

generate_ak() {
    echo "Generating TPM Attestation Key at persistent handle 0x81010002..."
    
    # Create an AK using the EK context at 0x81010001
    sudo tpm2_createak -C 0x81010001 -c "$WORK_DIR/ak.ctx" -G rsa -g sha256 -s rsassa -u "$WORK_DIR/ak.pub" -f pem
    
    # Persist AK at handle 0x81010002
    sudo tpm2_evictcontrol -c "$WORK_DIR/ak.ctx" 0x81010002
    
    echo "AK created and persisted at handle 0x81010002"
    
}

# If $1 is setup, run setup; if $1 is cleanup, run cleanup
if [ "$1" == "setup" ]; then
    echo "Setting up swtpm..."
    setup_swtpm
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


