#!/usr/bin/env bash
echo "ADD compile dependencies"

#ENV DEBIAN_FRONTEND=noninteractive
sudo sh -c 'curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor -o /usr/share/keyrings/intel-sgx.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" > /etc/apt/sources.list.d/intel-sgx.list'

sudo apt-get update 
sudo apt-get install -y --no-install-recommends \
    libclang-dev \
    libprotobuf-dev \
    libssl-dev \
    make \
    perl \
    pkg-config \
    protobuf-compiler \
    wget \
    clang \
    cmake \
    libtss2-dev 

echo "ADD SGX / TDX verifier"    
sudo apt-get install -y --no-install-recommends libsgx-dcap-quote-verify-dev

echo "ADD runtime softhsm for pcks11 module"
sudo apt install opensc -y --no-install-recommends
sudo apt-get install -y --no-install-recommends softhsm

echo "SETUP softhsm"
mkdir -p "$HOME/softhsm/tokens"
echo "directories.tokendir = $HOME/softhsm/tokens" > "$HOME/softhsm/softhsm2.conf"
echo 'export SOFTHSM2_CONF="$HOME/softhsm/softhsm2.conf"' >> ~/.bashrc
echo 'export SOFTHSM2_CONF="$HOME/softhsm/softhsm2.conf"' >> ~/.zshrc
export SOFTHSM2_CONF="$HOME/softhsm/softhsm2.conf"
softhsm2-util --init-token --free --label "Trustee pkcs11 test" --so-pin 12345678 --pin 12345678

echo 'default slot has been setup with so pin 12345678 and user pin 12345678'

