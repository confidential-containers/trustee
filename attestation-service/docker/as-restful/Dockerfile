# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

# rust:1.95.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 \
    AS builder
ARG ARCH=x86_64
ARG VERIFIER=all-verifier

WORKDIR /usr/src/attestation-service
COPY . .

# Install TPM Build Dependencies
RUN apt-get update && apt-get install -y protobuf-compiler clang libtss2-dev cmake

# Install TDX Build Dependencies
ARG DCAP_VERSION=1_27_100
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install --no-install-recommends -y libsgx-dcap-quote-verify-dev; fi

# Install libnvat from NVIDIA's apt repository
ARG NVAT_VERSION=2.0.0
ENV NVAT_USE_SYSTEM_LIB=1
RUN mkdir -p /opt/nvat-lib && if [ "${ARCH}" = "x86_64" ]; then \
    curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb && \
    dpkg -i /tmp/cuda-keyring.deb && \
    # Allow NVIDIA SHA-1 keys
    mkdir -p /etc/crypto-policies/back-ends && \
    printf '[hash_algorithms]\nsha1.second_preimage_resistance = 2028-02-01\n' > /etc/crypto-policies/back-ends/apt-sequoia.config && \
    apt-get update && apt-get install --no-install-recommends -y "libnvat-dev=${NVAT_VERSION}*" && \
    cp -a /usr/lib/x86_64-linux-gnu/libnvat.so* /opt/nvat-lib/ && \
    rm -rf /tmp/cuda-keyring.deb; fi

# Build and Install RESTful attestation-service
RUN if [ "$(uname -m)" != "${ARCH}" ]; then \
    export GCC_PACKAGE="gcc-${ARCH}-linux-gnu"; \
    export GCC_COMPILER="${ARCH}-linux-gnu-gcc"; \
    export RUSTC_TARGET="${ARCH}-unknown-linux-gnu"; \
    export TARGET_FLAG="--target ${RUSTC_TARGET}"; \
    export RUSTFLAGS_ARGS=" -C linker=${GCC_COMPILER}"; \
    export RUSTFLAGS="${RUSTFLAGS_ARGS}"; \
    apt-get install -y ${GCC_PACKAGE}; \
    rustup target add ${RUSTC_TARGET}; fi; \
    cargo install --path attestation-service --bin restful-as --features restful-bin,${VERIFIER},nvidia-nvat --locked ${TARGET_FLAG}

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

ARG ARCH=x86_64
ARG VERIFIER=all-verifier

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/tree/main/attestation-service"

# Install Openssl Suites
RUN apt-get update && apt-get install openssl -y && \
    apt install --reinstall ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install TDX Runtime Dependencies
ARG DCAP_VERSION=1_27_100
RUN if [ "${ARCH}" = "x86_64" ] && ( [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "tdx-verifier" ] ); \
    then apt-get update && apt-get install curl gnupg -y && \
    curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install --no-install-recommends -y libsgx-dcap-quote-verify && \
    apt-get remove curl gnupg -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Install TPM Runtime Dependencies
RUN if [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "az-snp-vtpm-verifier" ] || [ "${VERIFIER}" = "az-tdx-vtpm-verifier" ]; \
    then apt-get update && apt-get install libtss2-dev -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Install libnvat
COPY --from=builder /opt/nvat-lib/ /usr/local/lib/
RUN if [ "${ARCH}" = "x86_64" ]; then \
    apt-get update && apt-get install --no-install-recommends -y libcurl4 libxml2 libxmlsec1-openssl && \
    ldconfig && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

COPY --from=builder /usr/local/cargo/bin/restful-as /usr/local/bin/restful-as

COPY ./attestation-service/config.json /etc/config.json

VOLUME /opt/confidential-containers/attestation-service

CMD ["restful-as", "--socket", "0.0.0.0:8080", "--config-file", "/etc/config.json"]

EXPOSE 8080
