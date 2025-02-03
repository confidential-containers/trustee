# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM --platform=$BUILDPLATFORM docker.io/library/rust:latest AS builder
ARG BUILDPLATFORM=linux/amd64
ARG ARCH=x86_64
ARG VERIFIER=all-verifier

WORKDIR /usr/src/attestation-service
COPY . .

# Install TPM Build Dependencies
RUN apt-get update && apt-get install -y protobuf-compiler clang libtss2-dev

# Install TDX Build Dependencies
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y libsgx-dcap-quote-verify-dev; fi

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
    cargo install --path attestation-service --bin restful-as --features restful-bin,${VERIFIER} --locked ${TARGET_FLAG}

FROM ubuntu:22.04
ARG ARCH=x86_64
ARG VERIFIER=all-verifier

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/attestation-service"

# Install Openssl Suites
RUN apt-get update && apt-get install openssl -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

# Install TDX Runtime Dependencies
RUN if [ "${ARCH}" = "x86_64" ] && ( [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "tdx-verifier" ] ); \
    then apt-get update && apt-get install curl gnupg -y && \
    curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
    apt-get remove curl gnupg -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Install TPM Runtime Dependencies
RUN if [ "${VERIFIER}" = "all-verifier" ] || [ "${VERIFIER}" = "az-snp-vtpm-verifier" ] || [ "${VERIFIER}" = "az-tdx-vtpm-verifier" ]; \
    then apt-get update && apt-get install libtss2-dev -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

COPY --from=builder /usr/local/cargo/bin/restful-as /usr/local/bin/restful-as

COPY ./attestation-service/config.json /etc/config.json

VOLUME /opt/confidential-containers/attestation-service

CMD ["restful-as", "--socket", "0.0.0.0:8080", "--config-file", "/etc/config.json"]

EXPOSE 8080
