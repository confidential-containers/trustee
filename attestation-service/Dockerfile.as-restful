# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM rust:latest as builder
ARG ARCH=x86_64

WORKDIR /usr/src/attestation-service
COPY . .

# Install TPM Build Dependencies
RUN apt-get update && apt-get install -y protobuf-compiler clang libtss2-dev

# Install TDX Build Dependencies
RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y libsgx-dcap-quote-verify-dev; fi

# Build and Install RESTful attestation-service
RUN cargo install --path attestation-service --bin restful-as --features restful-bin --locked

FROM ubuntu:22.04
ARG ARCH=x86_64

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/attestation-service"

# Install TDX Runtime Dependencies
RUN apt-get update && apt-get install curl gnupg openssl -y && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN if [ "${ARCH}" = "x86_64" ]; then curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*; fi

# Copy TPM Runtime Dependencies
COPY --from=builder /usr/lib/${ARCH}-linux-gnu/libtss* /usr/lib/${ARCH}-linux-gnu

COPY --from=builder /usr/local/cargo/bin/restful-as /usr/local/bin/restful-as

COPY ./attestation-service/config.json /etc/config.json

VOLUME /opt/confidential-containers/attestation-service

CMD ["restful-as", "--socket", "0.0.0.0:8080", "--config-file", "/etc/config.json"]

EXPOSE 8080