# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.67 as builder

WORKDIR /usr/src/attestation-service
COPY . .

# Install golang
RUN wget https://go.dev/dl/go1.20.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

RUN apt-get update && apt install -y protobuf-compiler clang

# Install TDX Build Dependencies
RUN curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y libtdx-attest-dev libsgx-dcap-quote-verify-dev

# Build and Instll gRPC attestation-service
RUN cargo install --bin grpc-as --no-default-features --features="rvps-native rvps-grpc tokio/rt-multi-thread all-verifier" --path .


FROM ubuntu:20.04

# Install TDX Runtime Dependencies
RUN apt-get update && apt-get install curl gnupg -y && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

RUN curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
    rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

COPY --from=builder /usr/local/cargo/bin/grpc-as /usr/local/bin/grpc-as

VOLUME /opt/confidential-containers/attestation-service

CMD ["grpc-as", "--socket", "0.0.0.0:50004"]

EXPOSE 50004