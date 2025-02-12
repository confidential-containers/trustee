# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM --platform=$BUILDPLATFORM rust:latest AS builder
ARG BUILDPLATFORM=linux/amd64
ARG ARCH=x86_64

WORKDIR /usr/src/rvps

COPY . .

RUN apt-get update && apt-get install protobuf-compiler -y

RUN if [ "$(uname -m)" != "${ARCH}" ]; then \
    export GCC_PACKAGE="gcc-${ARCH}-linux-gnu"; \
    export GCC_COMPILER="${ARCH}-linux-gnu-gcc"; \
    export RUSTC_TARGET="${ARCH}-unknown-linux-gnu"; \
    export TARGET_FLAG="--target ${RUSTC_TARGET}"; \
    export RUSTFLAGS_ARGS=" -C linker=${GCC_COMPILER}"; \
    export RUSTFLAGS="${RUSTFLAGS_ARGS}"; \
    apt-get install -y ${GCC_PACKAGE}; \
    rustup target add ${RUSTC_TARGET}; fi; \
    cargo install --bin rvps --path rvps ${TARGET_FLAG}

FROM debian

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/rvps"

COPY --from=builder /usr/local/cargo/bin/rvps /usr/local/bin/rvps

CMD ["rvps"]

VOLUME /opt/confidential-containers/attestation-service/reference_values/

EXPOSE 50003
