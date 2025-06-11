ARG RUST_TOOLCHAIN_VERSION=1.85.1

FROM --platform=$BUILDPLATFORM docker.io/library/rust:${RUST_TOOLCHAIN_VERSION} AS builder
ARG ALIYUN=false

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y git

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=intel-trust-authority-as ALIYUN=${ALIYUN} && \
    make install-kbs

FROM ubuntu:22.04

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
