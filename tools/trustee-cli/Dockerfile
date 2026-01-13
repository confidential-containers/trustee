# rust:1.90.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c \
    AS builder
ARG ARCH=x86_64
ARG ALIYUN=false

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    gpg \
    gnupg-agent \
    git \
    sudo

RUN if [ "${ARCH}" = "aarch64" ]; then apt-get install -y libc-bin; fi

RUN apt-get install -y --no-install-recommends \
    libclang-dev \
    libprotobuf-dev \
    libssl-dev \
    make \
    perl \
    pkg-config \
    protobuf-compiler \
    wget \
    clang \
    cmake

# Build and Install trustee-cli
WORKDIR /usr/src/trustee
COPY . .

RUN cd tools/trustee-cli && make ARCH=${ARCH} && make ARCH=${ARCH} install

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

COPY --from=builder /usr/local/bin/trustee /usr/local/bin/trustee
