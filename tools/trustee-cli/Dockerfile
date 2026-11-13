FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/library/rust:1.99.0@sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90 AS builder
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

RUN if [ "${ARCH}" = "x86_64" ]; then curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | \
    tee /etc/apt/sources.list.d/intel-sgx.list; fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
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
    libtss2-dev && \
    if [ "${ARCH}" = "x86_64" ]; then apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify-dev; fi

# Build and Install trustee-cli
WORKDIR /usr/src/trustee
COPY . .

RUN cd tools/trustee-cli && make ARCH=${ARCH} && make ARCH=${ARCH} install

FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092
ARG ARCH=x86_64

WORKDIR /tmp

RUN apt-get update && \
    apt-get install -y \
    curl \
    gnupg \
    gnupg-agent && \
    if [ "${ARCH}" = "x86_64" ]; then curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify \
    libtss2-tctildr0 \
    libtss2-esys-3.0.2-0 ; \
    fi && \
    apt clean all && \
    rm -rf /tmp/*

COPY --from=builder /usr/local/bin/trustee /usr/local/bin/trustee
