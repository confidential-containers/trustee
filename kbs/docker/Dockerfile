# rust:1.95.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 \
    AS builder
ARG ARCH=x86_64
ARG ALIYUN=false
ARG VAULT=true
ARG GCP=false
ARG AWS=false
ARG EXTERNAL_PLUGIN=true

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    gpg \
    gnupg-agent \
    git \
    sudo

RUN if [ "${ARCH}" = "aarch64" ]; then apt-get install -y libc-bin; fi

ARG DCAP_VERSION=1_27_100
RUN if [ "${ARCH}" = "x86_64" ]; then curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
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

# Build and install libnvat from source
ARG NVAT=true
ARG NVAT_VERSION=2026.03.02
ENV NVAT_USE_SYSTEM_LIB=1
ENV LIBRARY_PATH=/usr/local/lib
RUN mkdir -p /opt/nvat-lib && if [ "${ARCH}" = "x86_64" ] && [ "${NVAT}" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends cmake pkg-config libxml2-dev zlib1g-dev && \
    git clone --depth=1 --branch "${NVAT_VERSION}" https://github.com/NVIDIA/attestation-sdk /tmp/attestation-sdk && \
    cmake -S /tmp/attestation-sdk/nv-attestation-sdk-cpp -B /tmp/attestation-sdk/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /tmp/attestation-sdk/build --parallel "$(nproc)" && \
    cmake --install /tmp/attestation-sdk/build && \
    ln -sf /usr/local/include/nvat.h /usr/include/nvat.h && \
    cp -a /usr/local/lib/libnvat.so* /opt/nvat-lib/ && \
    ldconfig && \
    rm -rf /tmp/attestation-sdk; fi

# Build and Install KBS
WORKDIR /usr/src/trustee
COPY . .

RUN cd kbs && make AS_FEATURE=coco-as-builtin FEATURES=pkcs11 ALIYUN=${ALIYUN} ARCH=${ARCH} VAULT=${VAULT} GCP=${GCP} AWS=${AWS} EXTERNAL_PLUGIN=${EXTERNAL_PLUGIN} NVAT=${NVAT} && \
    make ARCH=${ARCH} install-kbs

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9
ARG ARCH=x86_64

WORKDIR /tmp

ARG DCAP_VERSION=1_27_100
RUN apt-get update && \
    apt-get install -y \
    curl \
    gnupg \
    gnupg-agent && \
    if [ "${ARCH}" = "x86_64" ]; then curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    curl -sSLf https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/99dcap_${DCAP_VERSION}_noble_custom_version.cfg | \
    tee -a /etc/apt/preferences.d/99dcap && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify \
    libtss2-dev \
    libtss2-tctildr0 \
    libtss2-esys-3.0.2-0 ; \
    fi && \
    apt clean all && \
    rm -rf /tmp/*

# Install libnvat
ARG NVAT=true
COPY --from=builder /opt/nvat-lib/ /usr/local/lib/
RUN if [ "${ARCH}" = "x86_64" ] && [ "${NVAT}" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends libxml2 && \
    ldconfig && \
    apt clean all && \
    rm -rf /var/lib/apt/lists/* /tmp/*; fi

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
