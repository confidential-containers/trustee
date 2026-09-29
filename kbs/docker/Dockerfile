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

# Install libnvat from NVIDIA's apt repository
ARG NVAT=true
ARG NVAT_VERSION=2.0.0
ENV NVAT_USE_SYSTEM_LIB=1
RUN mkdir -p /opt/nvat-lib && if [ "${ARCH}" = "x86_64" ] && [ "${NVAT}" = "true" ]; then \
    curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb && \
    dpkg -i /tmp/cuda-keyring.deb && \
    apt-get update && apt-get install --no-install-recommends -y "libnvat-dev=${NVAT_VERSION}*" && \
    cp -a /usr/lib/x86_64-linux-gnu/libnvat.so* /opt/nvat-lib/ && \
    rm -rf /tmp/cuda-keyring.deb; fi

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
    apt-get update && apt-get install -y --no-install-recommends libcurl4 libxml2 libxmlsec1-openssl && \
    ldconfig && \
    apt clean all && \
    rm -rf /var/lib/apt/lists/* /tmp/*; fi

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
