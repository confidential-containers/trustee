FROM rust:slim as builder

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    gpg \
    gnupg-agent \
    git

RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | \
    tee /etc/apt/sources.list.d/intel-sgx.list && \
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
    libtss2-dev \
    libsgx-dcap-quote-verify-dev \
    libtdx-attest-dev

RUN wget https://go.dev/dl/go1.20.1.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Build and Install KBS
WORKDIR /usr/src/kbs
COPY . .

ARG KBS_FEATURES=coco-as-builtin,rustls,resource,opa
RUN cargo install --locked --path kbs/src/kbs --no-default-features --features ${KBS_FEATURES}

FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y \
    clang \
    curl \
    gnupg-agent

# Install TDX Runtime Dependencies
RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
    gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg
RUN echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    libsgx-dcap-default-qpl \
    libsgx-dcap-quote-verify \
    libtdx-attest \
    tpm2-tools

# Intel PCCS URL Configurations
# If you want the AS in KBS to connect to your customized PCCS for Intel TDX/SGX evidence verification,
# please modify this parameter.
# Default using localhost PCCS (Run in Host which the container land on).
ENV INTEL_PCCS_URL "https://localhost:8081/sgx/certification/v4/"
ENV INTEL_PCCS_USE_SECURE_CERT false

# Setup Intel PCCS URL
RUN sed -i "s|\"pccs_url\":.*$|\"pccs_url\":$INTEL_PCCS_URL,|" /etc/sgx_default_qcnl.conf; \
    sed -i "s/\"use_secure_cert\":.*$/\"use_secure_cert\":$INTEL_PCCS_USE_SECURE_CERT,/" /etc/sgx_default_qcnl.conf

COPY --from=builder /usr/local/cargo/bin/kbs /usr/local/bin/kbs
