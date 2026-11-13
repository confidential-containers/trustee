FROM --platform=${BUILDPLATFORM:-linux/amd64} docker.io/library/rust:1.99.0@sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90 AS builder
ARG BUILDPLATFORM=linux/amd64
ARG ARCH=x86_64
ARG ALIYUN=false
ARG NEBULA_CA_PLUGIN=false
ARG NEBULA_VERSION=v1.9.5
ARG SPIRE_PLUGIN=true
ARG VAULT=true
ARG EXTERNAL_PLUGIN=true

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y protobuf-compiler git sudo cmake clang

ENV OS_ARCH=${ARCH}
RUN if [ $(uname -m) != ${ARCH} ]; then \
    OS_ARCH=$(echo $OS_ARCH | sed s/x86_64/amd64/); \
    OS_ARCH=$(echo $OS_ARCH | sed s/aarch64/arm64/); \
    dpkg --add-architecture ${OS_ARCH}; \
    apt-get update; \
    apt-get install -y libssl-dev:${OS_ARCH}; fi

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=coco-as-grpc ALIYUN=${ALIYUN} ARCH=${ARCH} NEBULA_CA_PLUGIN=${NEBULA_CA_PLUGIN} SPIRE_PLUGIN=${SPIRE_PLUGIN} VAULT=${VAULT} EXTERNAL_PLUGIN=${EXTERNAL_PLUGIN} && \
    make ARCH=${ARCH} install-kbs

# Download and install Nebula
RUN if [ "${NEBULA_CA_PLUGIN}" = "true" ]; then \
       curl -fSLO https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-$(echo ${BUILDPLATFORM:-linux/amd64}} | sed 's/\//-/').tar.gz && \
       tar -C /usr/local/bin -xzf nebula-$(echo "${BUILDPLATFORM:-linux/amd64}}" | sed 's/\//-/').tar.gz; \
    else \
       touch /usr/local/bin/nebula-cert-dummy; \
    fi

FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
COPY --from=builder /usr/local/bin/nebula-cert* /usr/local/bin/nebula-cert
RUN rm -rf /usr/local/bin/nebula-cert-dummy
