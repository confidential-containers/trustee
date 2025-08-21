# rust:1.89.0
FROM --platform=${BUILDPLATFORM:-linux/amd64} \
    docker.io/library/rust@sha256:6e6d04bd50cd4c433a805c58c13f186a508c5b5417b9b61cae40ec28e0593c51 \
    AS builder
ARG BUILDPLATFORM=linux/amd64
ARG ARCH=x86_64
ARG ALIYUN=false
ARG NEBULA_CA_PLUGIN=false
ARG NEBULA_VERSION=v1.9.5

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y protobuf-compiler git sudo

ENV OS_ARCH=${ARCH}
RUN if [ $(uname -m) != ${ARCH} ]; then \
    OS_ARCH=$(echo $OS_ARCH | sed s/x86_64/amd64/); \
    OS_ARCH=$(echo $OS_ARCH | sed s/aarch64/arm64/); \
    dpkg --add-architecture ${OS_ARCH}; \
    apt-get update; \
    apt-get install -y libssl-dev:${OS_ARCH}; fi

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=coco-as-grpc ALIYUN=${ALIYUN} ARCH=${ARCH} NEBULA_CA_PLUGIN=${NEBULA_CA_PLUGIN} && \
    make ARCH=${ARCH} install-kbs

# Download and install Nebula
RUN if [ "${NEBULA_CA_PLUGIN}" = "true" ]; then \
       curl -fSLO https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-$(echo ${BUILDPLATFORM:-linux/amd64}} | sed 's/\//-/').tar.gz && \
       tar -C /usr/local/bin -xzf nebula-$(echo "${BUILDPLATFORM:-linux/amd64}}" | sed 's/\//-/').tar.gz; \
    else \
       touch /usr/local/bin/nebula-cert-dummy; \
    fi

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
COPY --from=builder /usr/local/bin/nebula-cert* /usr/local/bin/nebula-cert
RUN rm -rf /usr/local/bin/nebula-cert-dummy
