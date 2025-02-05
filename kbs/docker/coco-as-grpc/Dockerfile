FROM --platform=$BUILDPLATFORM docker.io/library/rust:latest AS builder
ARG BUILDPLATFORM=linux/amd64
ARG ARCH=x86_64
ARG ALIYUN=false

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
RUN cd kbs && make AS_FEATURE=coco-as-grpc ALIYUN=${ALIYUN} ARCH=${ARCH} && \
    make ARCH=${ARCH} install-kbs

FROM ubuntu:22.04

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
