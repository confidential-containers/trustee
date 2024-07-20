FROM rust:latest as builder
ARG ARCH=x86_64
ARG HTTPS_CRYPTO=rustls
ARG ALIYUN=false

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y protobuf-compiler git

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=coco-as-grpc HTTPS_CRYPTO=${HTTPS_CRYPTO} POLICY_ENGINE=opa ALIYUN=${ALIYUN} && \
    make install-kbs

FROM ubuntu:22.04

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
