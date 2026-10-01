# rust:1.95.0
FROM docker.io/library/rust@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 \
    AS builder
ARG ALIYUN=false
ARG VAULT=false
ARG EXTERNAL_PLUGIN=true

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y git cmake protobuf-compiler libprotobuf-dev

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=intel-trust-authority-as ALIYUN=${ALIYUN} VAULT=${VAULT} EXTERNAL_PLUGIN=${EXTERNAL_PLUGIN} && \
    make install-kbs

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
