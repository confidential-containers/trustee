# rust:1.90.0
FROM docker.io/library/rust@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c \
    AS builder
ARG ALIYUN=false

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y git cmake

# Build and Install KBS
RUN cd kbs && make AS_FEATURE=intel-trust-authority-as ALIYUN=${ALIYUN} && \
    make install-kbs

# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
