FROM rust:latest as builder
ARG ARCH=x86_64
ARG HTTPS_CRYPTO=rustls

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y protobuf-compiler git

# Build and Install KBS
RUN cargo install --path kbs --bin kbs --no-default-features --features coco-as-grpc,resource,opa,${HTTPS_CRYPTO}

FROM ubuntu:22.04

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/trustee/kbs"

COPY --from=builder /usr/local/cargo/bin/kbs /usr/local/bin/kbs
