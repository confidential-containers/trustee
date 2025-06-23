FROM docker.io/library/rust:1.87.0 AS builder

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev git sudo

# Build KBS Client
RUN cd kbs && make cli-static-linux && \
    cp ../target/$(uname -m)-unknown-linux-gnu/release/kbs-client /

FROM ubuntu:22.04

COPY --from=builder /kbs-client /usr/local/bin/kbs-client
