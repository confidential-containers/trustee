FROM docker.io/library/rust:1.99.1@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS builder

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev git sudo cmake

# Build KBS Client
RUN cd kbs && make cli-static-linux && \
    cp ../target/$(uname -m)-unknown-linux-gnu/release/kbs-client /

FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092

COPY --from=builder /kbs-client /usr/local/bin/kbs-client
