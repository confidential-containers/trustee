FROM rust:1.76.0 AS builder
ARG ARCH=x86_64

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y pkg-config libssl-dev git sudo

# Build KBS Client
RUN cd kbs && make ARCH=${ARCH} cli-static-linux && \
    cp ../target/${ARCH}-unknown-linux-gnu/release/kbs-client /

# Export view.txt
FROM scratch AS export
COPY --from=builder /kbs-client .
