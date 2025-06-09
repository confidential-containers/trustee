FROM docker.io/library/rust:1.85.1 AS builder
ARG ARCH=x86_64

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt install -y pkg-config libssl-dev git sudo

ENV OS_ARCH=${ARCH}
RUN if [ $(uname -m) != ${ARCH} ]; then \
    OS_ARCH=$(echo $OS_ARCH | sed s/x86_64/amd64/); \
    OS_ARCH=$(echo $OS_ARCH | sed s/aarch64/arm64/); \
    dpkg --add-architecture ${OS_ARCH}; \
    apt-get update; \
    apt-get install -y libssl-dev:${OS_ARCH}; fi

# Build KBS Client
RUN cd kbs && make ARCH=${ARCH} cli-static-linux && \
    cp ../target/${ARCH}-unknown-linux-gnu/release/kbs-client /

# Export view.txt
FROM scratch AS export
COPY --from=builder /kbs-client .
