FROM docker.io/library/rust:1.85.1 AS builder
ARG ARCH=x86_64

WORKDIR /usr/src/trustee
COPY . .

RUN apt-get update && apt install -y pkg-config libssl-dev git sudo

ENV OS_ARCH=${ARCH}
RUN if [ $(uname -m) != ${ARCH} ]; then \
    OS_ARCH=$(echo $OS_ARCH | sed s/x86_64/amd64/); \
    OS_ARCH=$(echo $OS_ARCH | sed s/aarch64/arm64/); \
    dpkg --add-architecture ${OS_ARCH}; \
    apt-get update; \
    apt-get install -y libssl-dev:${OS_ARCH}; fi

# Build Trustee CLI
RUN cargo build \
    -p trustee-cli \
    --target=${ARCH}-unknown-linux-gnu \
    --config "target.${ARCH}-unknown-linux-gnu.rustflags = '-C target-feature=+crt-static'" \
    --locked \
    --release && \
    cp target/${ARCH}-unknown-linux-gnu/release/trustee /

# Export view.txt
FROM scratch AS export
COPY --from=builder /trustee .

