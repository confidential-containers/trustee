# Create an image with kbs-client
# Based on kbs/docker/kbs-client-image/Dockerfile
FROM docker.io/library/rust:1.80.0 AS builder

WORKDIR /usr/src/kbs
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev git sudo
RUN cd kbs && make cli-static-linux && \
    cp ../target/$(uname -m)-unknown-linux-gnu/release/kbs-client /


# Create a 2nd image. The other will be discarded.
# Copy in the kbs-client that we just built, add some utilities and nebula
FROM ubuntu:22.04
COPY --from=builder /kbs-client /usr/local/bin/kbs-client

ARG BUILDPLATFORM=linux/amd64
ARG NEBULA_VERSION=v1.9.5

# install some useful tools
RUN apt-get update
RUN apt install -y \
  curl \
  jq \
  iputils-ping \
  iproute2
RUN echo no | apt-get install -y iperf3

# Download and install Nebula
RUN \
  curl -fSLO https://github.com/slackhq/nebula/releases/download/${NEBULA_VERSION}/nebula-$(echo ${BUILDPLATFORM} | sed 's/\//-/').tar.gz && \
  tar -C /usr/local/bin -xzf nebula-$(echo "${BUILDPLATFORM}" | sed 's/\//-/').tar.gz

RUN mkdir -p /opt/nebula/config
RUN mkdir -p /opt/nebula/creds
COPY kbs/docker/lighthouse/assets/lighthouse-config.yaml /opt/nebula/config
COPY kbs/docker/lighthouse/assets/start-lighthouse.sh /usr/local/bin
