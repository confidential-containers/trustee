# Copyright (c) 2023 by Alibaba.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

FROM rust:latest as builder

WORKDIR /usr/src/rvps

COPY . .

RUN apt-get update && apt-get install protobuf-compiler -y

RUN cargo install --bin rvps --path attestation-service/rvps

FROM debian

LABEL org.opencontainers.image.source="https://github.com/confidential-containers/attestation-service"

COPY --from=builder /usr/local/cargo/bin/rvps /usr/local/bin/rvps

CMD ["rvps", "--socket", "0.0.0.0:50003"]

VOLUME /opt/confidential-containers/attestation-service/reference_values/

EXPOSE 50003