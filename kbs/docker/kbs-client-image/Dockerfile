# Keep the Rust version aligned with rust-toolchain.toml.
FROM docker.io/library/rust:1.95.0@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder

# Comma-separated attesters; sample-attester (or empty) needs no Cargo features.
ARG attesters=sample-attester

# Match NVIDIA's nv-attestation-sdk-sys/Cargo.toml at the SDK revision in
# Trustee's Cargo.lock; also check the native SDK's CMakeLists.txt version.
ARG NVAT_VERSION=2.0.0

ENV CUDA_KEYRING_VERSION=1.1-1 \
    CUDA_KEYRING_SHA256=d2a6b11c096396d868758b86dab1823b25e14d70333f1dfa74da5ddaf6a06dba \
    NVAT_USE_SYSTEM_LIB=1

# Install libnvat-dev packages if nvidia-attester is selected
# Install libtss2-dev packages if az/tpm-attester is selected
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential clang cmake curl git libclang-dev libssl-dev \
        pkg-config protobuf-compiler && \
    case ",$attesters," in \
        *,nvidia-attester,*|*,all-attesters,*) \
            test "$(dpkg --print-architecture)" = amd64 && \
            apt-get install -y --no-install-recommends curl libstdc++6 zlib1g && \
            curl -fsSL -o /tmp/cuda-keyring.deb \
                "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_${CUDA_KEYRING_VERSION}_all.deb" && \
            echo "$CUDA_KEYRING_SHA256  /tmp/cuda-keyring.deb" | sha256sum --check --strict - && \
            dpkg -i /tmp/cuda-keyring.deb && \
            # Allow NVIDIA SHA-1 keys, matching the KBS builder.
            mkdir -p /etc/crypto-policies/back-ends && \
            printf '[hash_algorithms]\nsha1.second_preimage_resistance = 2028-02-01\n' > /etc/crypto-policies/back-ends/apt-sequoia.config && \
            apt-get update && \
            apt-get install -y --no-install-recommends \
                "libnvat-dev=${NVAT_VERSION}.*" && \
            apt-get purge -y cuda-keyring && \
            rm /tmp/cuda-keyring.deb ;; \
    esac && \
    case ",$attesters," in \
        *,az-*-attester,*|*,tpm-attester,*|*,all-attesters,*) \
            apt-get install -y --no-install-recommends libtss2-dev ;; \
    esac && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/kbs
COPY . .

# Sample support is unconditional - filter out sample-attester from Cargo passed features
RUN features="$(printf '%s' "$attesters" | sed 's/,sample-attester//g; s/sample-attester,//g;')" && \
    if [ -z "$features" ] || [ "$features" = sample-attester ]; then \
        make -C kbs cli CLI_FEATURES=sample_only; \
    else \
        make -C kbs cli ATTESTER="$features"; \
    fi

FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS runtime

ARG attesters=sample-attester
ARG NVAT_VERSION=2.0.0

ENV CUDA_KEYRING_VERSION=1.1-1 \
    CUDA_KEYRING_SHA256=d2a6b11c096396d868758b86dab1823b25e14d70333f1dfa74da5ddaf6a06dba

# Install libnvat packages if nvidia-attester is selected
# Install libcurl packages if se-attester is selected
# Install libtss2 packages if az/tpm-attester is selected
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3t64 && \
    case ",$attesters," in \
        *,nvidia-attester,*|*,all-attesters,*) \
            test "$(dpkg --print-architecture)" = amd64 && \
            apt-get install -y --no-install-recommends curl libstdc++6 zlib1g && \
            curl -fsSL -o /tmp/cuda-keyring.deb \
                "https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_${CUDA_KEYRING_VERSION}_all.deb" && \
            echo "$CUDA_KEYRING_SHA256  /tmp/cuda-keyring.deb" | sha256sum --check --strict - && \
            dpkg -i /tmp/cuda-keyring.deb && \
            apt-get update && \
            apt-get install -y --no-install-recommends \
                "libnvat=${NVAT_VERSION}.*" && \
            apt-get purge -y curl cuda-keyring && \
            rm /tmp/cuda-keyring.deb ;; \
    esac && \
    case ",$attesters," in \
        *,se-attester,*|*,all-attesters,*) \
            apt-get install -y --no-install-recommends libcurl4t64 ;; \
    esac && \
    case ",$attesters," in \
        *,az-*-attester,*|*,tpm-attester,*|*,all-attesters,*) \
            apt-get install -y --no-install-recommends \
                libtss2-esys-3.0.2-0 libtss2-tctildr0 libtss2-tcti-device0 ;; \
    esac && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/kbs/target/release/kbs-client /usr/local/bin/kbs-client
