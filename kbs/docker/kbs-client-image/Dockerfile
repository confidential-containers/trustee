# ubuntu:24.04
FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS runtime

# Comma-separated attesters; sample-attester (or empty) needs no Cargo features.
ARG attesters=sample-attester

# Match NVIDIA's nv-attestation-sdk-sys/Cargo.toml at the SDK revision in
# Trustee's Cargo.lock; also check the native SDK's CMakeLists.txt version.
ARG NVAT_VERSION=2.0.0

ENV CUDA_KEYRING_VERSION=1.1-1 \
    CUDA_KEYRING_SHA256=d2a6b11c096396d868758b86dab1823b25e14d70333f1dfa74da5ddaf6a06dba

# Install libnvat packages if nvidia-attester is selected
# Install libcurl packages if se-attester is selected
# Install libtss2 packages if az/tpm-attester is selected
RUN case "$attesters" in \
        ,*|*,|*,,*|*[!a-z0-9,-]*) echo "Invalid comma-separated attesters: $attesters" >&2; exit 1 ;; \
    esac && \
    apt-get update && \
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
                libtss2-esys-3.0.2-0t64 libtss2-tctildr0t64 libtss2-tcti-device0t64 ;; \
    esac && \
    rm -rf /var/lib/apt/lists/*

FROM runtime AS builder

# Keep the default aligned with rust-toolchain.toml.
ARG RUST_VERSION=1.95.0
ARG RUSTUP_VERSION=1.29.3

ENV RUSTUP_SHA256_AMD64=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 \
    RUSTUP_SHA256_ARM64=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 \
    RUSTUP_SHA256_S390X=df1762614062280a326ac988019ed1f8ceebeafa5fac95164a7201ff10e31d4b

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    PATH=/usr/local/cargo/bin:${PATH} \
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

# Install rust and verify signing.
RUN case "$(dpkg --print-architecture)" in \
    amd64) rustup_arch=x86_64; rustup_sha256="$RUSTUP_SHA256_AMD64" ;; \
    arm64) rustup_arch=aarch64; rustup_sha256="$RUSTUP_SHA256_ARM64" ;; \
    s390x) rustup_arch=s390x; rustup_sha256="$RUSTUP_SHA256_S390X" ;; \
        *) echo "Unsupported Rust architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac && \
    curl --proto '=https' --tlsv1.2 -fsSL \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustup_arch}-unknown-linux-gnu/rustup-init" \
        -o /tmp/rustup-init && \
    echo "$rustup_sha256  /tmp/rustup-init" | sha256sum --check --strict - && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --profile minimal --default-toolchain "$RUST_VERSION" && \
    rm /tmp/rustup-init

WORKDIR /usr/src/kbs
COPY . .

# Sample support is unconditional - filter out sample-attester from Cargo passed features
RUN features="$(printf '%s' "$attesters" | sed 's/,sample-attester//g; s/sample-attester,//g;')" && \
    if [ -z "$features" ] || [ "$features" = sample-attester ]; then \
        make -C kbs cli CLI_FEATURES=sample_only; \
    else \
        make -C kbs cli ATTESTER="$features"; \
    fi

FROM runtime

COPY --from=builder /usr/src/kbs/target/release/kbs-client /usr/local/bin/kbs-client
