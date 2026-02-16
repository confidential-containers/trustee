# AGENT.md

## Project Overview

The repo is a Rust workspace providing tools and components for attesting confidential guests
(Trusted Execution Environments) and delivering secrets to them. It is part of the
[Confidential Containers](https://github.com/confidential-containers) project.

The main components are:
- **KBS** (Key Broker Service) — remote attestation and secret delivery server (Relying Party)
- **Attestation Service (AS)** — verifies TEE evidence (Verifier)
- **RVPS** (Reference Value Provider Service) — manages reference values for evidence verification
- **KBS Client** / **Trustee CLI** — client tools for testing, configuration and key release

The sum of the above components is called "Trustee", it can be deployed as individual services
that are coupled via RPC or as a single all-in-one binary.

## Security Considerations

Remote attestation and secret delivery are security-sensitive operations. Changes to the
codebase should be made with due consideration of security implications, and new code should
be covered by comprehensive tests that validate security properties. We encourage coding
patterns that express invariant conditions in the type system, e.g. using a type state pattern
or newtypes to prevent misuse of APIs. Always consider the attack surface of new features and
strive to minimize it.

## API Stability

The project is packaged and distributed downstream. Trustee doesn't provide machine-enforcable
schemas for all its payloads and protocols yet, but we strive to avoid breakage for consumers
when iterating. If it's unavoidable, we point it out expclicitly in commit messages, so it
can be tracked and aggregated in release notes.

## Relationship to Guest Components

confidential-containers/guest-components is the counterpart to trustee that is running in a
TEE. It provides the attestation evidence and consumes secrets delivered by Trustee. The two
repositories are developed and released in tandem, but they are decoupled and can be used
independently. In the `kbs-client` crate we reference a revision of guest-components for
which we test and guarantee compatibility in any given revision of Trustee.

## Sample Verifiers

It's unlikely that local development will happen in a TEE that is able to produce genuine
attestation evidence. Therefore there are "sample" and a "sample-device" attester/verifier
pairs that can be used as dummy stubs for testing end-to-end flow in local  development and
testing. Any default policies that is shipped as part of the release should make sure to
reject these dummy evidences and release builds of attestation service should exclude the
sample verifier.

## Repository Structure

```
├── kbs/                        # Key Broker Service
│   ├── docker/                 # Dockerfiles
│   ├── docs/                   # KBS documentation
│   ├── config/                 # Kubernetes manifests
│   ├── test/                   # E2E tests, test data
│   └── Makefile
├── attestation-service/        # Attestation Service
│   ├── docker/                 # Dockerfiles
│   ├── tests/                  # integration tests, OPA policies, evidence templates
│   └── Makefile
├── rvps/                       # Reference Value Provider Service
│   ├── docker/                 # Dockerfile
│   └── Makefile
├── tools/
│   ├── kbs-client/             # KBS client library & CLI
│   └── trustee-cli/            # Unified Trustee CLI tool
│       └── Makefile
├── deps/                       # Shared library crates
│   ├── verifier/               # TEE verifier implementations
│   ├── policy-engine/          # OPA policy engine (regorus)
│   ├── key-value-storage/      # Storage abstraction (PostgreSQL, local)
│   └── eventlog/               # TCG event log parser
├── integration-tests/          # Workspace-level integration tests
├── protos/                     # Protocol Buffer definitions (attestation, reference)
├── hack/                       # Helper scripts (e2e.sh, release-helper.sh)
├── docker-compose.yml          # Full-stack local deployment
├── .github/workflows/          # CI/CD pipelines
└── .devcontainer/              # Dev container configurations
```

## Build & Development

### Prerequisites

- **Rust toolchain**: version pinned in `rust-toolchain.toml` (currently `1.90.0`)
- **Protobuf compiler** (`protoc`) for gRPC code generation
- **OpenSSL** development libraries
- **tpm2-tss** (for TPM verifier features)
- **libsgx-dcap-default-qpl** (for Intel SGX and TDX verifier features) installed from https://download.01.org/intel-sgx/.

### Building

Each component has its own `Makefile`. Common targets:

```bash
# KBS
make -C kbs build                 # Build KBS (default: background-check mode)
make -C kbs AS_TYPE=coco-as       # Select attestation service type
make -C kbs ALIYUN=true           # Enable Aliyun KMS backend
make -C kbs VAULT=true            # Enable HashiCorp Vault backend

# Attestation Service
make -C attestation-service build
make -C attestation-service grpc-as
make -C attestation-service restful-as

# RVPS
make -C rvps build

# Trustee CLI
make -C tools/trustee-cli build
```

Or build the entire workspace:

```bash
cargo build --workspace
```

### Feature Flags

Feature flags are heavily used to select TEE verifiers and backends:

- **Verifiers**: `tdx-verifier`, `sgx-verifier`, `snp-verifier`, `cca-verifier`,
  `csv-verifier`, `tpm-verifier`, `all-verifier`, `az-snp-vtpm-verifier`,
  `az-tdx-vtpm-verifier`, etc.
- **KBS modes**: `coco-as-builtin` (in-process AS), `coco-as-grpc` (remote gRPC AS),
  `intel-trust-authority-as`
- **KMS backends**: `aliyun`, `pkcs11`
- **Plugins**: `nebula-ca-plugin`, `vault`
- **Architecture-specific**: certain verifiers are gated to x86_64, aarch64, or s390x

### Testing

```bash
# Unit tests per crate
cargo test -p kbs
cargo test -p attestation-service
cargo test -p rvps
cargo test -p verifier

# Linting and formatting (per-component Makefiles)
make -C kbs lint                  # cargo clippy
make -C kbs format                # cargo fmt

# OPA policy validation
make -C attestation-service opa-check

# E2E tests
make -C kbs/test
make -C attestation-service/tests/e2e
```

### Docker Compose (Local Cluster)

```bash
docker-compose up -d
```

Starts: **setup** (cert generation) → **rvps** (:50003) → **as** (:50004) → **kbs** (:8080) → **keyprovider** (:50000)

## Architecture & Key Concepts

- **RATS model**: KBS acts as Relying Party, AS acts as Verifier, RVPS provides endorsements/reference values
- **gRPC**: AS and RVPS expose gRPC services defined in `protos/` (attestation.proto, reference.proto)
- **Policy engine**: OPA (Rego) policies via the `regorus` crate, used for attestation decisions
- **TEE support**: TDX, SGX, SNP, CCA, CSV, Hygon DCU, SE, NVIDIA GPU, TPM, Azure vTPM (SNP & TDX)
- **Target architectures**: x86_64, aarch64, s390x

## Code Conventions

- **Edition**: Rust 2021
- **Error handling**: `anyhow` for applications, `thiserror` for libraries
- **Async runtime**: `tokio` (full features)
- **Serialization**: `serde` / `serde_json` throughout
- **Logging**: `log` crate + `env_logger`, migrating toward `tracing` / `tracing-subscriber`
- **CLI parsing**: `clap` with derive macros
- **Testing**: `rstest` for parameterized tests, `serial_test` for tests requiring exclusive access
- **Formatting**: Always run `cargo fmt --all` on submissions before committing to ensure consistent code formatting
- **Linting**: Always run `cargo clippy --all-targets -- -D warnings` and fix all warnings and errors before committing

## CI/CD

Workflows live in `.github/workflows/`:
- **kbs-rust.yml** / **as-rust.yml** / **trustee-cli-rust.yml** — build & test on ubuntu-24.04 (+ ARM, s390x)
- **kbs-e2e.yml** / **as-e2e.yml** — end-to-end testing
- **build-*-image.yml** / **push-*-image-to-ghcr.yml** — container image builds & GHCR publishing
- **actionlint.yml** — workflow validation
- **link.yml** — broken link checks
- **scorecard.yaml** — OpenSSF scorecard
