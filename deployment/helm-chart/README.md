# Trustee Helm Chart

A Helm chart for deploying the Confidential Containers (CoCo) Trustee stack on Kubernetes. This chart includes Key Broker Service (KBS), Attestation Service (AS), and Reference Value Provider Service (RVPS).

## Introduction

This chart deploys the complete Trustee stack, which provides:
- **KBS (Key Broker Service)**: Manages and distributes secrets to workloads after attestation
- **AS (Attestation Service)**: Performs attestation verification and issues attestation tokens
- **RVPS (Reference Value Provider Service)**: Stores and provides reference values for attestation verification

## Architecture

The chart deploys three StatefulSets:
- `kbs`: Key Broker Service
- `attestation-service`: Attestation Service
- `reference-value-provider-service`: Reference Value Provider Service

All services use StatefulSets with persistent storage to maintain state across pod restarts.

### Design Decision: StatefulSet vs Deployment

Currently, all services are deployed as StatefulSets because **compute and storage are not decoupled**. The services require direct access to persistent storage volumes, which makes StatefulSets the appropriate choice for maintaining stable storage identities and ordered pod management.

> [!NOTE]
> There is an [open issue](https://github.com/confidential-containers/trustee/issues/1092) tracking the decoupling of compute and storage. Once this is implemented, we may migrate to Deployments with external storage backends, which would provide better scalability and flexibility.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- A Kubernetes cluster with a default StorageClass (or specify a custom one)
- For production deployments, ensure you have proper RBAC permissions

## Installation

### Quick Start

```bash
# The PWD should be root of trustee project
# Install with default values
helm install trustee ./deployment/helm-chart

# Install to a specific namespace
helm install trustee ./deployment/helm-chart --namespace coco-trustee --create-namespace
```

### Verify Installation

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=trustee

# Check services
kubectl get svc -l app.kubernetes.io/name=trustee

# Check StatefulSets
kubectl get statefulsets -l app.kubernetes.io/name=trustee
```

## Configuration

The following table lists the configurable parameters and their default values:

### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `log_level` | Log level for all services | `info` |

### KBS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `kbs.replicaCount` | Number of KBS replicas | `1` |
| `kbs.image.repository` | KBS image repository | `ghcr.io/confidential-containers/staged-images/kbs-grpc-as` |
| `kbs.image.tag` | KBS image tag | `latest` |
| `kbs.service.type` | KBS service type | `LoadBalancer` |
| `kbs.service.port` | KBS service port | `8080` |
| `kbs.userKeysSecretName` | Secret name for user keys (empty for auto-generation) | `""` |
| `kbs.autoGenerateKeys` | Enable auto-generation of keys via initContainer | `true` |
| `kbs.storage.enabled` | Enable persistent storage for KBS | `true` |
| `kbs.storage.size` | Storage size | `1Gi` |
| `kbs.storage.storageClass` | Storage class name | `standard` |
| `kbs.storage.accessMode` | Access mode | `ReadWriteOnce` |

### AS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `as.replicaCount` | Number of AS replicas | `1` |
| `as.image.repository` | AS image repository | `ghcr.io/confidential-containers/staged-images/coco-as-grpc` |
| `as.image.tag` | AS image tag | `latest` |
| `as.service.type` | AS service type | `ClusterIP` |
| `as.service.port` | AS service port | `50004` |
| `as.storage.enabled` | Enable persistent storage for AS | `true` |
| `as.storage.size` | Storage size | `1Gi` |
| `as.storage.storageClass` | Storage class name | `standard` |
| `as.storage.accessMode` | Access mode | `ReadWriteOnce` |

### RVPS Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `rvps.replicaCount` | Number of RVPS replicas | `1` |
| `rvps.image.repository` | RVPS image repository | `ghcr.io/confidential-containers/staged-images/rvps` |
| `rvps.image.tag` | RVPS image tag | `latest` |
| `rvps.service.type` | RVPS service type | `ClusterIP` |
| `rvps.service.port` | RVPS service port | `50003` |
| `rvps.storage.enabled` | Enable persistent storage for RVPS | `true` |
| `rvps.storage.size` | Storage size | `1Gi` |
| `rvps.storage.storageClass` | Storage class name | `standard` |
| `rvps.storage.accessMode` | Access mode | `ReadWriteOnce` |

## Keys and Certs

Trustee needs keys to sign attestation token, and also for KBS authentication.

### Auto-Generation (Default)

By default, the chart automatically generates all required keys using an initContainer:

```yaml
kbs:
  userKeysSecretName: ""  # Empty = auto-generate
  autoGenerateKeys: true
```

The initContainer generates:
- `private.key` and `public.pub` (ED25519 keys for KBS authentication)
- `ca.key` and `ca-cert.pem` (RSA 2048 CA certificate for token signing)
- `token.key`, `token-cert.pem`, and `token-cert-chain.pem` (EC prime256v1 token keys for attestation token signing)

**Note**: With auto-generation, keys are stored in an `emptyDir` volume and will be regenerated on pod restart. This is suitable for development/testing environments.

### Using Existing Keys (Production)

For production deployments, provide keys via a Kubernetes Secret:

1. Create a Secret with all required key files:

```bash
kubectl create secret generic kbs-user-keys \
  --from-file=private.key=./private.key \
  --from-file=public.pub=./public.pub \
  --from-file=token.key=./token.key \
  --from-file=token-cert.pem=./token-cert.pem \
  --from-file=token-cert-chain.pem=./token-cert-chain.pem \
  --from-file=ca.key=./ca.key \
  --from-file=ca-cert.pem=./ca-cert.pem
```

2. Configure the chart to use the Secret:

```yaml
kbs:
  userKeysSecretName: "kbs-user-keys"
  autoGenerateKeys: true  # Can remain true, will be ignored when Secret is provided
```

## Storage Configuration

All services support persistent storage via PersistentVolumeClaims (PVCs). Storage is enabled by default.

### Disable Persistent Storage

To use ephemeral storage (emptyDir) instead:

```yaml
kbs:
  storage:
    enabled: false

as:
  storage:
    enabled: false

rvps:
  storage:
    enabled: false
```

### Custom Storage Configuration

```yaml
kbs:
  storage:
    enabled: true
    size: 10Gi
    storageClass: fast-ssd
    accessMode: ReadWriteOnce
```

## Configuration Files

Configuration files are stored as templates in the `files/` directory:
- `as-config.json.template`: Attestation Service configuration
- `kbs-config.toml.template`: KBS configuration
- `rvps.json.template`: RVPS configuration
- `sgx_default_qcnl.conf`: Intel SGX/TDX configuration

These templates support Helm template syntax for dynamic configuration. You can modify these files to customize the deployment.
