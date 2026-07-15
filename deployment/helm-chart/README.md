# Trustee Helm Chart

Helm chart for [Confidential Containers](https://github.com/confidential-containers) **Trustee** on Kubernetes: **KBS**, **gRPC AS**, and **RVPS**, with optional bundled **PostgreSQL** ([Bitnami chart](https://artifacthub.io/packages/helm/bitnami/postgresql)) and **Valkey** ([Bitnami chart](https://artifacthub.io/packages/helm/bitnami/valkey), a Redis-protocol store for KBS sessions). KBS is wired to remote **`coco_as_grpc`** Attestation Service.

## Install

**Requirements**: Kubernetes 1.19+, Helm 3. If bundled Postgres is needed (when **`storageBackend.type: Postgres`** or **`sessionStorageType: Postgres`**), the Bitnami subchart uses PVC-backed storage, so your cluster must provide a usable **StorageClass** (or you must bind an existing claim).

From the **repository root**:

```bash
helm dependency update ./deployment/helm-chart

helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace
```

Wait for workloads, then port-forward KBS (default HTTP **8080**). The internal ClusterIP Service is **`<Helm fullname>-kbs`** (with the install command below, **`trustee-kbs`**):

```bash
kubectl get pods -n coco-trustee -w
kubectl port-forward -n coco-trustee svc/trustee-kbs 8080:8080
```

Uninstall the release:

```bash
helm uninstall trustee -n coco-trustee
```

> [!NOTE]
> When `secrets.useEphemeralGeneratedKeys` is `true` (default), a **post-delete** Helm hook removes the release-scoped `*-bootstrap-user-keys` Secret automatically.

## Typical scenarios

### Default: LocalFs storage

Same as **Install** above. If neither **`storageBackend.type`** nor **`sessionStorageType`** is **`Postgres`**, the chart does not deploy bundled Postgres; components use the default **`storageBackend`** (e.g. **LocalFs**).

### PostgreSQL as storage backend + in-memory KBS sessions

```bash
helm dependency update ./deployment/helm-chart

helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace \
  -f ./deployment/helm-chart/scenarios/postgres-backend.yaml
```

This enables the **Bitnami PostgreSQL** subchart (`postgresql.enabled: true`) and sets **`storageBackend.type: Postgres`**. KBS sessions stay in memory (`sessionStorageType: Memory`). Demo credentials default to `trustee` / `trustee` / `trustee` (override via `postgresql.auth.*`).

### External PostgreSQL

When an external Postgres service is used, set **`storageBackend.postgres.mode=external`**, pre-create a Secret with a **`POSTGRES_URL`** key, and point the chart at it:

```bash
kubectl create secret generic trustee-external-postgres -n coco-trustee \
  --from-literal=POSTGRES_URL='postgresql://user:password@postgres.example.com:5432/trustee?sslmode=require'

helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace \
  --set storageBackend.type=Postgres \
  --set storageBackend.postgres.mode=external \
  --set storageBackend.postgres.external.existingSecretName=trustee-external-postgres \
  --set storageBackend.postgres.external.existingSecretKey=POSTGRES_URL
```

When `storageBackend.postgres.mode=external`, the chart does **NOT** deploy the Bitnami subchart (`postgresql.enabled` stays `false`), even if Postgres is required by `storageBackend.type` or `sessionStorageType`.

### Valkey (Redis protocol) for KBS sessions

The KBS **`Redis`** session backend speaks the Redis wire protocol. The chart bundles **Valkey** (BSD-licensed) instead of Redis, whose license is no longer OSI-approved; any Redis-protocol-compatible service works. Storing sessions outside the KBS Pod allows running several KBS replicas.

```bash
helm dependency update ./deployment/helm-chart

helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace \
  -f ./deployment/helm-chart/scenarios/valkey-sessions.yaml
```

This enables the **Bitnami Valkey** subchart (`valkey.enabled: true`) and sets **`sessionStorageType: Redis`**. The chart writes the connection URL into a release-scoped Secret and injects it into KBS as **`REDIS_URL`**. The demo password defaults to `trustee` (override via `valkey.auth.password`). Sessions are short-lived, so the bundled Valkey runs `standalone` without a PVC by default (`valkey.primary.persistence.enabled: false`).

The default Valkey image is pulled from **docker.io**, where anonymous pulls are rate-limited. Override the image source to use a private mirror:

```bash
helm upgrade --install trustee ./deployment/helm-chart ... \
  -f ./deployment/helm-chart/scenarios/valkey-sessions.yaml \
  --set valkey.image.registry=mirror.example.com \
  --set valkey.image.repository=bitnami/valkey \
  --set valkey.image.tag=9.1.0
```

(A chart-wide `global.imageRegistry` is also honored by the Bitnami subcharts.)

### External Redis-compatible service

When an external Redis-compatible service is used, set **`storageBackend.redis.mode=external`**, pre-create a Secret with the connection URL, and point the chart at it:

```bash
kubectl create secret generic trustee-external-redis -n coco-trustee \
  --from-literal=REDIS_URL='redis://:password@redis.example.com:6379'

helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace \
  --set sessionStorageType=Redis \
  --set storageBackend.redis.mode=external \
  --set storageBackend.redis.external.existingSecretName=trustee-external-redis \
  --set storageBackend.redis.external.existingSecretKey=REDIS_URL
```

When `storageBackend.redis.mode=external`, the chart does **NOT** deploy the Valkey subchart (`valkey.enabled` stays `false`).

### Bring your own keys (BYOK)

Key material is controlled only by **`secrets.useEphemeralGeneratedKeys`**:

- **`true` (default):** a Helm **pre-install / pre-upgrade hook** Job generates ephemeral demo keys into a release-scoped Secret (name ends with **`bootstrap-user-keys`**). **`helm uninstall`** runs a **post-delete** hook that removes that Secret.
- **`false`:** you must **pre-create** a Kubernetes **`Secret`** in the target namespace, then set **`secrets.existingSecretName`** to that name. The bootstrap hook is **not** rendered.

When ephemeral generation is enabled, the hook uses:

- an `initContainer` (OpenSSL image) to generate keys into an `emptyDir`
- a `quay.io/kata-containers/kubectl` container to create the Secret from generated files

Both images are overridable via `bootstrapUserKeysJob.keygenImage.*` and `bootstrapUserKeysJob.kubectlImage.*`.

When ephemeral generation is disabled, the Secret must define these **data keys** (values are PEM text or base64-encoded PEM, same as any `kubectl create secret generic --from-file=...`):

| Secret key | Role |
|------------|------|
| **`KBS_ADMIN_PRIVATE_KEY`** / **`KBS_ADMIN_PUBKEY`** | KBS admin API Ed25519 keypair (used to sign admin JWTs). |
| **`KBS_ADMIN_TOKEN`** | Pre-signed admin bearer JWT for `kbs-client --admin-token-file` (generated by the bootstrap hook when ephemeral keys are enabled). |
| **`AS_TOKEN_SIGNING_PRIVATE_KEY`** | Attestation Service: sign attestation tokens. |
| **`AS_TOKEN_VERIFICATION_PUBLIC_KEY_CERT_CHAIN`** | AS: `x5c` / cert chain; KBS: trust anchor for token verification. |

The chart mounts that Secret on KBS and gRPC AS and **maps** those keys to in-container paths **`private.key`**, **`public.pub`**, **`token.key`**, **`token-cert-chain.pem`** under **`/opt/confidential-containers/kbs/user-keys`**.

Example (create Secret, then install):

```bash
kubectl create secret generic trustee-byok-keys -n coco-trustee \
  --from-file=KBS_ADMIN_PRIVATE_KEY=./admin.key.pem \
  --from-file=KBS_ADMIN_PUBKEY=./admin.pub.pem \
  --from-file=AS_TOKEN_SIGNING_PRIVATE_KEY=./token.key.pem \
  --from-file=AS_TOKEN_VERIFICATION_PUBLIC_KEY_CERT_CHAIN=./token-chain.pem

helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace \
  --set secrets.useEphemeralGeneratedKeys=false \
  --set secrets.existingSecretName=trustee-byok-keys
```

Or use **`scenarios/bring-your-own-keys.yaml`** (adjust Secret name / file paths in the comments there).

### IBM Secure Execution (s390x)

On **s390x**, the **IBM Secure Execution (SE)** verifier needs attestation materials at runtime. Because KBS talks to a **remote `coco_as_grpc` AS**, the verifier runs inside the **AS Pod**, so these materials must be mounted on **AS**, not KBS. (This differs from the builtin-AS kustomize overlay in `kbs/config/kubernetes/overlays/ibm-se`, which mounts them on KBS.)

The verifier reads materials from fixed paths under **`/run/confidential-containers/ibmse/`** (overridable via `SE_*` env vars; see `deps/verifier/src/se/README.md`). The chart mounts them from a **local node path** via a PersistentVolume / PersistentVolumeClaim — set **`as.verifier.se.credsDir`** to the directory on the node that contains the materials (equivalent to `IBM_SE_CREDS_DIR` used in the kustomize overlay), and **`as.verifier.se.nodeName`** to the name of that node.  The chart then creates a `local`-type PV + PVC and mounts the whole directory at `/run/confidential-containers/ibmse/` on the AS Pod.

| Material | Expected path under `credsDir` | Notes |
|----------|-------------------------------|-------|
| RSA measurement key pair | `rsa/encrypt_key.{pem,pub}` | Private key is **sensitive** — restrict node access. |
| Signing / intermediate certs | `certs/` | **Directory**; all files are read. |
| CRLs | `crls/` | **Directory**; all files are read. |
| Host Key Documents (HKD) | `hkds/` | **Directory**; all files are read. |
| SE image header | `hdr/hdr.bin` | Binary file. |
| Root CA (optional) | `root_ca.crt` | Single file. |

Set **`CERTS_OFFLINE_VERIFICATION=true`** (via `as.extraEnvVars`) to verify the HKD certificate chain offline. Do **not** set `SE_SKIP_CERTS_VERIFICATION=true` outside development — it disables HKD certificate chain verification.

```bash
# 1. Place all materials under a directory on the target s390x node, e.g.:
#    $IBM_SE_CREDS_DIR/{rsa/,certs/,crls/,hkds/,hdr/hdr.bin}
#    See deps/verifier/src/se/README.md for how to obtain the materials.

# 2. Install, pointing the chart at the node and directory:
helm upgrade --install trustee ./deployment/helm-chart \
  --namespace coco-trustee --create-namespace \
  -f ./deployment/helm-chart/scenarios/ibm-se.yaml \
  --set as.verifier.se.credsDir=$IBM_SE_CREDS_DIR \
  --set as.verifier.se.nodeName=<your-s390x-node-name>
```

Use an **s390x** AS image built with the `se-verifier` feature (`as.image.repository` / `as.image.tag`). See **`scenarios/ibm-se.yaml`** for the full override. Set the SE attestation policy afterwards as documented in `deps/verifier/src/se/README.md`.

## Testing

**Inspect resources**:

```bash
kubectl get deploy,pods,svc -n coco-trustee
helm status trustee -n coco-trustee
```

**Render-only check** (no install):

```bash
helm dependency update ./deployment/helm-chart

helm template trustee ./deployment/helm-chart \
  -f ./deployment/helm-chart/scenarios/postgres-backend.yaml \
  --namespace coco-trustee > /tmp/trustee-render.yaml
```

If your cluster cannot resolve `*.svc.cluster.local` from Pods, set `dnsHostAliasWorkaround: true` in your override values and then run `helm upgrade` again after Services exist so Helm `lookup` can resolve ClusterIPs.

**kbs-client** (build from the repo: `cargo build -p kbs-client --release`): with ephemeral keys, the hook-created Secret (name ends with **`bootstrap-user-keys`**) includes a pre-signed admin JWT under **`KBS_ADMIN_TOKEN`**. KBS expects `authorization_mode = "AuthenticatedAuthorization"` with a bearer JWT that includes a **`role`** claim matching `[admin.authorization.regex_acl]` (default role **`admin`**).

```bash
kubectl port-forward -n coco-trustee svc/trustee-kbs 8080:8080 &
SECRET=$(kubectl get secrets -n coco-trustee -o name | grep bootstrap-user-keys | head -1 | cut -d/ -f2)
kubectl get secret "$SECRET" -n coco-trustee -o jsonpath='{.data.KBS_ADMIN_TOKEN}' | base64 -d >/tmp/admin-token
kbs-client --url http://127.0.0.1:8080 config --admin-token-file /tmp/admin-token set-resource-policy --allow-all
```

Set a confidential resource (`config` + `--admin-token-file`, then `set-resource`):

```bash
echo 'demo-payload' >/tmp/demo-resource.txt
kbs-client --url http://127.0.0.1:8080 config --admin-token-file /tmp/admin-token set-resource \
  --path my_repo/resource_type/demo --resource-file /tmp/demo-resource.txt
```

Fetch a resource by KBS URI path (`get-resource` is a top-level subcommand; it follows the normal attestation / token flow for your client build and policy):

```bash
kbs-client --url http://127.0.0.1:8080 get-resource --path my_repo/resource_type/demo
```

## Configuration

Default **`values.yaml`** is intentionally small. Fixed on-disk paths for **LocalFs** / **LocalJson** are defined in **`templates/_helpers.tpl`** (not overridable via values). You can still merge extra keys with `-f` / `--set` (Helm merges arbitrary values).

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| as.affinity | object | `{}` | Affinity and anti-affinity scheduling rules for AS Pods. |
| as.extraEnvVars | list | `[]` | Extra environment variables for the AS container (for example `HTTP(S)_PROXY` and `NO_PROXY`). |
| as.verifier.se.credsDir | string | `""` | Absolute path on the target node to the directory containing IBM SE attestation materials (`rsa/`, `certs/`, `crls/`, `hkds/`, `hdr/hdr.bin`). When non-empty, the chart creates a `local`-type PersistentVolume + PersistentVolumeClaim and mounts the directory at `/run/confidential-containers/ibmse/` on the AS Pod. Requires `as.verifier.se.nodeName`. |
| as.verifier.se.nodeName | string | `""` | Kubernetes node name where the IBM SE materials directory (`as.verifier.se.credsDir`) resides. Required when `as.verifier.se.credsDir` is set; used in the PersistentVolume `nodeAffinity`. |
| as.image.pullPolicy | string | `"Always"` | AS container image pull policy. |
| as.image.repository | string | `"ghcr.io/confidential-containers/staged-images/coco-as-grpc"` | AS container image repository. |
| as.image.tag | string | `"latest"` | AS container image tag. |
| as.imagePullSecrets | list | `[]` | Optional image pull secrets for private registries. |
| as.nodeSelector | object | `{}` | Node label selection constraints for AS Pods. |
| as.podAnnotations | object | `{}` | Extra Pod annotations. |
| as.podSecurityContext | object | `{}` | Pod-level security context overrides. |
| as.replicaCount | int | `1` | Number of Attestation Service Pod replicas. |
| as.resources | object | `{"limits":{"cpu":"4","memory":"4Gi"},"requests":{"cpu":"500m","memory":"1Gi"}}` | Container CPU/memory requests and limits for AS. |
| as.service.loadBalancerAnnotations | object | `{}` | Annotations applied when `as.service.type` is `LoadBalancer`. |
| as.service.port | int | `50004` | AS Service port. |
| as.service.type | string | `"ClusterIP"` | AS Service type (`ClusterIP` or `LoadBalancer`). |
| as.tolerations | list | `[]` | Tolerations for scheduling AS Pods onto tainted nodes. |
| as.verifier.dcap.collateral_service | string | `"https://api.trustedservices.intel.com/sgx/certification/v4/"` | Intel DCAP collateral service URL. Required when `as.verifier.dcap` is configured. |
| as.verifier.dcap.tcb_update_type | string | `"early"` | DCAP TCB update type (for example `early`). |
| as.verifier.nvidia.type | string | `"Local"` | NVIDIA verifier type: `Local` or `Remote`. When `Remote`, `verifierUrl` must be set. |
| as.verifier.nvidia.verifierUrl | string | `"https://nras.attestation.nvidia.com/v4/attest"` | NRAS URL when `as.verifier.nvidia.type` is `Remote`. |
| bootstrapUserKeysJob | object | `{"keygenImage":{"pullPolicy":"IfNotPresent","repository":"alpine/openssl","tag":"3.5.6"},"kubectlImage":{"pullPolicy":"IfNotPresent","repository":"quay.io/kata-containers/kubectl","tag":"20260112"},"resources":{"limits":{"cpu":"200m","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}}` | Bootstrap hook Job settings (pre-install/pre-upgrade key generation and post-delete cleanup when `secrets.useEphemeralGeneratedKeys=true`). |
| bootstrapUserKeysJob.keygenImage.pullPolicy | string | `"IfNotPresent"` | OpenSSL `initContainer` image pull policy. |
| bootstrapUserKeysJob.keygenImage.repository | string | `"alpine/openssl"` | OpenSSL `initContainer` image repository that generates demo keys. |
| bootstrapUserKeysJob.keygenImage.tag | string | `"3.5.6"` | OpenSSL `initContainer` image tag. |
| bootstrapUserKeysJob.kubectlImage.pullPolicy | string | `"IfNotPresent"` | kubectl container image pull policy. |
| bootstrapUserKeysJob.kubectlImage.repository | string | `"quay.io/kata-containers/kubectl"` | kubectl container image repository that creates or updates the release-scoped Secret. |
| bootstrapUserKeysJob.kubectlImage.tag | string | `"20260112"` | kubectl container image tag. |
| bootstrapUserKeysJob.resources | object | `{"limits":{"cpu":"200m","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | CPU/memory requests and limits for the bootstrap hook Job. |
| dnsHostAliasWorkaround | bool | `false` | When `true`, templates use Helm `lookup` to write Service `clusterIP` entries into `hostAliases` for clusters that cannot resolve `*.svc.cluster.local`. If Services are missing on first render, rerun `helm upgrade`. |
| fullnameOverride | string | `""` | Override the fully qualified release name (truncated to 63 characters). |
| ingress | object | `{"annotations":{},"className":"","enabled":false,"host":"","tls":[]}` | Optional Kubernetes Ingress for the KBS Service. |
| ingress.annotations | object | `{}` | Ingress annotations. |
| ingress.className | string | `""` | IngressClass name. |
| ingress.enabled | bool | `false` | Enable Ingress for KBS. |
| ingress.host | string | `""` | Host-based routing. Leave empty to match all hosts (IP-only access). |
| ingress.tls | list | `[]` | TLS configuration entries. |
| kbs.affinity | object | `{}` | Affinity and anti-affinity scheduling rules for KBS Pods. |
| kbs.config.admin.audience | string | `"KBS"` | JWT `audience` claim for the bootstrap-generated admin token. |
| kbs.config.admin.issuer | string | `"TrusteeInHelm"` | JWT `issuer` claim for the bootstrap-generated admin token; must match `[admin.authentication.bearer_jwt]`. |
| kbs.config.admin.role | string | `"admin"` | JWT `role` claim and matching `[admin.authorization.regex_acl]` role. |
| kbs.config.attestationService.poolSize | int | `200` | Connection pool size for the KBS -> gRPC AS client (`pool_size` in `files/kbs-config.toml.template`). |
| kbs.config.attestationService.timeout | int | `30` | Request timeout in seconds for the KBS -> gRPC AS client (`timeout` in `files/kbs-config.toml.template`). |
| kbs.extraEnvVars | list | `[]` | Extra environment variables to inject into the KBS container. |
| kbs.extraVolumeMounts | list | `[]` | Extra volume mounts for the KBS container. |
| kbs.extraVolumes | list | `[]` | Extra volumes to attach to the KBS Pod. |
| kbs.image.pullPolicy | string | `"Always"` | KBS container image pull policy. |
| kbs.image.repository | string | `"ghcr.io/confidential-containers/staged-images/kbs-grpc-as"` | KBS container image repository. |
| kbs.image.tag | string | `"latest"` | KBS container image tag. |
| kbs.imagePullSecrets | list | `[]` | Optional image pull secrets for private registries. |
| kbs.nodeSelector | object | `{}` | Node label selection constraints for KBS Pods. |
| kbs.podAnnotations | object | `{}` | Extra Pod annotations (for example Prometheus scrape or service mesh integration). |
| kbs.podSecurityContext | object | `{}` | Pod-level security context overrides. |
| kbs.replicaCount | int | `1` | Number of KBS Pod replicas. |
| kbs.resourceRepository | list | `[]` | KBS resource repository configuration (passed through to KBS config). |
| kbs.resources | object | `{"limits":{"cpu":"2","memory":"2Gi"},"requests":{"cpu":"250m","memory":"256Mi"}}` | Container CPU/memory requests and limits for KBS. |
| kbs.service.exposeLoadBalancer | bool | `false` | When `true`, create an additional external `LoadBalancer` Service (`<fullname>-kbs-lb`). The primary KBS Service (`<fullname>-kbs`) is always internal `ClusterIP`. |
| kbs.service.loadBalancerAnnotations | object | `{}` | Annotations applied to the optional KBS `LoadBalancer` Service when `exposeLoadBalancer=true`. |
| kbs.service.port | int | `8080` | Service port for KBS; used by both the internal `ClusterIP` Service and the optional external `LoadBalancer` Service. |
| kbs.tolerations | list | `[]` | Tolerations for scheduling KBS Pods onto tainted nodes. |
| log_level | string | `"info"` | Container `RUST_LOG` for KBS, AS, and RVPS (`info`, `debug`, `warn`, `error`). |
| nameOverride | string | `""` | Override the chart name used in labels and resource names. |
| nodePort | object | `{"enabled":false,"port":""}` | Expose the KBS Service via a NodePort. |
| nodePort.enabled | bool | `false` | Enable a NodePort Service for KBS. |
| nodePort.port | string | `""` | Fixed NodePort number; empty assigns a random port from the NodePort range. |
| postgresql | object | `{"auth":{"database":"trustee","password":"trustee","username":"trustee"},"enabled":false,"nameOverride":"postgres","primary":{"initdb":{"scriptsConfigMap":"trustee-postgres-initdb"},"persistence":{"enabled":true,"existingClaim":"","size":"8Gi","storageClass":""},"resources":{"limits":{"cpu":"1","memory":"1Gi"},"requests":{"cpu":"250m","memory":"256Mi"}}},"service":{"ports":{"postgresql":5432}}}` | [Bitnami PostgreSQL](https://artifacthub.io/packages/helm/bitnami/postgresql) subchart. Set `enabled: true` when bundled Postgres is required (`storageBackend.postgres.mode=internal` and Postgres storage is needed; see `scenarios/postgres-backend.yaml`). Additional subchart keys (image, metrics, replication, and so on) are supported; see upstream docs. |
| postgresql.auth.database | string | `"trustee"` | Bundled Postgres database name (also used for the Trustee `POSTGRES_URL` Secret). |
| postgresql.auth.password | string | `"trustee"` | Bundled Postgres password (also used for the Trustee `POSTGRES_URL` Secret). |
| postgresql.auth.username | string | `"trustee"` | Bundled Postgres username (also used for the Trustee `POSTGRES_URL` Secret). |
| postgresql.enabled | bool | `false` | Enable the Bitnami PostgreSQL subchart. Must be `true` when `storageBackend.postgres.mode=internal` and Postgres storage is required. |
| postgresql.nameOverride | string | `"postgres"` | Subchart service name override; release Service becomes `{Helm release}-postgres`. |
| postgresql.primary.initdb.scriptsConfigMap | string | `"trustee-postgres-initdb"` | ConfigMap wired to `files/postgres-initkv.sql` via `templates/postgres-initdb-configmap.yaml` (do not override unless you know what you are doing). |
| postgresql.primary.persistence.enabled | bool | `true` | Enable PVC-backed storage for bundled Postgres. |
| postgresql.primary.persistence.existingClaim | string | `""` | Existing PVC name to reuse for bundled Postgres. |
| postgresql.primary.persistence.size | string | `"8Gi"` | Requested size for the auto-created bundled Postgres PVC (for example `8Gi`). |
| postgresql.primary.persistence.storageClass | string | `""` | StorageClass for the auto-created bundled Postgres PVC; empty uses the cluster default. |
| postgresql.primary.resources | object | `{"limits":{"cpu":"1","memory":"1Gi"},"requests":{"cpu":"250m","memory":"256Mi"}}` | CPU/memory requests and limits for bundled Postgres. |
| postgresql.service.ports.postgresql | int | `5432` | Bundled Postgres Service port (used in `POSTGRES_URL`). |
| rvps.affinity | object | `{}` | Affinity and anti-affinity scheduling rules for RVPS Pods. |
| rvps.extraEnvVars | list | `[]` | Extra environment variables for the RVPS container (for example `HTTP(S)_PROXY` and `NO_PROXY`). |
| rvps.image.pullPolicy | string | `"Always"` | RVPS container image pull policy. |
| rvps.image.repository | string | `"ghcr.io/confidential-containers/staged-images/rvps"` | RVPS container image repository. |
| rvps.image.tag | string | `"latest"` | RVPS container image tag. |
| rvps.imagePullSecrets | list | `[]` | Optional image pull secrets for private registries. |
| rvps.nodeSelector | object | `{}` | Node label selection constraints for RVPS Pods. |
| rvps.podAnnotations | object | `{}` | Extra Pod annotations. |
| rvps.podSecurityContext | object | `{}` | Pod-level security context overrides. |
| rvps.replicaCount | int | `1` | Number of RVPS Pod replicas. |
| rvps.resources | object | `{"limits":{"cpu":"1","memory":"1Gi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Container CPU/memory requests and limits for RVPS. |
| rvps.service.loadBalancerAnnotations | object | `{}` | Annotations for the internal RVPS LoadBalancer Service. |
| rvps.service.loadBalancerType | string | `"internal"` | Load balancer kind when `rvps.service.type` is `LoadBalancer`: `internal` or `public`. |
| rvps.service.port | int | `50003` | RVPS Service port. |
| rvps.service.publicLoadBalancerAnnotations | object | `{}` | Annotations for the public RVPS LoadBalancer Service when `loadBalancerType=public`. |
| rvps.service.type | string | `"ClusterIP"` | RVPS Service type (`ClusterIP` or `LoadBalancer`). |
| rvps.tolerations | list | `[]` | Tolerations for scheduling RVPS Pods onto tainted nodes. |
| secrets.existingSecretName | string | `""` | Required when `useEphemeralGeneratedKeys=false`. Secret must contain `KBS_ADMIN_PRIVATE_KEY`, `KBS_ADMIN_PUBKEY`, `AS_TOKEN_SIGNING_PRIVATE_KEY`, and `AS_TOKEN_VERIFICATION_PUBLIC_KEY_CERT_CHAIN`. Optionally include `KBS_ADMIN_TOKEN` (see `kbs/config/docker-compose/setup.sh` for claim layout). |
| secrets.useEphemeralGeneratedKeys | bool | `true` | When `true`, a pre-install/pre-upgrade hook generates demo keys into a release-scoped Secret; when `false`, you must pre-create a Secret and set `existingSecretName`. |
| sessionStorageType | string | `"Memory"` | KBS protocol session store: `Memory`, `LocalJson`, `LocalFs`, `Postgres`, or `Redis`. When empty, follows `storageBackend.type`. `Redis` speaks the Redis protocol and is served by the bundled Valkey subchart (or an external Redis-compatible service). |
| storageBackend | object | `{"localFs":{"persistence":{"as":"","kbs":"","rvps":""}},"localJson":{"persistence":{"as":"","kbs":"","rvps":""}},"postgres":{"external":{"existingSecretKey":"","existingSecretName":""},"internal":{"initKvTables":true},"mode":"internal"},"redis":{"external":{"existingSecretKey":"","existingSecretName":""},"mode":"internal"},"type":"LocalFs"}` | Unified KV backend for KBS, AS, and RVPS (same `storage_type` in each service config). |
| storageBackend.localFs.persistence.as | string | `""` | PVC claim name for AS local storage; empty uses `emptyDir`. |
| storageBackend.localFs.persistence.kbs | string | `""` | PVC claim name for KBS local storage; empty uses `emptyDir`. |
| storageBackend.localFs.persistence.rvps | string | `""` | PVC claim name for RVPS local storage; empty uses `emptyDir`. |
| storageBackend.localJson.persistence.as | string | `""` | PVC claim name for AS local JSON storage; empty uses `emptyDir`. |
| storageBackend.localJson.persistence.kbs | string | `""` | PVC claim name for KBS local JSON storage; empty uses `emptyDir`. |
| storageBackend.localJson.persistence.rvps | string | `""` | PVC claim name for RVPS local JSON storage; empty uses `emptyDir`. |
| storageBackend.postgres.external.existingSecretKey | string | `""` | Required when `mode` is `external`: Secret key name for the Postgres URL. |
| storageBackend.postgres.external.existingSecretName | string | `""` | Required when `mode` is `external`: Secret containing the Postgres URL. |
| storageBackend.postgres.internal.initKvTables | bool | `true` | When `true`, run KV table init SQL from `files/postgres-initkv.sql` on first database init (via a chart-managed ConfigMap). When `false`, also set `postgresql.primary.initdb.scriptsConfigMap` to `""`. |
| storageBackend.postgres.mode | string | `"internal"` | Postgres source: `internal` (Bitnami subchart) or `external` (pre-created Secret). |
| storageBackend.redis.external.existingSecretKey | string | `""` | Required when `mode` is `external`: Secret key name for the Redis URL. |
| storageBackend.redis.external.existingSecretName | string | `""` | Required when `mode` is `external`: Secret containing the Redis URL (e.g. `redis://:password@redis.example.com:6379`). |
| storageBackend.redis.mode | string | `"internal"` | Redis-protocol source: `internal` (Bitnami Valkey subchart) or `external` (pre-created Secret with a Redis URL). |
| storageBackend.type | string | `"LocalFs"` | Backend type: `LocalFs`, `LocalJson`, `Postgres`, or `Memory`. When `Postgres` (or `sessionStorageType` is `Postgres`), the chart injects `POSTGRES_URL`. Only settings for the selected type take effect. |
| valkey | object | `{"architecture":"standalone","auth":{"enabled":true,"password":"trustee"},"enabled":false,"image":{"pullPolicy":"IfNotPresent","registry":"registry-1.docker.io","repository":"bitnami/valkey","tag":"latest"},"nameOverride":"valkey","primary":{"persistence":{"enabled":false},"resources":{"limits":{"cpu":"1","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}},"service":{"ports":{"valkey":6379}}}}` | [Bitnami Valkey](https://artifacthub.io/packages/helm/bitnami/valkey) subchart, a Redis-protocol-compatible store used for the KBS `Redis` session backend (Valkey is BSD-licensed; it replaces Redis, whose license is no longer OSI-approved). Set `enabled: true` when the bundled store is required (`storageBackend.redis.mode=internal` and `sessionStorageType` or `storageBackend.type` is `Redis`; see `scenarios/valkey-sessions.yaml`). Additional subchart keys (metrics, replication, TLS, and so on) are supported; see upstream docs. |
| valkey.architecture | string | `"standalone"` | Single Valkey primary; sessions do not need replicas. Set `replication` plus `replica.*` keys for HA (see upstream docs). |
| valkey.auth.enabled | bool | `true` | Require a password for the bundled Valkey (also used for the Trustee `REDIS_URL` Secret). |
| valkey.auth.password | string | `"trustee"` | Bundled Valkey password (also used for the Trustee `REDIS_URL` Secret). |
| valkey.enabled | bool | `false` | Enable the Bitnami Valkey subchart. Must be `true` when `storageBackend.redis.mode=internal` and Redis storage is required. |
| valkey.image | object | `{"pullPolicy":"IfNotPresent","registry":"registry-1.docker.io","repository":"bitnami/valkey","tag":"latest"}` | Bundled Valkey container image. The default comes from `docker.io`, where anonymous pulls are rate-limited; point `registry`/`repository` at a private mirror to avoid pull failures (a chart-wide `global.imageRegistry` is also honored by the subchart). |
| valkey.image.pullPolicy | string | `"IfNotPresent"` | Valkey image pull policy. |
| valkey.image.registry | string | `"registry-1.docker.io"` | Valkey image registry; override with a mirror to avoid docker.io rate limits. |
| valkey.image.repository | string | `"bitnami/valkey"` | Valkey image repository. |
| valkey.image.tag | string | `"latest"` | Valkey image tag. |
| valkey.nameOverride | string | `"valkey"` | Subchart name override; the primary Service becomes `{Helm release}-valkey-primary`. |
| valkey.primary.persistence.enabled | bool | `false` | KBS sessions are short-lived, so the bundled Valkey defaults to no PVC; set `true` (plus optional `storageClass`/`size`) to persist sessions across Pod restarts. |
| valkey.primary.resources | object | `{"limits":{"cpu":"1","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | CPU/memory requests and limits for the bundled Valkey primary. |
| valkey.primary.service.ports.valkey | int | `6379` | Bundled Valkey Service port (used in `REDIS_URL`). |

## End-to-end test

Provision a **kind** cluster out of band, preload the Trustee images into it, point `kubectl` at it, then from the repository root:

```bash
kind create cluster --name kind --wait 5m
make -C deployment/helm-chart load-e2e-images-into-kind
make test-helm-e2e
```

`make e2e-test` assumes **KBS / AS / RVPS** images are already loaded into the cluster and deploys with [scenarios/e2e-local-images.yaml](./scenarios/e2e-local-images.yaml). The Makefile injects image repositories, tags, and `pullPolicy: Never` at install time so local runs and CI can use different preloaded image names without changing the scenario file.

- **Local preloaded images**: `trustee-e2e/*:e2e`, `pullPolicy: Never` (not GHCR `:latest`)
- **CI images**: reuses `docker-e2e-images-linux-amd64` from `workflow-call-build-docker-e2e-materials.yml` as `ghcr.io/confidential-containers/staged-images/*:latest`
- **Storage**: bundled Postgres KV backend (`storageBackend.type: Postgres`)
- **KBS sessions**: `sessionStorageType: Memory`

Steps:

1. **`helm-dependency-build`**
2. **`helm-lint`**
3. **`deploy`**
4. **`test-client`** — [e2e/test.sh](./e2e/test.sh)
5. **`undeploy`** — always attempted, even after failures

Debug individually:

```bash
make -C deployment/helm-chart load-e2e-images-into-kind
make -C deployment/helm-chart helm-lint
make -C deployment/helm-chart deploy
make -C deployment/helm-chart test-client
make -C deployment/helm-chart undeploy
```

Optional variables: `E2E_IMAGE_PREFIX`, `E2E_IMAGE_TAG`, `KBS_CLIENT`.

CI (`test-e2e-kbs.yml`) reuses the Docker Compose e2e image build workflow artifacts: it loads the pre-built Trustee images into kind and uses the pre-built `kbs-client` binary before running Helm e2e.

`make test-client` alone does not build images or undeploy.

## Development notes

1. Do not change the files under [files](./files/) unless you are updating the corresponding Helm template logic. Service config is rendered from `*.template` files; Postgres KV init SQL lives in `files/postgres-initkv.sql`.
2. After changing `Chart.yaml` dependencies, run `helm dependency update ./deployment/helm-chart` and commit `Chart.lock` plus `charts/` if your packaging workflow vendors subcharts.
3. After changing `values.yaml` comments or keys, regenerate this README from [README.md.gotmpl](./README.md.gotmpl): `helm-docs -c .` (run from this directory).
