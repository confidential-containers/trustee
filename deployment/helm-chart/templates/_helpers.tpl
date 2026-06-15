{{/*
Expand the name of the chart.
*/}}
{{- define "coco-trustee.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "coco-trustee.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "coco-trustee.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "coco-trustee.labels" -}}
helm.sh/chart: {{ include "coco-trustee.chart" . }}
{{ include "coco-trustee.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "coco-trustee.selectorLabels" -}}
app.kubernetes.io/name: {{ include "coco-trustee.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Release-scoped Kubernetes metadata.name values (unique per Helm release; <= 63 chars).
Each helper truncates `coco-trustee.fullname` to leave room for its suffix before printf.
*/}}
{{- define "coco-trustee.names.kbs" -}}
{{- printf "%s-kbs" (include "coco-trustee.fullname" . | trunc 59 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.kbsLb" -}}
{{- printf "%s-kbs-lb" (include "coco-trustee.fullname" . | trunc 56 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.kbsConfig" -}}
{{- printf "%s-kbs-config" (include "coco-trustee.fullname" . | trunc 52 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.as" -}}
{{- printf "%s-as" (include "coco-trustee.fullname" . | trunc 60 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.asLb" -}}
{{- printf "%s-as-lb" (include "coco-trustee.fullname" . | trunc 57 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.asConfig" -}}
{{- printf "%s-as-config" (include "coco-trustee.fullname" . | trunc 53 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.rvps" -}}
{{- printf "%s-rvps" (include "coco-trustee.fullname" . | trunc 58 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.rvpsLb" -}}
{{- printf "%s-rvps-lb" (include "coco-trustee.fullname" . | trunc 55 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.rvpsLbPublic" -}}
{{- printf "%s-rvps-lb-pub" (include "coco-trustee.fullname" . | trunc 49 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.rvpsConfig" -}}
{{- printf "%s-rvps-config" (include "coco-trustee.fullname" . | trunc 50 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.bootstrapKeys" -}}
{{- printf "%s-bootstrap-keys" (include "coco-trustee.fullname" . | trunc 48 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.bootstrapKeysDelete" -}}
{{- printf "%s-bootstrap-keys-del" (include "coco-trustee.fullname" . | trunc 44 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.bootstrapUserKeysSecret" -}}
{{- printf "%s-bootstrap-user-keys" (include "coco-trustee.fullname" . | trunc 43 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.postgres" -}}
{{- printf "%s-postgres" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.names.postgresInitdb" -}}
{{- printf "%s-postgres-initdb" .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Fixed workload ports (override only via undocumented values for advanced use).
*/}}
{{- define "coco-trustee.port.kbs" -}}
{{- $s := .Values.kbs.service | default dict }}{{ default 8080 $s.port }}
{{- end }}
{{- define "coco-trustee.port.as" -}}
{{- $s := .Values.as.service | default dict }}{{ default 50004 $s.port }}
{{- end }}
{{- define "coco-trustee.port.rvps" -}}
{{- $s := .Values.rvps.service | default dict }}{{ default 50003 $s.port }}
{{- end }}
{{- define "coco-trustee.port.postgres" -}}
{{- $pg := (.Values.postgresql | default dict) }}
{{- $ports := dig "service" "ports" dict $pg }}
{{- $gport := dig "postgresql" "service" "ports" "postgresql" "" (.Values.global | default dict) }}
{{- default 5432 (coalesce $gport $ports.postgresql) }}
{{- end }}

{{/*
AS verifier config JSON fragment
*/}}
{{- define "coco-trustee.as.verifier" -}}
{{- $nv := dig "verifier" "nvidia" (dict) (default dict .Values.as) | default dict -}}
{{- $dcap := dig "verifier" "dcap" (dict) (default dict .Values.as) | default dict -}}
{{- if $nv -}}
{{- if eq $nv.type "Remote" -}}
{{- $_ := required "as.verifier.nvidia.verifierUrl must be set when as.verifier.nvidia.type is Remote" (trim (default "" $nv.verifierUrl)) -}}
{{- end -}}
{{- $nvType := default "Local" $nv.type -}}
"nvidia_verifier": {
    "type": "{{ $nvType }}"
    {{- if eq $nv.type "Remote" }},
    "verifier_url": "{{ $nv.verifierUrl }}"
    {{- end }}
}
{{- end -}}
{{- if and $dcap $nv }},
{{- end }}
{{ if $dcap -}}
{{- $_ := required "as.verifier.dcap.collateral_service must be set when as.verifier.dcap is set" (trim (default "" $dcap.collateral_service)) -}}
"dcap_verifier": {
    "collateral_service": "{{ $dcap.collateral_service }}"
    {{- if $dcap.tcb_update_type }},
    "tcb_update_type": "{{ $dcap.tcb_update_type }}"
    {{- end }}
}
{{- end -}}
{{- end }}

{{/*
Container security defaults (aligned with prior chart defaults).
*/}}
{{- define "coco-trustee.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
  - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Unified storage backend type (single source: `storageBackend.type`).
*/}}
{{- define "coco-trustee.storage.type" -}}
{{- $g := .Values.storageBackend | default dict }}
{{- if $g.type }}{{ $g.type }}{{- else }}LocalFs{{- end -}}
{{- end }}

{{- define "coco-trustee.storage.storageBackendIsPostgres" -}}
{{- $st := include "coco-trustee.storage.type" . | trim }}
{{- if or (eq $st "Postgres") (eq $st "postgres") }}true{{- end }}
{{- end }}

{{- define "coco-trustee.kbs.sessionStorageIsPostgres" -}}
{{- $sst := include "coco-trustee.kbs.sessionStorageType" . | trim }}
{{- if or (eq $sst "Postgres") (eq $sst "postgres") }}true{{- end }}
{{- end }}

{{- define "coco-trustee.storage.needsPostgres" -}}
{{- $st := include "coco-trustee.storage.type" . | trim }}
{{- $sst := include "coco-trustee.kbs.sessionStorageType" . | trim }}
{{- if or (eq $st "Postgres") (eq $st "postgres") (eq $sst "Postgres") (eq $sst "postgres") }}true{{- end }}
{{- end }}

{{- define "coco-trustee.postgres.mode" -}}
{{- $pg := (.Values.storageBackend.postgres | default dict) }}
{{- $mode := default "internal" $pg.mode }}
{{- lower $mode }}
{{- end }}

{{/*
True when the Bitnami PostgreSQL subchart should be used (in-cluster, non-external).
*/}}
{{- define "coco-trustee.postgres.useBitnami" -}}
{{- $needsPostgres := include "coco-trustee.storage.needsPostgres" . | trim }}
{{- $mode := include "coco-trustee.postgres.mode" . | trim }}
{{- if and (eq $needsPostgres "true") (ne $mode "external") }}true{{- end }}
{{- end }}

{{- define "coco-trustee.postgres.initKvTables" -}}
{{- $pg := (.Values.storageBackend.postgres | default dict) }}
{{- $pgi := ($pg.internal | default dict) }}
{{- if (ternary $pgi.initKvTables true (hasKey $pgi "initKvTables")) }}true{{- end }}
{{- end }}

{{/*
PVC claim names for local KV backends (LocalFs / LocalJson). Empty => chart uses emptyDir for that workload path.
KBS may need a claim when main or session storage is local; AS/RVPS follow unified `storageBackend.type` only.
*/}}
{{- define "coco-trustee.persistence.kbsDataClaimName" -}}
{{- $st := include "coco-trustee.storage.type" . | trim }}
{{- $sst := include "coco-trustee.kbs.sessionStorageType" . | trim }}
{{- $lfP := (((.Values.storageBackend | default dict).localFs | default dict).persistence | default dict) }}
{{- $ljP := (((.Values.storageBackend | default dict).localJson | default dict).persistence | default dict) }}
{{- $needLF := or (eq $st "LocalFs") (eq $st "local_fs") (eq $sst "LocalFs") (eq $sst "local_fs") }}
{{- $needLJ := or (eq $st "LocalJson") (eq $st "local_json") (eq $sst "LocalJson") (eq $sst "local_json") }}
{{- if and $needLF $needLJ }}
{{- coalesce ($lfP.kbs | default "") ($ljP.kbs | default "") }}
{{- else if $needLF }}
{{- $lfP.kbs | default "" }}
{{- else if $needLJ }}
{{- $ljP.kbs | default "" }}
{{- end }}
{{- end }}

{{- define "coco-trustee.persistence.asDataClaimName" -}}
{{- $st := include "coco-trustee.storage.type" . | trim }}
{{- $lfP := (((.Values.storageBackend | default dict).localFs | default dict).persistence | default dict) }}
{{- $ljP := (((.Values.storageBackend | default dict).localJson | default dict).persistence | default dict) }}
{{- if or (eq $st "LocalFs") (eq $st "local_fs") }}{{ $lfP.as | default "" }}{{- else if or (eq $st "LocalJson") (eq $st "local_json") }}{{ $ljP.as | default "" }}{{- end }}
{{- end }}

{{- define "coco-trustee.persistence.rvpsRefClaimName" -}}
{{- $st := include "coco-trustee.storage.type" . | trim }}
{{- $lfP := (((.Values.storageBackend | default dict).localFs | default dict).persistence | default dict) }}
{{- $ljP := (((.Values.storageBackend | default dict).localJson | default dict).persistence | default dict) }}
{{- if or (eq $st "LocalFs") (eq $st "local_fs") }}{{ $lfP.rvps | default "" }}{{- else if or (eq $st "LocalJson") (eq $st "local_json") }}{{ $ljP.rvps | default "" }}{{- end }}
{{- end }}

{{/*
Fixed on-disk paths for LocalFs / LocalJson (match Trustee images and `key-value-storage` defaults);
*/}}
{{- define "coco-trustee.storage.kbsLocalDir" -}}/opt/confidential-containers/kbs/repository{{- end }}

{{- define "coco-trustee.storage.asLocalDir" -}}/opt/confidential-containers/attestation-service{{- end }}

{{- define "coco-trustee.storage.rvpsLocalDir" -}}/opt/confidential-containers/attestation-service/reference_values{{- end }}

{{- define "coco-trustee.storage.localJsonDir" -}}/opt/confidential-containers/trustee/local-json{{- end }}

{{- define "coco-trustee.svc.as" -}}
{{- printf "%s.%s.svc.cluster.local" (include "coco-trustee.names.as" .) .Release.Namespace -}}
{{- end }}
{{- define "coco-trustee.svc.rvps" -}}
{{- printf "%s.%s.svc.cluster.local" (include "coco-trustee.names.rvps" .) .Release.Namespace -}}
{{- end }}
{{- define "coco-trustee.svc.kbs" -}}
{{- printf "%s.%s.svc.cluster.local" (include "coco-trustee.names.kbs" .) .Release.Namespace -}}
{{- end }}
{{- define "coco-trustee.svc.postgres" -}}
{{- printf "%s.%s.svc.cluster.local" (include "coco-trustee.names.postgres" .) .Release.Namespace -}}
{{- end }}

{{- define "coco-trustee.postgres.internalSecretName" -}}
{{- printf "%s-postgres-auth" (include "coco-trustee.fullname" . | trunc 48 | trimSuffix "-") | trunc 63 | trimSuffix "-" -}}
{{- end }}
{{- define "coco-trustee.postgres.internalUser" -}}
{{- $auth := dig "auth" dict (.Values.postgresql | default dict) }}
{{- $gauth := dig "postgresql" "auth" dict (.Values.global | default dict) }}
{{- default "trustee" (coalesce $gauth.username $auth.username) }}
{{- end }}
{{- define "coco-trustee.postgres.internalPassword" -}}
{{- $auth := dig "auth" dict (.Values.postgresql | default dict) }}
{{- $gauth := dig "postgresql" "auth" dict (.Values.global | default dict) }}
{{- default "trustee" (coalesce $gauth.password $auth.password) }}
{{- end }}
{{- define "coco-trustee.postgres.internalDatabase" -}}
{{- $auth := dig "auth" dict (.Values.postgresql | default dict) }}
{{- $gauth := dig "postgresql" "auth" dict (.Values.global | default dict) }}
{{- default "trustee" (coalesce $gauth.database $auth.database) }}
{{- end }}

{{- define "coco-trustee.postgresUrlSecretName" -}}
{{- $pg := (.Values.storageBackend.postgres | default dict) }}
{{- $ext := ($pg.external | default dict) }}
{{- $mode := include "coco-trustee.postgres.mode" . | trim }}
{{- $needsPostgres := include "coco-trustee.storage.needsPostgres" . | trim }}
{{- if and (eq $mode "external") (eq $needsPostgres "true") -}}
{{ required "storageBackend.postgres.external.existingSecretName must be set when storageBackend.postgres.mode=external" (trim (default "" $ext.existingSecretName)) }}
{{- else -}}
{{ include "coco-trustee.postgres.internalSecretName" . }}
{{- end -}}
{{- end }}

{{- define "coco-trustee.postgresUrlSecretKey" -}}
{{- $pg := (.Values.storageBackend.postgres | default dict) }}
{{- $ext := ($pg.external | default dict) }}
{{- $mode := include "coco-trustee.postgres.mode" . | trim }}
{{- if eq $mode "external" -}}
{{ required "storageBackend.postgres.external.existingSecretKey must be set when storageBackend.postgres.mode=external" (trim (default "" $ext.existingSecretKey)) }}
{{- else -}}
POSTGRES_URL
{{- end -}}
{{- end }}

{{/*
KBS session storage.
*/}}
{{- define "coco-trustee.kbs.sessionStorageType" -}}
{{- if .Values.sessionStorageType }}{{ .Values.sessionStorageType }}{{- end -}}
{{- end }}

{{/*
Optional hostAliases mapping in-cluster Service names to ClusterIP (Helm lookup).
For clusters where Pod DNS cannot resolve *.svc.cluster.local. If lookup returns
nothing (e.g. first dry-run), this block is omitted; run helm upgrade again after Services exist.
*/}}
{{- define "coco-trustee.podHostAliases" -}}
{{- if .Values.dnsHostAliasWorkaround }}
{{- $ns := .Release.Namespace }}
{{- $pg := lookup "v1" "Service" $ns (include "coco-trustee.names.postgres" .) }}
{{- $rv := lookup "v1" "Service" $ns (include "coco-trustee.names.rvps" .) }}
{{- $as := lookup "v1" "Service" $ns (include "coco-trustee.names.as" .) }}
{{- $kbs := lookup "v1" "Service" $ns (include "coco-trustee.names.kbs" .) }}
{{- $pgip := "" }}
{{- if $pg }}{{ $pgip = default "" $pg.spec.clusterIP }}{{- end }}
{{- $rvip := "" }}
{{- if $rv }}{{ $rvip = default "" $rv.spec.clusterIP }}{{- end }}
{{- $asip := "" }}
{{- if $as }}{{ $asip = default "" $as.spec.clusterIP }}{{- end }}
{{- $kbsip := "" }}
{{- if $kbs }}{{ $kbsip = default "" $kbs.spec.clusterIP }}{{- end }}
{{- if and $rv $as $kbs $rvip $asip $kbsip (ne $rvip "None") (ne $asip "None") (ne $kbsip "None") }}
hostAliases:
  {{- if and $pg $pgip (ne $pgip "None") (eq (include "coco-trustee.postgres.useBitnami" . | trim) "true") }}
  - ip: {{ $pgip | quote }}
    hostnames:
      - {{ include "coco-trustee.names.postgres" . | quote }}
      - {{ include "coco-trustee.svc.postgres" . | quote }}
  {{- end }}
  - ip: {{ $rvip | quote }}
    hostnames:
      - {{ include "coco-trustee.names.rvps" . | quote }}
      - {{ include "coco-trustee.svc.rvps" . | quote }}
  - ip: {{ $asip | quote }}
    hostnames:
      - {{ include "coco-trustee.names.as" . | quote }}
      - {{ include "coco-trustee.svc.as" . | quote }}
  - ip: {{ $kbsip | quote }}
    hostnames:
      - {{ include "coco-trustee.names.kbs" . | quote }}
      - {{ include "coco-trustee.svc.kbs" . | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
When true, render the Helm hook Job + RBAC that creates the release-scoped Secret (`coco-trustee.names.bootstrapUserKeysSecret`) with ephemeral demo keys.
*/}}
{{- define "coco-trustee.kbs.useBootstrapKeysJob" -}}
{{- if .Values.secrets.useEphemeralGeneratedKeys }}1{{- end -}}
{{- end }}

{{/*
Internal: bootstrap hook Job images (defaults can be overridden in values.yaml).
*/}}
{{- define "coco-trustee.internal.bootstrapKeysKeygenImage" -}}
{{- $j := .Values.bootstrapUserKeysJob | default dict -}}
{{- $i := $j.keygenImage | default dict -}}
{{- $repo := default "alpine/openssl" $i.repository -}}
{{- $tag := default "latest" $i.tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}
{{- define "coco-trustee.internal.bootstrapKeysKubectlImage" -}}
{{- $j := .Values.bootstrapUserKeysJob | default dict -}}
{{- $i := $j.kubectlImage | default dict -}}
{{- $repo := default "quay.io/kata-containers/kubectl" $i.repository -}}
{{- $tag := default "latest" $i.tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end }}

{{/*
KBS admin JWT settings (bootstrap token + kbs-config.toml).
*/}}
{{- define "coco-trustee.kbs.adminIssuer" -}}
{{- $adm := (((.Values.kbs | default dict).config | default dict).admin | default dict) -}}
{{- default "TrusteeInHelm" $adm.issuer }}
{{- end }}
{{- define "coco-trustee.kbs.adminAudience" -}}
{{- $adm := (((.Values.kbs | default dict).config | default dict).admin | default dict) -}}
{{- default "KBS" $adm.audience }}
{{- end }}
{{- define "coco-trustee.kbs.adminRole" -}}
{{- $adm := (((.Values.kbs | default dict).config | default dict).admin | default dict) -}}
{{- default "admin" $adm.role }}
{{- end }}

{{/*
Secret name for KBS + AS user-keys volume. Ephemeral path uses hook-created Secret; otherwise secrets.existingSecretName.
*/}}
{{- define "coco-trustee.userKeysSecretNameResolved" -}}
{{- if .Values.secrets.useEphemeralGeneratedKeys }}{{ include "coco-trustee.names.bootstrapUserKeysSecret" . }}
{{- else }}{{ trim (default "" .Values.secrets.existingSecretName) }}
{{- end -}}
{{- end }}

{{/*
Kubernetes Secret data keys for user material (same for hook-created and pre-created BYO Secrets).
Workloads mount these to private.key / public.pub / token.key / token-cert-chain.pem via volume items.
*/}}
{{- define "coco-trustee.userKeysSecretDataKey.adminPrivate" -}}KBS_ADMIN_PRIVATE_KEY{{- end }}
{{- define "coco-trustee.userKeysSecretDataKey.adminPublic" -}}KBS_ADMIN_PUBKEY{{- end }}
{{- define "coco-trustee.userKeysSecretDataKey.adminToken" -}}KBS_ADMIN_TOKEN{{- end }}
{{- define "coco-trustee.userKeysSecretDataKey.tokenSigning" -}}AS_TOKEN_SIGNING_PRIVATE_KEY{{- end }}
{{- define "coco-trustee.userKeysSecretDataKey.tokenCertChain" -}}AS_TOKEN_VERIFICATION_PUBLIC_KEY_CERT_CHAIN{{- end }}

{{/*
Volume `items` mapping Secret keys to filenames expected by KBS and gRPC AS under /opt/confidential-containers/kbs/user-keys.
*/}}
{{- define "coco-trustee.userKeysSecretVolumeItems" -}}
items:
  - key: {{ include "coco-trustee.userKeysSecretDataKey.adminPrivate" . }}
    path: private.key
  - key: {{ include "coco-trustee.userKeysSecretDataKey.adminPublic" . }}
    path: public.pub
  - key: {{ include "coco-trustee.userKeysSecretDataKey.tokenSigning" . }}
    path: token.key
  - key: {{ include "coco-trustee.userKeysSecretDataKey.tokenCertChain" . }}
    path: token-cert-chain.pem
{{- end }}
