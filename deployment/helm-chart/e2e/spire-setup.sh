#!/usr/bin/env bash
# Installs a throwaway SPIRE server+agent+spiffe-csi stack via the
# upstream `spiffe/helm-charts-hardened` charts. Must run before
# `deploy-spire` (Makefile), which needs the spiffe-csi driver already
# registered.

set -euo pipefail

SPIRE_NAMESPACE="coco-trustee-e2e"
SPIRE_TRUST_DOMAIN="example.org"
SPIRE_CLUSTER_NAME="kind-spire-e2e"
KBS_SERVICE_ACCOUNT="default"
KBS_SPIFFE_ID="spiffe://${SPIRE_TRUST_DOMAIN}/ns/${SPIRE_NAMESPACE}/sa/${KBS_SERVICE_ACCOUNT}"

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

main() {
	require_cmd kubectl
	require_cmd helm

	log "installing spire-crds + spire (server, agent, spiffe-csi) into ${SPIRE_NAMESPACE}"
	helm upgrade --install --create-namespace -n "${SPIRE_NAMESPACE}" spire-crds spire-crds \
		--repo https://spiffe.github.io/helm-charts-hardened/ \
		--wait --timeout 5m

	helm upgrade --install -n "${SPIRE_NAMESPACE}" spire spire \
		--repo https://spiffe.github.io/helm-charts-hardened/ \
		--set "global.spire.clusterName=${SPIRE_CLUSTER_NAME}" \
		--set "global.spire.trustDomain=${SPIRE_TRUST_DOMAIN}" \
		--set "global.spire.namespaces.create=false" \
		--set "spire-agent.authorizedDelegates[0]=${KBS_SPIFFE_ID}" \
		--set "spire-agent.sockets.admin.enabled=true" \
		--set "spire-agent.sockets.admin.mountOnHost=true" \
		--wait --timeout 10m

	kubectl rollout status daemonset/spire-agent -n "${SPIRE_NAMESPACE}" --timeout=300s
	kubectl rollout status statefulset/spire-server -n "${SPIRE_NAMESPACE}" --timeout=300s

	log "spire stack ready"
}

main "$@"
