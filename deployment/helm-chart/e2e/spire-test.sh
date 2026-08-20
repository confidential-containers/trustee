#!/usr/bin/env bash
# End-to-end check for the SPIRE plugin: registers SPIRE entries, attests
# as the sample TEE, and fetches an X.509-SVID + trust bundle(s) via the
# spire plugin. Assumes `spire-setup.sh` and `deploy-spire` already ran.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${CHART_DIR}/../.." && pwd)"

KBS_CLIENT="${KBS_CLIENT:-${REPO_ROOT}/target/release/kbs-client}"
KBS_CLIENT_SUDO="${KBS_CLIENT_SUDO:-sudo -E}"
KBS_URL="https://127.0.0.1:8080"

SPIRE_NAMESPACE="coco-trustee-e2e"
SPIRE_TRUST_DOMAIN="example.org"
SPIRE_SERVER_POD_SELECTOR="app.kubernetes.io/name=server,app.kubernetes.io/instance=spire"
KBS_SERVICE_ACCOUNT="default"
KBS_SPIFFE_ID="spiffe://${SPIRE_TRUST_DOMAIN}/ns/${SPIRE_NAMESPACE}/sa/${KBS_SERVICE_ACCOUNT}"
WORKLOAD_SPIFFE_ID="spiffe://${SPIRE_TRUST_DOMAIN}/workload/helm-e2e-nginx"

SPIRE_ENTRY_SELECTORS=(
	"k8s:pod-image:bitnami/nginx:latest"
	"trustee:container_uids:65535"
	"trustee:container_uids:1001"
	"trustee:true"
)

INIT_DATA_FILE="${REPO_ROOT}/integration-tests/tests/init-data-with-policy.toml"

WORK_DIR="$(mktemp -d)"
ADMIN_TOKEN_FILE="${WORK_DIR}/admin-token"
KBS_CERT_FILE="${WORK_DIR}/kbs-tls.crt"
SVID_RESPONSE_FILE="${WORK_DIR}/svid-response.json"
BUNDLES_RESPONSE_FILE="${WORK_DIR}/bundles-response.json"
PORT_FORWARD_PID=""

cleanup() {
	local code=$?
	if [[ -n "${PORT_FORWARD_PID}" ]] && kill -0 "${PORT_FORWARD_PID}" 2>/dev/null; then
		kill "${PORT_FORWARD_PID}" 2>/dev/null || true
		wait "${PORT_FORWARD_PID}" 2>/dev/null || true
	fi
	rm -rf "${WORK_DIR}"
	exit "${code}"
}
trap cleanup EXIT

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

kbs_client() {
	${KBS_CLIENT_SUDO} "${KBS_CLIENT}" --cert-file "${KBS_CERT_FILE}" "$@"
}

spire_server() {
	local pod
	pod="$(kubectl get pods -n "${SPIRE_NAMESPACE}" -l "${SPIRE_SERVER_POD_SELECTOR}" \
		-o jsonpath='{.items[0].metadata.name}')"
	[[ -n "${pod}" ]] || die "could not find SPIRE server pod (selector: ${SPIRE_SERVER_POD_SELECTOR})"
	kubectl exec -n "${SPIRE_NAMESPACE}" "${pod}" -c spire-server -- /opt/spire/bin/spire-server "$@"
}

agent_spiffe_id() {
	spire_server agent list | grep -m1 '^SPIFFE ID' | awk '{print $NF}'
}

register_spire_entries() {
	local parent_id
	parent_id="$(agent_spiffe_id)"
	[[ -n "${parent_id}" ]] || die "could not determine the attested SPIRE agent's SPIFFE ID"

	log "registering SPIRE entry for KBS's own (delegate) SPIFFE ID: ${KBS_SPIFFE_ID} (parent: ${parent_id})"
	spire_server entry create \
		-spiffeID "${KBS_SPIFFE_ID}" \
		-parentID "${parent_id}" \
		-selector "k8s:ns:${SPIRE_NAMESPACE}" \
		-selector "k8s:sa:${KBS_SERVICE_ACCOUNT}"

	log "registering SPIRE entry for the attested workload: ${WORKLOAD_SPIFFE_ID} (parent: ${parent_id})"
	local selector_args=()
	local sel
	for sel in "${SPIRE_ENTRY_SELECTORS[@]}"; do
		selector_args+=(-selector "${sel}")
	done
	spire_server entry create \
		-spiffeID "${WORKLOAD_SPIFFE_ID}" \
		-parentID "${parent_id}" \
		"${selector_args[@]}"
}

wait_for_bootstrap_secret() {
	local secret_name="trustee-e2e-bootstrap-user-keys"
	local i
	for i in $(seq 1 120); do
		if kubectl get secret "${secret_name}" -n "${SPIRE_NAMESPACE}" >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	die "timed out waiting for Secret ${secret_name}"
}

start_port_forward() {
	log "port-forward KBS -> 127.0.0.1:8080"
	kubectl port-forward -n "${SPIRE_NAMESPACE}" svc/trustee-e2e-kbs 8080:8080 >/dev/null 2>&1 &
	PORT_FORWARD_PID=$!
	for _ in $(seq 1 60); do
		if ! kill -0 "${PORT_FORWARD_PID}" 2>/dev/null; then
			die "kubectl port-forward exited unexpectedly"
		fi
		if (echo >/dev/tcp/127.0.0.1/8080) >/dev/null 2>&1; then
			sleep 2
			return 0
		fi
		sleep 1
	done
	die "KBS not reachable on 127.0.0.1:8080 after port-forward"
}

fetch_resource_with_retry() {
	local path="$1" out_file="$2"
	local attempts=5 delay=3
	local i
	for ((i = 1; i <= attempts; i++)); do
		if kbs_client --url "${KBS_URL}" get-resource \
			--path "${path}" \
			--plugin "spire" \
			--init-data "$(cat "${INIT_DATA_FILE}")" \
			| base64 -d >"${out_file}"; then
			return 0
		fi
		log "get-resource ${path} failed (attempt ${i}/${attempts}); retrying in ${delay}s"
		sleep "${delay}"
	done
	die "get-resource ${path} failed after ${attempts} attempts"
}

check_svid_response() {
	local svid_file="$1" expected_spiffe_id="$2"
	grep -Eq "\"spiffe_id\"[[:space:]]*:[[:space:]]*\"${expected_spiffe_id}\"" "${svid_file}" \
		|| die "unexpected spiffe_id in ${svid_file} (expected ${expected_spiffe_id})"
}

main() {
	require_cmd kubectl
	require_cmd base64
	require_cmd seq

	[[ -x "${KBS_CLIENT}" ]] || die "kbs-client not found at ${KBS_CLIENT} (set KBS_CLIENT to a pre-built binary)"
	[[ -f "${INIT_DATA_FILE}" ]] || die "init-data fixture not found: ${INIT_DATA_FILE}"

	register_spire_entries

	wait_for_bootstrap_secret
	start_port_forward

	kubectl get secret trustee-e2e-kbs-tls -n "${SPIRE_NAMESPACE}" \
		-o "jsonpath={.data.tls\\.crt}" \
		| base64 -d >"${KBS_CERT_FILE}"
	[[ -s "${KBS_CERT_FILE}" ]] ||
		die "certificate data key tls.crt is empty in Secret trustee-e2e-kbs-tls"

	kubectl get secret trustee-e2e-bootstrap-user-keys -n "${SPIRE_NAMESPACE}" \
		-o "jsonpath={.data.KBS_ADMIN_TOKEN}" | base64 -d >"${ADMIN_TOKEN_FILE}"

	log "set resource policy"
	kbs_client --url "${KBS_URL}" config \
		--admin-token-file "${ADMIN_TOKEN_FILE}" \
		set-resource-policy \
		--allow-all

	log "attest (sample TEE) + fetch X.509-SVID via the spire plugin's x509-svid resource"
	fetch_resource_with_retry "x509-svid" "${SVID_RESPONSE_FILE}"

	log "fetch trust bundle(s) via the spire plugin's x509-bundles resource"
	fetch_resource_with_retry "x509-bundles" "${BUNDLES_RESPONSE_FILE}"

	check_svid_response "${SVID_RESPONSE_FILE}" "${WORKLOAD_SPIFFE_ID}"

	log "spire plugin e2e passed"
}

main "$@"
