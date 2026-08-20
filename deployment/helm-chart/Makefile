# Helm chart end-to-end tests (Trustee deploy + kbs-client + undeploy).
#
# Prerequisites: helm, kubectl, base64, diff, openssl, and a pre-built kbs-client.
# A Kubernetes cluster must already exist (kind recommended). Cluster creation is out of band.
#
# Images must already be loaded into the target Kubernetes cluster before running e2e-test.

REPO_ROOT := $(abspath ../..)
CHART_DIR := $(abspath .)
KBS_CLIENT ?= $(REPO_ROOT)/target/release/kbs-client

# When set (e.g. EXPECTED_TEE=tdx), the e2e client additionally asserts that the
# attestation evidence was produced by this TEE type, turning the leg into a real
# hardware-path check. Empty by default so non-TEE / local runs are unaffected.
EXPECTED_TEE ?=

E2E_IMAGE_PREFIX ?= trustee-e2e
E2E_IMAGE_TAG ?= e2e
E2E_IMAGE_PULL_POLICY ?= Never

# Base e2e scenario file. Override this to switch scenario per run.
E2E_BASE_SCENARIO ?= $(CHART_DIR)/scenarios/e2e-local-images.yaml

E2E_SPIRE_SCENARIO ?= $(CHART_DIR)/scenarios/spire.yaml

# Optional extra Helm args for scenario-specific runtime settings.
HELM_E2E_EXTRA_ARGS ?=

# kind cluster used by load-e2e-images-into-kind (override for parallel/self-hosted runs).
KIND_CLUSTER ?= kind

E2E_KBS_IMAGE_REPOSITORY := $(E2E_IMAGE_PREFIX)/kbs-grpc-as
E2E_AS_IMAGE_REPOSITORY := $(E2E_IMAGE_PREFIX)/coco-as-grpc
E2E_RVPS_IMAGE_REPOSITORY := $(E2E_IMAGE_PREFIX)/rvps

E2E_KBS_IMAGE := $(E2E_KBS_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)
E2E_AS_IMAGE := $(E2E_AS_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)
E2E_RVPS_IMAGE := $(E2E_RVPS_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)

HELM_E2E_IMAGE_ARGS := \
	--set-string kbs.image.repository='$(E2E_KBS_IMAGE_REPOSITORY)' \
	--set-string kbs.image.tag='$(E2E_IMAGE_TAG)' \
	--set-string kbs.image.pullPolicy='$(E2E_IMAGE_PULL_POLICY)' \
	--set-string as.image.repository='$(E2E_AS_IMAGE_REPOSITORY)' \
	--set-string as.image.tag='$(E2E_IMAGE_TAG)' \
	--set-string as.image.pullPolicy='$(E2E_IMAGE_PULL_POLICY)' \
	--set-string rvps.image.repository='$(E2E_RVPS_IMAGE_REPOSITORY)' \
	--set-string rvps.image.tag='$(E2E_IMAGE_TAG)' \
	--set-string rvps.image.pullPolicy='$(E2E_IMAGE_PULL_POLICY)' \
	$(HELM_E2E_EXTRA_ARGS)

HELM_E2E_SCENARIO_YAML := -f '$(E2E_BASE_SCENARIO)'

export KBS_CLIENT
export EXPECTED_TEE

.PHONY: e2e-test deploy undeploy test-client check-tools wait-ready \
	check-docker helm-dependency-build helm-lint \
	load-e2e-images-into-kind prepare-e2e-tls dump-logs \
	install-spire-stack deploy-spire test-client-spire e2e-test-spire

check-tools:
	@command -v helm >/dev/null || (echo "missing: helm" >&2; exit 1)
	@command -v kubectl >/dev/null || (echo "missing: kubectl" >&2; exit 1)
	@command -v base64 >/dev/null || (echo "missing: base64" >&2; exit 1)
	@command -v diff >/dev/null || (echo "missing: diff" >&2; exit 1)

check-docker:
	@command -v docker >/dev/null || (echo "missing: docker" >&2; exit 1)

helm-dependency-build: check-tools
	helm dependency build '$(CHART_DIR)'

helm-lint: helm-dependency-build
	helm lint '$(CHART_DIR)'
	helm lint '$(CHART_DIR)' $(HELM_E2E_SCENARIO_YAML) $(HELM_E2E_IMAGE_ARGS)
	helm lint '$(CHART_DIR)' -f '$(CHART_DIR)/scenarios/native-tls.yaml'

load-e2e-images-into-kind: check-docker
	@command -v kind >/dev/null || (echo "missing: kind (required to load local images)" >&2; exit 1)
	@echo "==> loading images into kind cluster $(KIND_CLUSTER)"
	kind load docker-image --name '$(KIND_CLUSTER)' \
		'$(E2E_KBS_IMAGE)' '$(E2E_AS_IMAGE)' '$(E2E_RVPS_IMAGE)'

prepare-e2e-tls: check-tools
	@command -v openssl >/dev/null || (echo "missing: openssl" >&2; exit 1)
	@work_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$work_dir"' EXIT; \
	kubectl create namespace coco-trustee-e2e \
		--dry-run=client -o yaml | kubectl apply -f -; \
	openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
		-keyout "$$work_dir/tls.key" \
		-out "$$work_dir/tls.crt" \
		-subj '/CN=127.0.0.1' \
		-addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
		-addext 'basicConstraints=CA:FALSE' >/dev/null 2>&1; \
	kubectl create secret tls trustee-e2e-kbs-tls \
		--namespace coco-trustee-e2e \
		--key "$$work_dir/tls.key" \
		--cert "$$work_dir/tls.crt" \
		--dry-run=client -o yaml | kubectl apply -f -

deploy: helm-lint prepare-e2e-tls
	helm upgrade --install trustee-e2e '$(CHART_DIR)' \
		--namespace coco-trustee-e2e \
		--create-namespace \
		$(HELM_E2E_SCENARIO_YAML) \
		$(HELM_E2E_IMAGE_ARGS) \
		--wait \
		--timeout 20m

wait-ready: check-tools
	kubectl wait --for=condition=available deployment/trustee-e2e-rvps -n coco-trustee-e2e --timeout=600s
	kubectl wait --for=condition=available deployment/trustee-e2e-as -n coco-trustee-e2e --timeout=600s
	kubectl wait --for=condition=available deployment/trustee-e2e-kbs -n coco-trustee-e2e --timeout=600s

undeploy: check-tools
	helm uninstall trustee-e2e -n coco-trustee-e2e 2>/dev/null || true
	kubectl delete namespace coco-trustee-e2e --ignore-not-found --timeout=120s 2>/dev/null || true

# Print pod/cluster diagnostics before teardown so CI failures are actionable.
# Must run while the namespace still exists (before undeploy).
dump-logs: check-tools
	@echo "==> cluster state (namespace coco-trustee-e2e)"
	-kubectl get pods,jobs,deploy,svc -n coco-trustee-e2e -o wide 2>&1 || true
	-kubectl get events -n coco-trustee-e2e --sort-by='.lastTimestamp' 2>&1 || true
	@echo "==> pod descriptions"
	-kubectl describe pods -n coco-trustee-e2e 2>&1 || true
	@echo "==> container logs"
	@pods=$$(kubectl get pods -n coco-trustee-e2e -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true); \
	if [ -z "$$pods" ]; then \
		echo "(no pods found in coco-trustee-e2e)"; \
	else \
		for pod in $$pods; do \
			echo "---- logs: $$pod (current) ----"; \
			kubectl logs -n coco-trustee-e2e "$$pod" --all-containers --prefix --timestamps 2>&1 || true; \
			echo "---- logs: $$pod (previous) ----"; \
			kubectl logs -n coco-trustee-e2e "$$pod" --all-containers --prefix --timestamps --previous 2>&1 || true; \
		done; \
	fi

test-client: check-tools wait-ready
	@chmod +x '$(CHART_DIR)/e2e/test.sh'
	@'$(CHART_DIR)/e2e/test.sh'

# Deploy, test, then always undeploy. Images must already be present in the cluster.
# On failure, dump container logs before undeploy so they appear in CI output.
e2e-test: check-tools
	@status=0; \
	if [ $$status -eq 0 ]; then \
		$(MAKE) deploy || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		$(MAKE) test-client || status=$$?; \
	fi; \
	if [ $$status -ne 0 ]; then \
		$(MAKE) dump-logs || true; \
	fi; \
	$(MAKE) undeploy || true; \
	exit $$status

install-spire-stack: check-tools
	@chmod +x '$(CHART_DIR)/e2e/spire-setup.sh'
	@'$(CHART_DIR)/e2e/spire-setup.sh'

deploy-spire: helm-lint prepare-e2e-tls install-spire-stack
	helm upgrade --install trustee-e2e '$(CHART_DIR)' \
		--namespace coco-trustee-e2e \
		--create-namespace \
		-f '$(E2E_BASE_SCENARIO)' \
		-f '$(E2E_SPIRE_SCENARIO)' \
		$(HELM_E2E_IMAGE_ARGS) \
		--wait \
		--timeout 20m

test-client-spire: check-tools wait-ready
	@chmod +x '$(CHART_DIR)/e2e/spire-test.sh'
	@'$(CHART_DIR)/e2e/spire-test.sh'

# Deploy SPIRE + Trustee, test the plugin, then always undeploy.
e2e-test-spire: check-tools
	@status=0; \
	if [ $$status -eq 0 ]; then \
		$(MAKE) deploy-spire || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		$(MAKE) test-client-spire || status=$$?; \
	fi; \
	if [ $$status -ne 0 ]; then \
		$(MAKE) dump-logs || true; \
	fi; \
	$(MAKE) undeploy || true; \
	exit $$status
