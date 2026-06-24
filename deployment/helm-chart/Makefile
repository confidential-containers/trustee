# Helm chart end-to-end tests (Trustee deploy + kbs-client + undeploy).
#
# Prerequisites: helm, kubectl, base64, diff, and a pre-built kbs-client.
# A Kubernetes cluster must already exist (kind recommended). Cluster creation is out of band.
#
# Images must already be loaded into the target Kubernetes cluster before running e2e-test.

REPO_ROOT := $(abspath ../..)
CHART_DIR := $(abspath .)
KBS_CLIENT ?= $(REPO_ROOT)/target/release/kbs-client

E2E_IMAGE_PREFIX ?= trustee-e2e
E2E_IMAGE_TAG ?= e2e

E2E_KBS_IMAGE_REPOSITORY := $(E2E_IMAGE_PREFIX)/kbs-grpc-as
E2E_AS_IMAGE_REPOSITORY := $(E2E_IMAGE_PREFIX)/coco-as-grpc
E2E_RVPS_IMAGE_REPOSITORY := $(E2E_IMAGE_PREFIX)/rvps

E2E_KBS_IMAGE := $(E2E_KBS_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)
E2E_AS_IMAGE := $(E2E_AS_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)
E2E_RVPS_IMAGE := $(E2E_RVPS_IMAGE_REPOSITORY):$(E2E_IMAGE_TAG)

HELM_E2E_IMAGE_ARGS := \
	--set-string kbs.image.repository='$(E2E_KBS_IMAGE_REPOSITORY)' \
	--set-string kbs.image.tag='$(E2E_IMAGE_TAG)' \
	--set-string kbs.image.pullPolicy='Never' \
	--set-string as.image.repository='$(E2E_AS_IMAGE_REPOSITORY)' \
	--set-string as.image.tag='$(E2E_IMAGE_TAG)' \
	--set-string as.image.pullPolicy='Never' \
	--set-string rvps.image.repository='$(E2E_RVPS_IMAGE_REPOSITORY)' \
	--set-string rvps.image.tag='$(E2E_IMAGE_TAG)' \
	--set-string rvps.image.pullPolicy='Never'

export KBS_CLIENT

.PHONY: e2e-test deploy undeploy test-client check-tools wait-ready \
	check-docker helm-dependency-build helm-lint load-e2e-images-into-kind

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
	helm lint '$(CHART_DIR)' -f '$(CHART_DIR)/scenarios/e2e-local-images.yaml' $(HELM_E2E_IMAGE_ARGS)

load-e2e-images-into-kind: check-docker
	@command -v kind >/dev/null || (echo "missing: kind (required to load local images)" >&2; exit 1)
	@echo "==> loading images into kind cluster kind"
	kind load docker-image --name kind \
		'$(E2E_KBS_IMAGE)' '$(E2E_AS_IMAGE)' '$(E2E_RVPS_IMAGE)'

deploy: helm-lint
	helm upgrade --install trustee-e2e '$(CHART_DIR)' \
		--namespace coco-trustee-e2e \
		--create-namespace \
		-f '$(CHART_DIR)/scenarios/e2e-local-images.yaml' \
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

test-client: check-tools wait-ready
	@chmod +x '$(CHART_DIR)/e2e/test.sh'
	@'$(CHART_DIR)/e2e/test.sh'

# Deploy, test, then always undeploy. Images must already be present in the cluster.
e2e-test: check-tools
	@status=0; \
	if [ $$status -eq 0 ]; then \
		$(MAKE) deploy || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		$(MAKE) test-client || status=$$?; \
	fi; \
	$(MAKE) undeploy || true; \
	exit $$status
