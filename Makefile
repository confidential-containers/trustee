.PHONY: test-all test-unit test-e2e \
	test-kbs-unit test-as-unit test-trustee-cli-unit \
	test-kbs-e2e test-as-e2e \
	test-kbs-vault-e2e test-kbs-docker-e2e \
	kbs-e2e-build kbs-e2e-install-deps kbs-e2e-build-bins \
	kbs-vault-e2e-install-deps kbs-vault-e2e-run \
	as-e2e-install-deps as-e2e-run

# Aggregate targets
test-all: test-unit test-e2e

test-unit: test-kbs-unit test-as-unit test-trustee-cli-unit

test-e2e: test-kbs-e2e test-as-e2e

# KBS: lint, fmt, unit/integration tests
test-kbs-unit:
	$(MAKE) -C kbs lint TEST_FEATURES="$(TEST_FEATURES)"
	$(MAKE) -C kbs format
	$(MAKE) -C kbs check TEST_FEATURES="$(TEST_FEATURES)"

# Attestation service / RVPS / shared deps: fmt, clippy, tests
test-as-unit:
	cargo fmt -p attestation-service -p reference-value-provider-service -p eventlog -p verifier -p key-value-storage -p policy-engine --check
	cargo clippy -p attestation-service -p reference-value-provider-service -p eventlog -p verifier -p key-value-storage -p policy-engine -- -D warnings
	cargo test -p attestation-service -p reference-value-provider-service -p verifier -p eventlog -p key-value-storage -p policy-engine

# Trustee CLI: lint, fmt, unit tests
test-trustee-cli-unit:
	$(MAKE) -C tools/trustee-cli lint
	$(MAKE) -C tools/trustee-cli format
	$(MAKE) -C tools/trustee-cli check

# KBS e2e tests (reuses kbs/test Makefile)
# Separate targets for installing dependencies and building binaries
kbs-e2e-install-deps:
	$(MAKE) -C kbs/test install-dev-dependencies

kbs-e2e-build-bins:
	$(MAKE) -C kbs/test bins TEST_FEATURES="$(TEST_FEATURES)"

kbs-e2e-build: kbs-e2e-install-deps kbs-e2e-build-bins

test-kbs-e2e: kbs-e2e-build
	$(MAKE) -C kbs/test e2e-test

# KBS Vault integration e2e (no SSL + SSL)
# Separate targets for installing dependencies and running tests
kbs-vault-e2e-install-deps:
	$(MAKE) -C kbs/test install-dev-dependencies

kbs-vault-e2e-run:
	$(MAKE) -C kbs/test test-vault-nossl
	$(MAKE) -C kbs/test stop-vault
	$(MAKE) -C kbs/test test-vault-ssl
	$(MAKE) -C kbs/test stop-vault-ssl

test-kbs-vault-e2e: kbs-vault-e2e-install-deps kbs-vault-e2e-run

# KBS Docker Compose e2e (cluster with sample TEE)
# Uses a temp dir for config/keys and always runs 'docker compose down -v' on exit.
test-kbs-docker-e2e:
	cargo build --manifest-path tools/kbs-client/Cargo.toml --no-default-features --release
	E2E_DIR=$$(mktemp -d) && \
	trap "docker compose -f $(CURDIR)/docker-compose.yml --project-directory $$E2E_DIR down -v; sudo rm -rf $$E2E_DIR || true" EXIT && \
	set -e && \
	mkdir -p $$E2E_DIR/kbs/config/docker-compose $$E2E_DIR/kbs/data/kbs-storage $$E2E_DIR/kbs/data/nebula-ca $$E2E_DIR/kbs/data/attestation-service $$E2E_DIR/kbs/data/reference-values && \
	cp $(CURDIR)/kbs/config/docker-compose/as-config.json \
		$(CURDIR)/kbs/config/docker-compose/rvps.json \
		$(CURDIR)/kbs/config/docker-compose/kbs-config.toml \
		$(CURDIR)/kbs/config/docker-compose/setup.sh \
		$$E2E_DIR/kbs/config/docker-compose/ && \
	docker compose -f $(CURDIR)/docker-compose.yml build --build-arg BUILDPLATFORM="$${BUILD_PLATFORM:-linux/amd64}" --build-arg ARCH="$${TARGET_ARCH:-x86_64}" --build-arg VERIFIER="$${VERIFIER:-all-verifier}" && \
	docker compose -f $(CURDIR)/docker-compose.yml --project-directory $$E2E_DIR up -d && \
	cd $(CURDIR)/target/release && \
	echo "shhhhh" > test-secret && \
	./kbs-client --url http://127.0.0.1:8080 config --admin-token-file $$E2E_DIR/kbs/config/docker-compose/admin-token set-resource --path "test-org/test-repo/test-secret" --resource-file test-secret && \
	! ./kbs-client --url http://127.0.0.1:8080 get-resource --path "test-org/test-repo/test-secret" && \
	./kbs-client --url http://127.0.0.1:8080 config --admin-token-file $$E2E_DIR/kbs/config/docker-compose/admin-token set-resource-policy --policy-file "$(CURDIR)/kbs/test/data/policy_2.rego" && \
	./kbs-client --url http://127.0.0.1:8080 get-resource --path "test-org/test-repo/test-secret"

# Attestation service e2e tests
# Separate targets for installing dependencies and running tests
as-e2e-install-deps:
	$(MAKE) -C attestation-service/tests/e2e install-dependencies

as-e2e-run:
	$(MAKE) -C attestation-service/tests/e2e e2e-grpc-test
	$(MAKE) -C attestation-service/tests/e2e e2e-restful-test

test-as-e2e: as-e2e-install-deps as-e2e-run

