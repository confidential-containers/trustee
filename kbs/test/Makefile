ARCH := $(shell uname -m)
OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
CODENAME := $(shell lsb_release -sc)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
KBS_CONFIG_PATH := ./config
QCNL_CONF_PATH := $(shell mktemp --suffix=.kbs-qcnl.conf)
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/..
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)
TEE ?= sample
WORK_DIR := $(MAKEFILE_DIR)/work
KBS_REPO_PATH := $(WORK_DIR)/repository
ATTESTATION_TOKEN := $(WORK_DIR)/attestation_token
ROUNDTRIP_FILE := $(WORK_DIR)/secret
REPOSITORY_SECRET := one/two/three
SECRET_FILE := $(KBS_REPO_PATH)/$(REPOSITORY_SECRET)

# match those with the entries in the config/*.toml files
CA_KEY := $(WORK_DIR)/ca.key
CA_CSR := $(WORK_DIR)/ca-req.csr
CA_CERT := $(WORK_DIR)/ca-cert.pem
TOKEN_KEY := $(WORK_DIR)/token.key
TOKEN_CSR := $(WORK_DIR)/token-req.csr
TOKEN_CERT := $(WORK_DIR)/token-cert.pem
TOKEN_CERT_CHAIN := $(WORK_DIR)/token-cert-chain.pem
KBS_KEY := $(WORK_DIR)/kbs.key
KBS_PEM := $(WORK_DIR)/kbs.pem
TEE_KEY := $(WORK_DIR)/tee.key
HTTPS_KEY := $(WORK_DIR)/https.key
HTTPS_CERT := $(WORK_DIR)/https.crt
KBS_POLICY := $(WORK_DIR)/kbs-policy.rego
EXT_PLUGIN_ATTEST_POLICY := $(WORK_DIR)/ext-plugin-attest-policy.rego
PLUGIN_ATTESTATION_TOKEN := $(WORK_DIR)/plugin-attestation-token

# External plugin test certificates
ECHO_PLUGIN_CA_KEY := $(WORK_DIR)/echo-plugin-ca.key
ECHO_PLUGIN_CA_CERT := $(WORK_DIR)/echo-plugin-ca.pem
ECHO_PLUGIN_SERVER_KEY := $(WORK_DIR)/echo-plugin-server.key
ECHO_PLUGIN_SERVER_CERT := $(WORK_DIR)/echo-plugin-server.pem

TEST_FEATURES ?=
TEST_ARGUMENTS ?=

SHELL := bash
ifneq ($(OS),Ubuntu)
    $(error "This Makefile requires Ubuntu")
endif

define TEE_POLICY_REGO
package policy

default allow = false

allow if {
	data.plugin == "resource"
	data["resource-path"][0] == "one"
	data["resource-path"][1] == "two"
	data["resource-path"][2] == "three"
	input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["$(TEE)"]
}
endef
export TEE_POLICY_REGO

define EXT_PLUGIN_POLICY_REGO
package policy

default allow = false

allow if {
	data.plugin == "echo-test"
	input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["$(TEE)"]
}
endef
export EXT_PLUGIN_POLICY_REGO

ifneq ($(TEST_FEATURES),)
  TEST_ARGUMENTS = --no-default-features --features $(TEST_FEATURES)
endif

.PHONY: install-dev-dependencies
install-dev-dependencies: install-dependencies
	sudo apt-get update && \
	sudo apt-get install -y \
		build-essential \
		clang \
		libssl-dev \
		libtss2-dev \
		pkg-config \
		protobuf-compiler && \
	if [ "${ARCH}" = "x86_64" ]; then \
	sudo apt-get install -y \
		libsgx-dcap-quote-verify-dev; fi

.PHONY: install-dependencies
install-dependencies:
	if [ "${ARCH}" = "x86_64" ]; then \
	curl -L "$(SGX_REPO_URL)/intel-sgx-deb.key" | sudo gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg --yes && \
	echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] $(SGX_REPO_URL) $(CODENAME) main" \
		| sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
	sudo apt-get update && \
	sudo apt-get install -y \
		libsgx-dcap-default-qpl \
		libsgx-dcap-quote-verify \
		libsgx-urts \
		libtss2-esys-3.0.2-0 \
		libtss2-tctildr0 \
		openssl; fi

kbs:
	cd $(PROJECT_DIR) && \
	make background-check-kbs && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs $(CURDIR)/kbs

resource-kbs:
	cd $(PROJECT_DIR) && \
	make passport-resource-kbs && \
	install -D --compare $(PROJECT_DIR)/../target/release/resource-kbs $(CURDIR)/resource-kbs

client:
	cd $(PROJECT_DIR) && \
	cargo build -p kbs-client --release $(TEST_ARGUMENTS) && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs-client $(CURDIR)/client

# Build external plugin echo test server
echo-plugin:
	cd $(PROJECT_DIR) && \
	cargo build --release --bin external_plugin_test_server --features external-plugin && \
	install -D --compare $(PROJECT_DIR)/../target/release/external_plugin_test_server $(CURDIR)/echo-plugin

# Build KBS with external-plugin feature
ext-plugin-kbs:
	cd $(PROJECT_DIR) && \
	make background-check-kbs-external-plugin && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs $(CURDIR)/ext-plugin-kbs

.PHONY: bins
bins: kbs resource-kbs client

$(CA_KEY):
	openssl genrsa -traditional -out $(CA_KEY) 2048

$(CA_CERT): $(CA_KEY)
	openssl req -new -key "$(CA_KEY)" -out "$(CA_CSR)" \
		-subj "/O=CNCF/OU=CoCo/CN=KBS-test-root" && \
	openssl req -x509 -days 3650 -key "$(CA_KEY)" -in "$(CA_CSR)" -out "$(CA_CERT)"

$(TOKEN_KEY):
	openssl ecparam -name prime256v1 -genkey -noout -out "$@"

$(TOKEN_CERT): $(TOKEN_KEY) $(CA_CERT) $(CA_KEY)
	openssl req -new -key "$(TOKEN_KEY)" -out "$(TOKEN_CSR)" \
		-subj "/O=CNCF/OU=CoCo/CN=CoCo-AS" && \
	openssl x509 -req -in "$(TOKEN_CSR)" -CA "$(CA_CERT)" -CAkey "$(CA_KEY)" \
		-CAcreateserial -out $(TOKEN_CERT) -extensions req_ext

$(TOKEN_CERT_CHAIN): $(TOKEN_CERT) $(CA_CERT)
	cat "$(TOKEN_CERT)" "$(CA_CERT)" > "$(TOKEN_CERT_CHAIN)"

.PHONY: generate-attestation-token-signer
generate-attestation-token-signer: $(TOKEN_CERT_CHAIN)

$(HTTPS_KEY) $(HTTPS_CERT):
	openssl req -x509 -out "$(HTTPS_CERT)" -keyout "$(HTTPS_KEY)" \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=kbs.coco' \
		--addext "subjectAltName=IP:127.0.0.1" \
		--addext "basicConstraints=CA:FALSE"

$(KBS_KEY):
	openssl genpkey -algorithm ed25519 > "$(KBS_KEY)"

$(KBS_PEM): $(KBS_KEY)
	openssl pkey -in "$(KBS_KEY)" -pubout -out "$(KBS_PEM)"

$(TEE_KEY):
	openssl genrsa -traditional -out "$(TEE_KEY)" 2048

$(SECRET_FILE):
	mkdir -p $$(dirname "$(SECRET_FILE)") && \
	openssl rand 16 > "$(SECRET_FILE)"

.PHONY: start-kbs
start-kbs: kbs.PID

.PHONY: start-resource-kbs
start-resource-kbs: resource-kbs.PID

kbs-keys: $(KBS_KEY) $(TOKEN_KEY) $(HTTPS_KEY)

kbs-certs: $(KBS_PEM) $(TOKEN_CERT_CHAIN) $(HTTPS_CERT)

kbs.PID: kbs kbs-keys kbs-certs $(SECRET_FILE)
	@printf "${BOLD}start kbs${SGR0}\n"
	{ \
		"$(CURDIR)/kbs" --config-file "$(KBS_CONFIG_PATH)/kbs.toml" \
		& echo $$! > kbs.PID; \
	} && \
	sleep 1

resource-kbs.PID: resource-kbs $(KBS_PEM) $(CA_CERT) $(SECRET_FILE)
	@printf "${BOLD}start resource-kbs${SGR0}\n"
	{ \
		./resource-kbs --config-file "$(KBS_CONFIG_PATH)/resource-kbs.toml" \
		& echo $$! > resource-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-kbs
stop-kbs: kbs.PID
	@printf "${BOLD}stop kbs${SGR0}\n"
	kill $$(cat $<) && rm $<

.PHONY: stop-resource-kbs
stop-resource-kbs: resource-kbs.PID
	@printf "${BOLD}stop resource-kbs${SGR0}\n"
	kill $$(cat $<) && rm $<

test-bgcheck: client start-kbs
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-resource-policy \
		--policy-file <(echo "$$TEE_POLICY_REGO") && \
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		get-resource \
		--path "$(REPOSITORY_SECRET)" \
		| base64 -d > "$(ROUNDTRIP_FILE)" && \
	diff "$(ROUNDTRIP_FILE)" "$(SECRET_FILE)"
	@printf "${BOLD}background-check e2e test passed${SGR0}\n"

.PHONY: $(ATTESTATION_TOKEN)
$(ATTESTATION_TOKEN): client $(TEE_KEY) start-kbs
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		attest \
		--tee-key-file "$(TEE_KEY)" \
		> "$(ATTESTATION_TOKEN)"

test-passport: client $(ATTESTATION_TOKEN) start-resource-kbs
	./client --url http://127.0.0.1:50002 \
		config --auth-private-key "$(KBS_KEY)" \
		set-resource-policy --policy-file <(echo "$$TEE_POLICY_REGO") && \
	./client --url http://127.0.0.1:50002 get-resource \
		--attestation-token "$(ATTESTATION_TOKEN)" \
		--tee-key-file "$(TEE_KEY)" \
		--path $(REPOSITORY_SECRET) \
		| base64 -d > "$(ROUNDTRIP_FILE)" && \
	diff "$(SECRET_FILE)" "$(ROUNDTRIP_FILE)"
	@printf "${BOLD}passport e2e test passed${SGR0}\n"

.PHONY: stop
stop: stop-kbs stop-resource-kbs stop-ext-plugins

.PHONY: e2e-test
e2e-test: test-bgcheck test-passport stop

# External plugin certificate generation
$(ECHO_PLUGIN_CA_KEY):
	mkdir -p $(WORK_DIR) && \
	openssl genrsa -out $(ECHO_PLUGIN_CA_KEY) 4096

$(ECHO_PLUGIN_CA_CERT): $(ECHO_PLUGIN_CA_KEY)
	openssl req -new -x509 -key $(ECHO_PLUGIN_CA_KEY) -out $(ECHO_PLUGIN_CA_CERT) -days 365 \
		-subj "/C=US/ST=CA/L=Test/O=Test/OU=EchoPlugin/CN=Echo Plugin CA"

$(ECHO_PLUGIN_SERVER_KEY):
	mkdir -p $(WORK_DIR) && \
	openssl genrsa -out $(ECHO_PLUGIN_SERVER_KEY) 4096

$(ECHO_PLUGIN_SERVER_CERT): $(ECHO_PLUGIN_SERVER_KEY) $(ECHO_PLUGIN_CA_CERT) $(ECHO_PLUGIN_CA_KEY)
	openssl req -new -key $(ECHO_PLUGIN_SERVER_KEY) -out $(WORK_DIR)/echo-plugin-server.csr \
		-subj "/C=US/ST=CA/L=Test/O=Test/OU=EchoPlugin/CN=127.0.0.1" && \
	echo -e "[v3_req]\nsubjectAltName=IP:127.0.0.1,DNS:localhost" > $(WORK_DIR)/echo-plugin-server.conf && \
	openssl x509 -req -in $(WORK_DIR)/echo-plugin-server.csr -CA $(ECHO_PLUGIN_CA_CERT) -CAkey $(ECHO_PLUGIN_CA_KEY) \
		-CAcreateserial -out $(ECHO_PLUGIN_SERVER_CERT) -days 365 -extensions v3_req \
		-extfile $(WORK_DIR)/echo-plugin-server.conf

# Start plaintext echo plugin server on :50051
.PHONY: start-echo-plugin
start-echo-plugin: echo-plugin.PID

echo-plugin.PID: echo-plugin
	@printf "${BOLD}start echo plugin (plaintext)${SGR0}\n"
	{ \
		ECHO_PLUGIN_LISTEN_ADDR=127.0.0.1:50051 \
		"$(CURDIR)/echo-plugin" \
		& echo $$! > echo-plugin.PID; \
	} && \
	sleep 1

# Start TLS echo plugin server on :50052
.PHONY: start-echo-plugin-tls
start-echo-plugin-tls: echo-plugin-tls.PID

echo-plugin-tls.PID: echo-plugin $(ECHO_PLUGIN_SERVER_CERT) $(ECHO_PLUGIN_SERVER_KEY)
	@printf "${BOLD}start echo plugin (TLS)${SGR0}\n"
	{ \
		ECHO_PLUGIN_LISTEN_ADDR=127.0.0.1:50052 \
		ECHO_PLUGIN_TLS_CERT=$(ECHO_PLUGIN_SERVER_CERT) \
		ECHO_PLUGIN_TLS_KEY=$(ECHO_PLUGIN_SERVER_KEY) \
		"$(CURDIR)/echo-plugin" \
		& echo $$! > echo-plugin-tls.PID; \
	} && \
	sleep 1

# Start KBS with external-plugin config (insecure, port 8085)
.PHONY: start-ext-plugin-kbs
start-ext-plugin-kbs: ext-plugin-kbs.PID

ext-plugin-kbs.PID: ext-plugin-kbs
	@printf "${BOLD}start ext-plugin-kbs (insecure)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin.toml" \
		& echo $$! > ext-plugin-kbs.PID; \
	} && \
	sleep 1

# Start KBS with external-plugin TLS config (port 8086)
.PHONY: start-ext-plugin-tls-kbs
start-ext-plugin-tls-kbs: ext-plugin-tls-kbs.PID

ext-plugin-tls-kbs.PID: ext-plugin-kbs $(ECHO_PLUGIN_CA_CERT)
	@printf "${BOLD}start ext-plugin-kbs (TLS)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin-tls.toml" \
		& echo $$! > ext-plugin-tls-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-echo-plugin
stop-echo-plugin:
	@if [ -f echo-plugin.PID ]; then \
		printf "${BOLD}stop echo plugin (plaintext)${SGR0}\n"; \
		kill $$(cat echo-plugin.PID) && rm echo-plugin.PID || rm -f echo-plugin.PID; \
	fi

.PHONY: stop-echo-plugin-tls
stop-echo-plugin-tls:
	@if [ -f echo-plugin-tls.PID ]; then \
		printf "${BOLD}stop echo plugin (TLS)${SGR0}\n"; \
		kill $$(cat echo-plugin-tls.PID) && rm echo-plugin-tls.PID || rm -f echo-plugin-tls.PID; \
	fi

.PHONY: stop-ext-plugin-kbs
stop-ext-plugin-kbs:
	@if [ -f ext-plugin-kbs.PID ]; then \
		printf "${BOLD}stop ext-plugin-kbs (insecure)${SGR0}\n"; \
		kill $$(cat ext-plugin-kbs.PID) && rm ext-plugin-kbs.PID || rm -f ext-plugin-kbs.PID; \
	fi

.PHONY: stop-ext-plugin-tls-kbs
stop-ext-plugin-tls-kbs:
	@if [ -f ext-plugin-tls-kbs.PID ]; then \
		printf "${BOLD}stop ext-plugin-kbs (TLS)${SGR0}\n"; \
		kill $$(cat ext-plugin-tls-kbs.PID) && rm ext-plugin-tls-kbs.PID || rm -f ext-plugin-tls-kbs.PID; \
	fi

# Write the attestation policy for external plugin test
$(EXT_PLUGIN_ATTEST_POLICY):
	echo "$$EXT_PLUGIN_POLICY_REGO" > $(EXT_PLUGIN_ATTEST_POLICY)

# Start KBS with external-plugin attestation config (HTTPS, port 8087)
.PHONY: start-ext-plugin-attest-kbs
start-ext-plugin-attest-kbs: ext-plugin-attest-kbs.PID

ext-plugin-attest-kbs.PID: ext-plugin-kbs kbs-keys kbs-certs $(EXT_PLUGIN_ATTEST_POLICY)
	@printf "${BOLD}start ext-plugin-kbs (attestation)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin-attest.toml" \
		& echo $$! > ext-plugin-attest-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-ext-plugin-attest-kbs
stop-ext-plugin-attest-kbs:
	@if [ -f ext-plugin-attest-kbs.PID ]; then \
		printf "${BOLD}stop ext-plugin-kbs (attestation)${SGR0}\n"; \
		kill $$(cat ext-plugin-attest-kbs.PID) && rm ext-plugin-attest-kbs.PID || rm -f ext-plugin-attest-kbs.PID; \
	fi

# Get attestation token for external plugin test
.PHONY: $(PLUGIN_ATTESTATION_TOKEN)
$(PLUGIN_ATTESTATION_TOKEN): client $(TEE_KEY) start-ext-plugin-attest-kbs
	./client \
		--url https://127.0.0.1:8087 \
		--cert-file "$(HTTPS_CERT)" \
		attest \
		--tee-key-file "$(TEE_KEY)" \
		> "$(PLUGIN_ATTESTATION_TOKEN)"

# External plugin integration test (insecure / plaintext)
.PHONY: test-ext-plugin
test-ext-plugin: start-echo-plugin start-ext-plugin-kbs
	@printf "${BOLD}running external plugin integration test (insecure)${SGR0}\n"
	curl -sf http://127.0.0.1:8085/kbs/v0/echo-test/admin/hello | grep -q "Echo:" && \
	printf "${BOLD}external plugin integration test (insecure) passed${SGR0}\n"

# External plugin integration test (TLS)
.PHONY: test-ext-plugin-tls
test-ext-plugin-tls: start-echo-plugin-tls start-ext-plugin-tls-kbs
	@printf "${BOLD}running external plugin integration test (TLS)${SGR0}\n"
	curl -sf http://127.0.0.1:8086/kbs/v0/echo-test/admin/hello | grep -q "Echo:" && \
	printf "${BOLD}external plugin integration test (TLS) passed${SGR0}\n"

# External plugin integration test (attestation path)
.PHONY: test-ext-plugin-attest
test-ext-plugin-attest: start-echo-plugin $(PLUGIN_ATTESTATION_TOKEN)
	@printf "${BOLD}running external plugin integration test (attestation)${SGR0}\n"
	! curl -sf --cacert "$(HTTPS_CERT)" https://127.0.0.1:8087/kbs/v0/echo-test/hello && \
	curl -sf --cacert "$(HTTPS_CERT)" -H "Authorization: Bearer $$(cat $(PLUGIN_ATTESTATION_TOKEN))" \
		https://127.0.0.1:8087/kbs/v0/echo-test/hello | grep -q "Echo:" && \
	printf "${BOLD}external plugin integration test (attestation) passed${SGR0}\n"

# External plugin metrics test (verifies /metrics endpoint has plugin counters)
# Uses before/after snapshot so the test works regardless of prior requests.
.PHONY: test-ext-plugin-metrics
test-ext-plugin-metrics: start-echo-plugin start-ext-plugin-kbs
	@printf "${BOLD}running external plugin metrics test${SGR0}\n"
	before=$$(curl -sf http://127.0.0.1:8085/metrics | \
		sed -n 's/^kbs_plugin_request_duration_seconds_count{plugin_name="echo-test"} //p'); \
	before=$${before:-0}; \
	curl -sf http://127.0.0.1:8085/kbs/v0/echo-test/admin/hello > /dev/null && \
	curl -sf http://127.0.0.1:8085/kbs/v0/echo-test/admin/hello > /dev/null && \
	after=$$(curl -sf http://127.0.0.1:8085/metrics | \
		sed -n 's/^kbs_plugin_request_duration_seconds_count{plugin_name="echo-test"} //p') && \
	curl -sf http://127.0.0.1:8085/metrics | grep -q 'kbs_plugin_requests_total{plugin_name="echo-test"}' && \
	delta=$$((after - before)) && \
	if [ "$$delta" -eq 2 ]; then \
		printf "${BOLD}external plugin metrics test passed (count delta=%s)${SGR0}\n" "$$delta"; \
	else \
		printf "FAIL: expected delta=2, got delta=%s (before=%s, after=%s)\n" "$$delta" "$$before" "$$after"; \
		exit 1; \
	fi

# Stop all external plugin processes
.PHONY: stop-ext-plugins
stop-ext-plugins: stop-echo-plugin stop-echo-plugin-tls stop-ext-plugin-kbs stop-ext-plugin-tls-kbs stop-ext-plugin-attest-kbs

# Run all external plugin tests with cleanup
.PHONY: e2e-ext-plugin
e2e-ext-plugin:
	@$(MAKE) test-ext-plugin test-ext-plugin-metrics test-ext-plugin-tls test-ext-plugin-attest; \
	status=$$?; \
	$(MAKE) stop-ext-plugins; \
	if [ $$status -eq 0 ]; then \
		printf "${BOLD}all external plugin e2e tests passed${SGR0}\n"; \
	else \
		printf "${BOLD}external plugin e2e tests FAILED${SGR0}\n"; \
		exit 1; \
	fi

# Vault configuration (using OpenBao, an open-source Vault-compatible server)
OPENBAO_VERSION := 2.5.0
OPENBAO_URL := https://github.com/openbao/openbao/releases/download/v$(OPENBAO_VERSION)/bao_$(OPENBAO_VERSION)_Linux_x86_64.tar.gz
VAULT_BIN := $(WORK_DIR)/bao
VAULT_CONFIG := $(WORK_DIR)/vault-config.json
VAULT_SSL_CONFIG := $(WORK_DIR)/vault-ssl-config.json
VAULT_TOKEN_FILE := $(WORK_DIR)/vault-token
VAULT_KBS_CONFIG_PATH := ./config
VAULT_CA_KEY := $(WORK_DIR)/vault-ca.key
VAULT_CA_CERT := $(WORK_DIR)/vault-ca.pem
VAULT_SERVER_KEY := $(WORK_DIR)/vault-server.key
VAULT_SERVER_CERT := $(WORK_DIR)/vault-server.pem

# Download and setup OpenBao binary
$(VAULT_BIN):
	@if [ ! -f $(VAULT_BIN) ]; then \
		printf "${BOLD}downloading openbao binary${SGR0}\n"; \
		mkdir -p $(WORK_DIR) && \
		cd $(WORK_DIR) && \
		curl -L "$(OPENBAO_URL)" -o bao.tar.gz && \
		tar xzf bao.tar.gz bao && \
		chmod +x bao && \
		rm bao.tar.gz; \
	else \
		printf "${BOLD}openbao binary already exists${SGR0}\n"; \
	fi

# Create Vault configuration for kv1 engine
$(VAULT_CONFIG):
	mkdir -p $(WORK_DIR) && \
	echo '{"storage":{"file":{"path":"$(WORK_DIR)/vault-data"}},"listener":{"tcp":{"address":"127.0.0.1:8200","tls_disable":true}},"default_lease_ttl":"168h","max_lease_ttl":"720h","ui":true,"disable_mlock":true}' > $(VAULT_CONFIG)

# Create Vault SSL configuration for kv1 engine
$(VAULT_SSL_CONFIG): $(VAULT_SERVER_CERT) $(VAULT_SERVER_KEY)
	mkdir -p $(WORK_DIR) && \
	echo '{"storage":{"file":{"path":"$(WORK_DIR)/vault-ssl-data"}},"listener":{"tcp":{"address":"127.0.0.1:8200","tls_disable":false,"tls_cert_file":"$(VAULT_SERVER_CERT)","tls_key_file":"$(VAULT_SERVER_KEY)"}},"default_lease_ttl":"168h","max_lease_ttl":"720h","ui":true,"disable_mlock":true}' > $(VAULT_SSL_CONFIG)

# Generate Vault CA certificate for SSL
$(VAULT_CA_KEY):
	openssl genrsa -out $(VAULT_CA_KEY) 4096

$(VAULT_CA_CERT): $(VAULT_CA_KEY)
	openssl req -new -x509 -key $(VAULT_CA_KEY) -out $(VAULT_CA_CERT) -days 365 \
		-subj "/C=US/ST=CA/L=San Francisco/O=Test/OU=Vault/CN=Vault CA"

# Generate Vault server certificate for SSL
$(VAULT_SERVER_KEY):
	openssl genrsa -out $(VAULT_SERVER_KEY) 4096

$(VAULT_SERVER_CERT): $(VAULT_SERVER_KEY) $(VAULT_CA_CERT) $(VAULT_CA_KEY)
	openssl req -new -key $(VAULT_SERVER_KEY) -out $(WORK_DIR)/vault-server.csr \
		-subj "/C=US/ST=CA/L=San Francisco/O=Test/OU=Vault/CN=127.0.0.1" && \
	echo -e "[v3_req]\nsubjectAltName=IP:127.0.0.1,DNS:localhost" > $(WORK_DIR)/vault-server.conf && \
	openssl x509 -req -in $(WORK_DIR)/vault-server.csr -CA $(VAULT_CA_CERT) -CAkey $(VAULT_CA_KEY) \
		-CAcreateserial -out $(VAULT_SERVER_CERT) -days 365 -extensions v3_req \
		-extfile $(WORK_DIR)/vault-server.conf

# Build KBS with vault feature enabled
vault-kbs:
	cd $(PROJECT_DIR) && \
	make background-check-kbs VAULT=true && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs $(CURDIR)/vault-kbs

# Start Vault server with kv1 secrets engine
.PHONY: start-vault
start-vault: vault.PID

vault.PID: $(VAULT_BIN) $(VAULT_CONFIG)
	@if [ ! -f vault.PID ]; then \
		printf "${BOLD}starting vault server${SGR0}\n"; \
		mkdir -p $(WORK_DIR)/vault-data && \
		{ \
			$(VAULT_BIN) server -config=$(VAULT_CONFIG) \
			& echo $$! > vault.PID; \
		} && \
		sleep 3 && \
		export VAULT_ADDR=http://127.0.0.1:8200 && \
		$(VAULT_BIN) operator init -key-shares=1 -key-threshold=1 > $(WORK_DIR)/vault-init.txt && \
		export VAULT_UNSEAL_KEY=$$(grep 'Unseal Key 1:' $(WORK_DIR)/vault-init.txt | cut -d' ' -f4) && \
		export VAULT_ROOT_TOKEN=$$(grep 'Initial Root Token:' $(WORK_DIR)/vault-init.txt | cut -d' ' -f4) && \
		$(VAULT_BIN) operator unseal $$VAULT_UNSEAL_KEY && \
		echo $$VAULT_ROOT_TOKEN > $(VAULT_TOKEN_FILE) && \
		export VAULT_TOKEN=$$VAULT_ROOT_TOKEN && \
		$(VAULT_BIN) secrets enable -version=1 -path=secret kv && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/test-tag data="test-secret-value" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/no-data-key value="some-value" other="content" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/empty-data data="" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/json-preloaded data='{"service":"database","credentials":{"host":"db.example.com","port":5432,"username":"app_user","password":"secure_pass"},"settings":{"max_connections":100,"timeout":30}}' && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/numeric-string data="12345" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/base64-encoded data="SGVsbG8gV29ybGQ=" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/unicode-value data="こんにちは世界" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/url-value data="https://user:pass@host:8080/path?key=val&foo=bar" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/pem-like data="-----BEGIN CERTIFICATE-----MIIBxTCCAW..." && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/whitespace-value data="  leading and trailing  " && \
		printf "${BOLD}vault server started and configured${SGR0}\n"; \
	else \
		printf "${BOLD}vault server already running (vault.PID exists)${SGR0}\n"; \
	fi

.PHONY: stop-vault
stop-vault: vault.PID
	@printf "${BOLD}stopping vault server${SGR0}\n"
	kill $$(cat $<) && rm $< || true

# Start Vault server with SSL enabled
.PHONY: start-vault-ssl
start-vault-ssl: vault-ssl.PID

vault-ssl.PID: $(VAULT_BIN) $(VAULT_SSL_CONFIG)
	@if [ ! -f vault-ssl.PID ]; then \
		printf "${BOLD}starting vault server with SSL${SGR0}\n"; \
		mkdir -p $(WORK_DIR)/vault-ssl-data && \
		{ \
			$(VAULT_BIN) server -config=$(VAULT_SSL_CONFIG) \
			& echo $$! > vault-ssl.PID; \
		} && \
		sleep 3 && \
		export VAULT_ADDR=https://127.0.0.1:8200 && \
		export VAULT_CACERT=$(VAULT_CA_CERT) && \
		$(VAULT_BIN) operator init -key-shares=1 -key-threshold=1 > $(WORK_DIR)/vault-ssl-init.txt && \
		export VAULT_UNSEAL_KEY=$$(grep 'Unseal Key 1:' $(WORK_DIR)/vault-ssl-init.txt | cut -d' ' -f4) && \
		export VAULT_ROOT_TOKEN=$$(grep 'Initial Root Token:' $(WORK_DIR)/vault-ssl-init.txt | cut -d' ' -f4) && \
		$(VAULT_BIN) operator unseal $$VAULT_UNSEAL_KEY && \
		echo $$VAULT_ROOT_TOKEN > $(WORK_DIR)/vault-ssl-token && \
		export VAULT_TOKEN=$$VAULT_ROOT_TOKEN && \
		$(VAULT_BIN) secrets enable -version=1 -path=secret kv && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-test data="ssl-test-secret-value" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-skip-verify-test data="ssl-skip-verify-test-value" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-numeric data="12345" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-base64 data="SGVsbG8gV29ybGQ=" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-unicode data="こんにちは世界" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-url data="https://user:pass@host:8080/path?key=val&foo=bar" && \
		$(VAULT_BIN) kv put secret/test-repo/test-type/ssl-pem-like data="-----BEGIN CERTIFICATE-----MIIBxTCCAW..." && \
		printf "${BOLD}vault SSL server started and configured${SGR0}\n"; \
	else \
		printf "${BOLD}vault SSL server already running (vault-ssl.PID exists)${SGR0}\n"; \
	fi

.PHONY: stop-vault-ssl
stop-vault-ssl: vault-ssl.PID
	@printf "${BOLD}stopping vault SSL server${SGR0}\n"
	kill $$(cat $<) && rm $< || true

# Test vault integration without SSL
.PHONY: test-vault-nossl
test-vault-nossl: vault-kbs start-vault
	@printf "${BOLD}running vault integration tests (no SSL)${SGR0}\n"
	export VAULT_TOKEN=$$(cat $(VAULT_TOKEN_FILE)) && \
	cd $(PROJECT_DIR) && \
	cargo test --features vault vault_nossl -- --ignored

# Test vault SSL integration
.PHONY: test-vault-ssl
test-vault-ssl: vault-kbs start-vault-ssl
	@printf "${BOLD}running vault SSL integration tests${SGR0}\n"
	export VAULT_TOKEN=$$(cat $(WORK_DIR)/vault-ssl-token) && \
	export VAULT_CA_CERT=$(VAULT_CA_CERT) && \
	cd $(PROJECT_DIR) && \
	cargo test --features vault vault_ssl -- --ignored

# TPM variables  
TPM_CONFIG_FILE := $(KBS_CONFIG_PATH)/tpm-config.json
export TPM_CONFIG_FILE

# TPM dependencies installation
.PHONY: install-swtpm-dependencies
install-swtpm-dependencies:
	sudo apt-get update && \
	sudo apt-get install -y \
		swtpm \
		swtpm-tools \
		tpm2-tools \
		linux-modules-extra-$(shell uname -r)

# Setup swtpm
.PHONY: setup-swtpm
setup-swtpm:
	@printf "${BOLD}Setting up swtpm${SGR0}\n"
	sudo ./setup-swtpm.sh setup


# Cleanup TPM-related files
.PHONY: clean-tpm
clean-tpm:
	sudo ./setup-swtpm.sh cleanup

.PHONY: clean
clean:  clean-tpm
	rm -rf \
		kbs \
		client \
		resource-kbs \
		vault-kbs \
		echo-plugin \
		ext-plugin-kbs \
		work/*
