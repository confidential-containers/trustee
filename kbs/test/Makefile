ARCH := $(shell uname -m)
OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
CODENAME := $(shell lsb_release -sc)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
SGX_COLLATERAL_URL := https://api.trustedservices.intel.com/sgx/certification/v4/
SGX_QCNL_CONFIG := /etc/sgx_default_qcnl.conf
KBS_CONFIG_PATH := ./config
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

TEST_FEATURES ?=
TEST_ARGUMENTS ?=

SHELL := bash
ifneq ($(OS),Ubuntu)
    $(error "This Makefile requires Ubuntu")
endif

define TEE_POLICY_REGO
package policy

default allow = false

allow {
	input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["$(TEE)"]
}
endef
export TEE_POLICY_REGO

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
		openssl && \
	echo '{"collateral_service": "$(SGX_COLLATERAL_URL)"}' | sudo tee $(SGX_QCNL_CONFIG); fi

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
stop: stop-kbs stop-resource-kbs

.PHONY: e2e-test
e2e-test: test-bgcheck test-passport stop

# Vault configuration
VAULT_VERSION := 1.19.5
VAULT_ARCH := linux_amd64
VAULT_URL := https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_$(VAULT_ARCH).zip
VAULT_BIN := $(WORK_DIR)/vault
VAULT_CONFIG := $(WORK_DIR)/vault-config.json
VAULT_SSL_CONFIG := $(WORK_DIR)/vault-ssl-config.json
VAULT_TOKEN_FILE := $(WORK_DIR)/vault-token
VAULT_KBS_CONFIG_PATH := ./config
VAULT_CA_KEY := $(WORK_DIR)/vault-ca.key
VAULT_CA_CERT := $(WORK_DIR)/vault-ca.pem
VAULT_SERVER_KEY := $(WORK_DIR)/vault-server.key
VAULT_SERVER_CERT := $(WORK_DIR)/vault-server.pem

# Download and setup Vault binary
$(VAULT_BIN):
	@if [ ! -f $(VAULT_BIN) ]; then \
		printf "${BOLD}downloading vault binary${SGR0}\n"; \
		mkdir -p $(WORK_DIR) && \
		cd $(WORK_DIR) && \
		curl -L "$(VAULT_URL)" -o vault.zip && \
		unzip vault.zip && \
		chmod +x vault && \
		rm vault.zip; \
	else \
		printf "${BOLD}vault binary already exists${SGR0}\n"; \
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
		work/*
