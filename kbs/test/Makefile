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

SHELL := bash
ifneq ($(OS),Ubuntu)
    $(error "This Makefile requires Ubuntu")
endif

define TEE_POLICY_REGO
package policy

default allow = false

allow {
	input["submods"]["cpu"]["ear.trustee.tcb_claims"]["$(TEE)"]
}
endef
export TEE_POLICY_REGO

.PHONY: install-dev-dependencies
install-dev-dependencies: install-dependencies
	sudo apt-get update && \
	sudo apt-get install -y \
		build-essential \
		clang \
		libsgx-dcap-quote-verify-dev \
		libssl-dev \
		libtdx-attest-dev \
		libtss2-dev \
		pkg-config \
		protobuf-compiler

.PHONY: install-dependencies
install-dependencies:
	curl -L "$(SGX_REPO_URL)/intel-sgx-deb.key" | sudo gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
	echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] $(SGX_REPO_URL) $(CODENAME) main" \
		| sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
	sudo apt-get update && \
	sudo apt-get install -y \
		libsgx-dcap-default-qpl \
		libsgx-dcap-quote-verify \
		libsgx-urts \
		libtdx-attest \
		libtss2-esys-3.0.2-0 \
		libtss2-tctildr0 \
		openssl && \
	echo '{"collateral_service": "$(SGX_COLLATERAL_URL)"}' | sudo tee $(SGX_QCNL_CONFIG)

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
	cargo build -p kbs-client --release && \
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

.PHONY: clean
clean:
	rm -rf \
		kbs \
		client \
		resource-kbs \
		work/*
