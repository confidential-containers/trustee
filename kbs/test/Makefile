OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
SGX_COLLATERAL_URL := https://api.trustedservices.intel.com/sgx/certification/v4/
SGX_QCNL_CONFIG := /etc/sgx_default_qcnl.conf
KBS_REPO_PATH := ./data/repository
KBS_CONFIG_PATH := ./data/e2e
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/..
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)
TEE ?= sample

SHELL := bash
ifeq ($(OS),Ubuntu)
    ifneq ($(RELEASE),22.04)
        $(error "This Makefile requires Ubuntu 22.04")
    endif
else
    $(error "This Makefile requires Ubuntu")
endif

define TEE_POLICY_REGO
package policy

default allow = false

allow {
        input["tee"] == "$(TEE)"
}
endef
export TEE_POLICY_REGO

.PHONY: install-dependencies
install-dependencies:
	curl -L "$(SGX_REPO_URL)/intel-sgx-deb.key" | sudo apt-key add - && \
	echo "deb [arch=amd64] $(SGX_REPO_URL) jammy main" \
		| sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
	sudo apt-get update && \
	sudo apt-get install -y \
		build-essential \
		clang \
		libsgx-dcap-default-qpl \
		libsgx-dcap-quote-verify \
		libsgx-dcap-quote-verify-dev \
		libsgx-urts \
		libssl-dev \
		libtdx-attest \
		libtdx-attest-dev \
		libtss2-dev \
		openssl \
		pkg-config \
		protobuf-compiler && \
	echo '{"collateral_service": "$(SGX_COLLATERAL_URL)"}' | sudo tee $(SGX_QCNL_CONFIG)

kbs:
	cd $(PROJECT_DIR) && \
	make background-check-kbs POLICY_ENGINE=opa && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs $(CURDIR)/kbs

resource-kbs:
	cd $(PROJECT_DIR) && \
	make passport-resource-kbs POLICY_ENGINE=opa && \
	install -D --compare $(PROJECT_DIR)/../target/release/resource-kbs $(CURDIR)/resource-kbs

client:
	cd $(PROJECT_DIR) && \
	cargo build -p kbs-client --release && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs-client $(CURDIR)/client

.PHONY: bins
bins: kbs resource-kbs client

ca-key.pem:
	openssl genrsa -traditional -out ca-key.pem 2048

ca-cert.pem: ca-key.pem
	openssl req -new -key ca-key.pem -out ca-req.csr -subj "/O=CNCF/OU=CoCo/CN=KBS-test-root" && \
	openssl req -x509 -days 3650 -key ca-key.pem -in ca-req.csr -out ca-cert.pem

token-key.pem:
	openssl genrsa -traditional -out token-key.pem 2048

token-cert.pem: token-key.pem ca-cert.pem ca-key.pem
	openssl req -new -key token-key.pem -out token-req.csr -subj "/O=CNCF/OU=CoCo/CN=CoCo-AS" && \
	openssl x509 -req -in token-req.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out token-cert.pem -extensions req_ext

token-cert-chain.pem: token-cert.pem ca-cert.pem
	cat token-cert.pem ca-cert.pem > token-cert-chain.pem

.PHONY: generate-attestation-token-signer
generate-attestation-token-signer: token-cert-chain.pem

kbs.key:
	openssl genpkey -algorithm ed25519 > kbs.key

kbs.pem: kbs.key
	openssl pkey -in kbs.key -pubout -out kbs.pem

tee.key:
	openssl genrsa -traditional -out tee.key 2048

$(KBS_REPO_PATH)/one/two/three:
	mkdir -p $(KBS_REPO_PATH)/one/two && \
	openssl rand 16 > $(KBS_REPO_PATH)/one/two/three

.PHONY: start-kbs
start-kbs: kbs.PID

.PHONY: start-resource-kbs
start-resource-kbs: resource-kbs.PID

kbs.PID: kbs kbs.pem token-key.pem token-cert-chain.pem $(KBS_REPO_PATH)/one/two/three
	@printf "${BOLD}start kbs${SGR0}\n"
	{ \
		$(CURDIR)/kbs --config-file $(KBS_CONFIG_PATH)/kbs.toml \
		& echo $$! > kbs.PID; \
	} && \
	sleep 1

resource-kbs.PID: resource-kbs kbs.pem ca-cert.pem $(KBS_REPO_PATH)/one/two/three
	@printf "${BOLD}start resource-kbs${SGR0}\n"
	{ \
		./resource-kbs --config-file $(KBS_CONFIG_PATH)/resource-kbs.toml \
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
		config --auth-private-key kbs.key \
		set-resource-policy --policy-file <(echo "$$TEE_POLICY_REGO") && \
	./client get-resource \
		 --path one/two/three \
		 | base64 -d > roundtrip_secret && \
	diff $(KBS_REPO_PATH)/one/two/three roundtrip_secret
	@printf "${BOLD}background-check e2e test passed${SGR0}\n"

.PHONY: attestation_token
attestation_token: client tee.key start-kbs
	./client attest \
		--tee-key-file tee.key \
		> attestation_token

test-passport: client attestation_token start-resource-kbs
	./client --url http://127.0.0.1:50002 \
		config --auth-private-key kbs.key \
		set-resource-policy --policy-file <(echo "$$TEE_POLICY_REGO") && \
	./client --url http://127.0.0.1:50002 get-resource \
		--attestation-token attestation_token \
		--tee-key-file tee.key \
		--path one/two/three \
		| base64 -d > roundtrip_secret && \
	diff $(KBS_REPO_PATH)/one/two/three roundtrip_secret
	@printf "${BOLD}passport e2e test passed${SGR0}\n"

.PHONY: stop
stop: stop-kbs stop-resource-kbs

.PHONY: e2e-test
e2e-test: test-bgcheck test-passport stop

.PHONY: clean
clean:
	rm -rf \
		kbs \
		resource-kbs \
		kbs.key \
		kbs.pem \
		tee.key \
		tee.pem \
		client \
		token-signer \
		roundtrip_secret \
		$(KBS_REPO_PATH)/one/two/three
