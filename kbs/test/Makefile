OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
KBS_REPO_PATH := ./data/repository
KBS_CONFIG_PATH := ./data/e2e
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/..
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)

ifeq ($(OS),Ubuntu)
    ifneq ($(RELEASE),22.04)
        $(error "This Makefile requires Ubuntu 22.04")
    endif
else
    $(error "This Makefile requires Ubuntu")
endif

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
		libsgx-dcap-quote-verify-dev \
		libtdx-attest-dev \
		libtss2-dev \
		openssl \
		pkg-config \
		protobuf-compiler

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

.PHONY: generate-attestation-token-signer
generate-attestation-token-signer:
	mkdir $(CURDIR)/token-signer/
	openssl genrsa -traditional -out ./token-signer/cakey.pem 2048
	openssl req -new -key ./token-signer/cakey.pem -out ./token-signer/careq.csr -subj "/O=CNCF/OU=CoCo/CN=KBS-test-root"
	openssl req -x509 -days 3650 -key ./token-signer/cakey.pem -in ./token-signer/careq.csr -out ./token-signer/cacert.pem
	openssl genrsa -traditional -out ./token-signer/token-key.pem 2048
	openssl req -new -key ./token-signer/token-key.pem -out ./token-signer/token-cert-req.csr -subj "/O=CNCF/OU=CoCo/CN=CoCo-AS"
	openssl x509 -req -in ./token-signer/token-cert-req.csr -CA ./token-signer/cacert.pem -CAkey ./token-signer/cakey.pem -CAcreateserial -out ./token-signer/token-cert.pem -extensions req_ext
	cat ./token-signer/token-cert.pem ./token-signer/cacert.pem > ./token-signer/token-cert-chain.pem

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

kbs.PID: kbs kbs.pem $(KBS_REPO_PATH)/one/two/three
	@printf "${BOLD}start kbs${SGR0}\n"
	{ \
		RUST_LOG=actix-server=warn \
		$(CURDIR)/kbs --config-file $(KBS_CONFIG_PATH)/kbs.toml \
		& echo $$! > kbs.PID; \
	} && \
	sleep 1

resource-kbs.PID: resource-kbs kbs.pem $(KBS_REPO_PATH)/one/two/three
	@printf "${BOLD}start resource-kbs${SGR0}\n"
	{ \
		RUST_LOG=actix-server=debug \
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
	RUST_LOG=kbs_protocol=warn ./client \
		config --auth-private-key kbs.key \
		set-resource-policy --policy-file $(MAKEFILE_DIR)/data/policy_2.rego && \
	RUST_LOG=kbs_protocol=error ./client get-resource \
		 --path one/two/three \
		 | base64 -d > roundtrip_secret && \
	diff $(KBS_REPO_PATH)/one/two/three roundtrip_secret
	@printf "${BOLD}background-check e2e test passed${SGR0}\n"

.PHONY: attestation_token
attestation_token: client tee.key start-kbs
	RUST_LOG=kbs_protocol=warn ./client attest \
		--tee-key-file tee.key \
		> attestation_token

test-passport: client attestation_token start-resource-kbs
	RUST_LOG=kbs_protocol=warn ./client --url http://127.0.0.1:50002 \
		config --auth-private-key kbs.key \
		set-resource-policy --policy-file $(MAKEFILE_DIR)/data/policy_2.rego && \
	RUST_LOG=kbs_protocol=warn ./client --url http://127.0.0.1:50002 get-resource \
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
