OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
KBS_REPO_PATH := /opt/confidential-containers/kbs/repository
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/..

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
		libsgx-dcap-quote-verify-dev \
		libtdx-attest-dev \
		libtss2-dev \
		openssl \
		pkg-config \
		protobuf-compiler

kbs:
	cd $(PROJECT_DIR) && \
	cargo build -p kbs --release --features rustls,coco-as-builtin,resource,opa && \
	install -D --compare ./target/release/kbs $(CURDIR)/kbs

client:
	cd $(PROJECT_DIR) && \
	cargo build -p kbs-client --release \
		--features api-server/coco-as-builtin,api-server/rustls && \
	install -D --compare $(PROJECT_DIR)/target/release/kbs-client $(CURDIR)/client

.PHONY: bins
bins: kbs client

kbs.key:
	openssl genpkey -algorithm ed25519 > kbs.key

kbs.pem: kbs.key
	openssl pkey -in kbs.key -pubout -out kbs.pem

$(KBS_REPO_PATH)/one/two/three:
	mkdir -p $(KBS_REPO_PATH)/one/two && \
	openssl rand 16 > $(KBS_REPO_PATH)/one/two/three

.PHONY: start-kbs
start-kbs: kbs kbs.pem $(KBS_REPO_PATH)/one/two/three
	./kbs \
	  --socket 127.0.0.1:8080 \
	  --insecure-http \
	  --auth-public-key ./kbs.pem &

.PHONY: e2e-test
e2e-test: start-kbs client
	./client get-resource --path one/two/three | base64 -d > roundtrip_secret && \
	diff $(KBS_REPO_PATH)/one/two/three roundtrip_secret
	@echo "e2e test passed"

.PHONY: clean
clean:
	rm kbs kbs.key kbs.pem client roundtrip_secret $(KBS_REPO_PATH)/one/two/three
