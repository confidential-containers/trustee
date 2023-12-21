OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/../..
RESTFUL_BIN := /usr/local/bin/restful-as
GRPC_BIN := /usr/local/bin/grpc-as
AS_CACHE_PATH := /opt/confidential-containers/attestation-service
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)
EVIDENCE_FILE ?= $(MAKEFILE_DIR)/evidence.json
RAW_RUNTIME_DATA_FILE ?= $(MAKEFILE_DIR)/raw-runtime-data

RAW_RUNTIME_DATA := $(shell cat $(RAW_RUNTIME_DATA_FILE) | base64 -w0 | tr -d '=' | sed -e "s/+/-/g" -e "s/\//_/g")
EVIDENCE := $(shell cat $(EVIDENCE_FILE) | base64 -w0 | tr -d '=' | sed -e "s/+/-/g" -e "s/\//_/g")

GRPC_TEE_ENUM ?= 2
GRPC_REQUEST := $(MAKEFILE_DIR)/grpc-request.json

RESTFUL_TEE_ENUM ?= snp
RESTFUL_REQUEST := $(MAKEFILE_DIR)/restful-request.json

.PHONY: install-dependencies
install-dependencies:
	curl -L "$(SGX_REPO_URL)/intel-sgx-deb.key" | sudo apt-key add - && \
	echo "deb [arch=amd64] $(SGX_REPO_URL) jammy main" \
		| sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
	sudo apt-get update && \
	sudo apt-get install -y \
		protobuf-compiler \
		clang \
		libtss2-dev \
		libtdx-attest-dev \
		libsgx-dcap-quote-verify-dev \
		libsgx-dcap-default-qpl

$(RESTFUL_BIN) $(GRPC_BIN):
	cd $(PROJECT_DIR) && $(MAKE) build && $(MAKE) install

restful.pid: $(RESTFUL_BIN)
	@printf "${BOLD}start restful-coco-as${SGR0}\n"
	{ \
		RUST_LOG=info \
		$(RESTFUL_BIN) --socket 127.0.0.1:8080 \
		& echo $$! > $@; \
	} && \
	sleep 2

grpc.pid: $(GRPC_BIN)
	@printf "${BOLD}start grpc-coco-as${SGR0}\n"
	{ \
		RUST_LOG=info \
		$(GRPC_BIN) --socket 127.0.0.1:50004 \
		& echo $$! > $@; \
	} && \
	sleep 2

$(RESTFUL_REQUEST): $(RESTFUL_REQUEST).template
	sed -e "s/%RESTFUL_TEE_ENUM%/$(RESTFUL_TEE_ENUM)/g" \
		-e "s/%RUNTIME_DATA%/$(RAW_RUNTIME_DATA)/g" \
		-e "s/%EVIDENCE%/$(EVIDENCE)/g" \
		$(RESTFUL_REQUEST).template > $(RESTFUL_REQUEST)

.PHONY: restful-test
restful-test: restful.pid $(RESTFUL_REQUEST)
	curl -k -X POST http://127.0.0.1:8080/attestation \
     -i \
     -H 'Content-Type: application/json' \
     -d @$(RESTFUL_REQUEST)

$(GRPC_REQUEST): $(GRPC_REQUEST).template
	sed -e "s/%GRPC_TEE_ENUM%/$(GRPC_TEE_ENUM)/g" \
		-e "s/%RUNTIME_DATA%/$(RAW_RUNTIME_DATA)/g" \
		-e "s/%EVIDENCE%/$(EVIDENCE)/g" \
		$(GRPC_REQUEST).template > $(GRPC_REQUEST)

.PHONY: grpc-test
grpc-test: grpc.pid $(GRPC_REQUEST)
	echo $$(cat $(GRPC_REQUEST)) \
	| grpcurl -plaintext -import-path ../../protos -proto ../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/AttestationEvaluate

.PHONY: stop-restful-as
stop-restful-as: restful.pid
	@printf "${BOLD}stop restful-as${SGR0}\n"
	kill $$(cat $<) && rm $<
	rm -rf $(AS_CACHE_PATH)

.PHONY: stop-grpc-as
stop-grpc-as: grpc.pid
	@printf "${BOLD}stop grpc-as${SGR0}\n"
	kill $$(cat $<) && rm $<
	rm -rf $(AS_CACHE_PATH)

.PHONY: e2e-restful-test
e2e-restful-test: restful-test stop-restful-as

.PHONY: e2e-grpc-test
e2e-grpc-test: grpc-test stop-grpc-as

.PHONY: clean
clean:
	rm -f \
		$(RESTFUL_BIN) \
		$(GRPC_BIN) \
		grpc.pid \
		restful.pid \
		$(RESTFUL_REQUEST) \
		$(GRPC_REQUEST)
