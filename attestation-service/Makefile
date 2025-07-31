PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local
TARGET_DIR := ../target
BIN_NAMES := grpc-as restful-as

DEBUG ?=
DESTDIR ?= $(PREFIX)/bin

VERIFIER ?= all-verifier

RVPS_GRPC := true

ifeq ($(RVPS_GRPC), true)
	RVPS_FEATURES := rvps-grpc
endif

ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

build: grpc-as restful-as

grpc-as:
	cargo build --bin grpc-as $(release) --features grpc-bin,$(VERIFIER),$(RVPS_FEATURES)

restful-as:
	cargo build --bin restful-as $(release) --features restful-bin,$(VERIFIER),$(RVPS_FEATURES)

install:
	for bin_name in $(BIN_NAMES); do \
		install -D -m0755 $(TARGET_DIR)/$$bin_name $(DESTDIR); \
	done

opa-check:
	for rego_file in src/ear_token/*.rego ; do \
		opa fmt -d $${rego_file} && \
		opa check $${rego_file} --capabilities=tests/capabilities.json --rego-v1; \
	done

clean:
	cargo clean
