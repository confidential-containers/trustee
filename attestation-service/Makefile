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

# TODO: Remove `RVPS_BUILTIN`
# when https://github.com/confidential-containers/trustee/pull/553 gets merged
# Here we also declare another variable `RVPS_FEATURES1` because a blank will
# be added when doing '+=' operation in Makefile
RVPS_BUILTIN := true

ifeq ($(RVPS_GRPC), true)
	RVPS_FEATURES1 := rvps-grpc
endif

ifeq ($(RVPS_BUILTIN), true)
	RVPS_FEATURES := $(RVPS_FEATURES1),rvps-builtin
else
	RVPS_FEATURES := $(RVPS_FEATURES1)
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

clean:
	cargo clean
