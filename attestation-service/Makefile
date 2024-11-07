PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local
TARGET_DIR := ../target
BIN_NAMES := grpc-as restful-as

DEBUG ?=
DESTDIR ?= $(PREFIX)/bin

FEATURES ?=

ifdef FEATURES
	OPTIONAL_FEATURES := ,$(FEATURES)
	default-features := --no-default-features
else
	OPTIONAL_FEATURES :=
	default-features :=
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
	cargo build --bin grpc-as $(release) $(default-features) --features grpc-bin$(OPTIONAL_FEATURES)

restful-as:
	cargo build --bin restful-as $(release) $(default-features) --features restful-bin$(OPTIONAL_FEATURES)

install:
	for bin_name in $(BIN_NAMES); do \
		install -D -m0755 $(TARGET_DIR)/$$bin_name $(DESTDIR); \
	done

clean:
	cargo clean
