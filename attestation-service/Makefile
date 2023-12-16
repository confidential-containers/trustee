PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local
TARGET_DIR := ../target
BIN_NAMES := grpc-as restful-as

DEBUG ?=
DESTDIR ?= $(PREFIX)/bin

ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

build: grpc-as restful-as

grpc-as:
	cargo build --bin grpc-as $(release) --features grpc-bin

restful-as:
	cargo build --bin restful-as $(release) --features restful-bin

install:
	for bin_name in $(BIN_NAMES); do \
		install -D -m0755 $(TARGET_DIR)/$$bin_name $(DESTDIR); \
	done

clean:
	cargo clean
