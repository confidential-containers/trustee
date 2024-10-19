AS_TYPE ?= coco-as
ALIYUN ?= false
NEBULA_CA_PLUGIN ?= false

BUILD_ARCH := $(shell uname -m)
ARCH ?= $(shell uname -m)
# Check if ARCH is supported, otehrwise return error
ifeq ($(filter $(ARCH),x86_64 s390x aarch64),)
	$(error "Unsupported architecture: $(ARCH)")
endif

RELEASE_DIR := ../target/release
TARGET_FLAG :=
CARGO_ENV :=
ifneq ($(BUILD_ARCH), $(ARCH))
  ifneq (,$(wildcard /etc/debian_version))
    GCC_PACKAGE := gcc-$(ARCH)-linux-gnu
    GCC_COMPILER := $(ARCH)-linux-gnu-gcc
    RUSTC_TARGET := $(ARCH)-unknown-linux-gnu
    GCC_INSTALL := $(shell sudo apt-get install -y ${GCC_PACKAGE})
    RUST_INSTALL := $(shell rustup target add ${RUSTC_TARGET})
    RUSTFLAGS_ARGS := -C linker=$(GCC_COMPILER)
    TARGET_FLAG := --target $(RUSTC_TARGET)
    RELEASE_DIR := ../target/$(RUSTC_TARGET)/release
    OS_ARCH := $(ARCH)
    OS_ARCH := $(OS_ARCH:x86_64=amd64)
    OS_ARCH := $(OS_ARCH:aarch64=arm64)
    CARGO_ENV := OPENSSL_INCLUDE_DIR=/usr/include/$(ARCH)-linux-gnu OPENSSL_LIB_DIR=/usr/lib/$(ARCH)-linux-gnu RUSTFLAGS="$(RUSTFLAGS_ARGS)"
  else
    $(error ERROR: Cross-compiling is only tested on Debian-like OSes)
  endif
endif

CLI_FEATURES ?=
ATTESTER ?=
FEATURES ?=

COCO_AS_INTEGRATION_TYPE ?= builtin

INSTALL_DESTDIR ?= /usr/local/bin

ifeq ($(AS_TYPE), coco-as)
  AS_FEATURE += $(AS_TYPE)-$(COCO_AS_INTEGRATION_TYPE),
else ifneq ($(AS_TYPE), )
  AS_FEATURE += $(AS_TYPE),
endif

ifeq ($(ALIYUN), true)
  FEATURES += aliyun
endif

ifeq ($(NEBULA_CA_PLUGIN), true)
  FEATURES += nebula-ca-plugin
endif

ifndef CLI_FEATURES
  ifdef ATTESTER
    CLI_FEATURES = "sample_only,$(ATTESTER)"
  else
    CLI_FEATURES += "sample_only,all-attesters"
  endif
endif

build: background-check-kbs

.PHONY: background-check-kbs
background-check-kbs:
	$(CARGO_ENV) cargo build -p kbs --locked --release --no-default-features --features $(FEATURES),$(AS_FEATURE) $(TARGET_FLAG)

.PHONY: passport-issuer-kbs
passport-issuer-kbs:
	$(CARGO_ENV) cargo build -p kbs --locked --release --no-default-features --features $(AS_FEATURE),$(FEATURES) $(TARGET_FLAG)
	mv ../target/release/kbs ../target/release/issuer-kbs

.PHONY: passport-resource-kbs
passport-resource-kbs:
	$(CARGO_ENV) cargo build -p kbs --locked --release --no-default-features --features $(FEATURES), $(TARGET_FLAG)
	mv ../target/release/kbs ../target/release/resource-kbs

.PHONY: cli
cli:
	$(CARGO_ENV) cargo build -p kbs-client --locked --release --no-default-features --features $(CLI_FEATURES) $(TARGET_FLAG)

.PHONY: cli-static-linux
cli-static-linux:
	$(CARGO_ENV) cargo build \
      -p kbs-client \
      --target=$(ARCH)-unknown-linux-gnu \
      --config "target.$(ARCH)-unknown-linux-gnu.rustflags = '-C target-feature=+crt-static'" \
      --locked \
      --release \
      --no-default-features \
      --features sample_only

install-kbs:
	install -D -m0755 $(RELEASE_DIR)/kbs $(INSTALL_DESTDIR)

install-issuer-kbs:
	install -D -m0755 $(RELEASE_DIR)/issuer-kbs $(INSTALL_DESTDIR)
	install -D -m0755 $(RELEASE_DIR)/kbs-client $(INSTALL_DESTDIR)

install-resource-kbs:
	install -D -m0755 $(RELEASE_DIR)/resource-kbs $(INSTALL_DESTDIR)

install-cli:
	install -D -m0755 $(RELEASE_DIR)/kbs-client $(INSTALL_DESTDIR)

uninstall:
	rm -rf $(INSTALL_DESTDIR)/kbs $(INSTALL_DESTDIR)/kbs-client $(INSTALL_DESTDIR)/issuer-kbs $(INSTALL_DESTDIR)/resource-kbs

check:
	cargo test -p kbs -p kbs-client -p integration-tests

lint:
	cargo clippy -p kbs -p kbs-client -- -D warnings

format:
	cargo fmt -p kbs -p kbs-client -- --check --config format_code_in_doc_comments=true

clean:
	cargo clean

