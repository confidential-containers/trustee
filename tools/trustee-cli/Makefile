BUILD_ARCH := $(shell uname -m)
ARCH ?= $(shell uname -m)
# Check if ARCH is supported, otherwise return error
ifeq ($(filter $(ARCH),x86_64 s390x aarch64 arm64),)
	$(error "Unsupported architecture: $(ARCH)")
endif

RELEASE_DIR := ../../target/release
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
    RELEASE_DIR := ../../target/$(RUSTC_TARGET)/release
    OS_ARCH := $(ARCH)
    OS_ARCH := $(OS_ARCH:x86_64=amd64)
    OS_ARCH := $(OS_ARCH:aarch64=arm64)
    CARGO_ENV := OPENSSL_INCLUDE_DIR=/usr/include/$(ARCH)-linux-gnu OPENSSL_LIB_DIR=/usr/lib/$(ARCH)-linux-gnu RUSTFLAGS="$(RUSTFLAGS_ARGS)"
  else
    $(error ERROR: Cross-compiling is only tested on Debian-like OSes)
  endif
endif

INSTALL_DESTDIR ?= /usr/local/bin

build:
	$(CARGO_ENV) cargo build -p trustee-cli --locked --release $(TARGET_FLAG)

install:
	install -D -m0755 $(RELEASE_DIR)/trustee $(INSTALL_DESTDIR)

uninstall:
	rm -rf $(INSTALL_DESTDIR)/trustee

check:
	cargo test -p trustee-cli

lint:
	cargo clippy -p trustee-cli -- -D warnings

format:
	cargo fmt -p trustee-cli -- --check --config format_code_in_doc_comments=true

clean:
	cargo clean

