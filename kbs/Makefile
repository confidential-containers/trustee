AS_TYPE ?= coco-as
ALIYUN ?= false

ARCH := $(shell uname -m)
# Check if ARCH is supported, otehrwise return error
ifeq ($(filter $(ARCH),x86_64 s390x),)
	$(error "Unsupported architecture: $(ARCH)")
endif

CLI_FEATURES ?=
ATTESTER ?=
FEATURES ?=

COCO_AS_INTEGRATION_TYPE ?= builtin

INSTALL_DESTDIR ?= /usr/local/bin

ifeq ($(AS_TYPE), coco-as)
  AS_FEATURE = $(AS_TYPE)-$(COCO_AS_INTEGRATION_TYPE)
else
  AS_FEATURE = $(AS_TYPE)
endif

ifeq ($(ALIYUN), true)
  FEATURES += aliyun
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
	cargo build -p kbs --locked --release --no-default-features --features $(AS_FEATURE),resource,$(FEATURES)

.PHONY: passport-issuer-kbs
passport-issuer-kbs:
	cargo build -p kbs --locked --release --no-default-features --features $(AS_FEATURE),$(FEATURES)
	mv ../target/release/kbs ../target/release/issuer-kbs

.PHONY: passport-resource-kbs
passport-resource-kbs:
	cargo build -p kbs --locked --release --no-default-features --features resource,$(FEATURES)
	mv ../target/release/kbs ../target/release/resource-kbs

.PHONY: cli
cli:
	cargo build -p kbs-client --locked --release --no-default-features --features $(CLI_FEATURES)

.PHONY: cli-static-linux
cli-static-linux:
	cargo build \
      -p kbs-client \
      --target=$(ARCH)-unknown-linux-gnu \
      --config "target.$(ARCH)-unknown-linux-gnu.rustflags = '-C target-feature=+crt-static'" \
      --locked \
      --release \
      --no-default-features \
      --features sample_only

install-kbs:
	install -D -m0755 ../target/release/kbs $(INSTALL_DESTDIR)

install-issuer-kbs:
	install -D -m0755 ../target/release/issuer-kbs $(INSTALL_DESTDIR)
	install -D -m0755 ../target/release/kbs-client $(INSTALL_DESTDIR)

install-resource-kbs:
	install -D -m0755 ../target/release/resource-kbs $(INSTALL_DESTDIR)

install-cli:
	install -D -m0755 ../target/release/kbs-client $(INSTALL_DESTDIR)

uninstall:
	rm -rf $(INSTALL_DESTDIR)/kbs $(INSTALL_DESTDIR)/kbs-client $(INSTALL_DESTDIR)/issuer-kbs $(INSTALL_DESTDIR)/resource-kbs

check:
	cargo test -p kbs -p kbs-client

lint:
	cargo clippy -p kbs -p kbs-client -- -D warnings

format:
	cargo fmt -p kbs -p kbs-client -- --check --config format_code_in_doc_comments=true

clean:
	cargo clean

