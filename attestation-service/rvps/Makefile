PREFIX := /usr/local

TARGET_DIR := ../../target/release
DESTDIR ?= $(PREFIX)/bin
BIN_NAMES := rvps rvps-tool

build: bin tool

# Build RVPS in gRPC version
bin:
	cargo build --release --bin rvps --no-default-features --features bin

# Build RVPS client tool
tool:
	cargo build --release --bin rvps-tool --no-default-features --features bin

install:
	for bin_name in $(BIN_NAMES); do \
		install -D -m0755 $(TARGET_DIR)/$$bin_name $(DESTDIR); \
	done

clean:
	cargo clean