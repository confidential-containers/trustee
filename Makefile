.PHONY: kbs
kbs:
	cargo build

.PHONY: kbs-coco-as
kbs-coco-as:
	cargo build --no-default-features --features coco-as-builtin,rustls

.PHONY: kbs-coco-as-grpc
kbs-coco-as-grpc:
	cargo build --no-default-features --features coco-as-grpc,rustls

.PHONY: kbs-coco-as-no-verifier
kbs-coco-as-no-verifier:
	cargo build --no-default-features --features coco-as-builtin-no-verifier,rustls

.PHONY: kbs-coco-as-openssl
kbs-coco-as-openssl:
	cargo build --no-default-features --features coco-as-builtin,openssl

.PHONY: kbs-coco-as-grpc-openssl
kbs-coco-as-grpc-openssl:
	cargo build --no-default-features --features coco-as-grpc,openssl

.PHONY: kbs-coco-as-no-verifier-openssl
kbs-coco-as-no-verifier-openssl:
	cargo build --no-default-features --features coco-as-builtin-no-verifier,openssl

.PHONY: check
check:
	cargo test --lib

.PHONY: lint
lint:
	cargo clippy -- -D warnings  -Wmissing-docs

.PHONY: format
format:
	cargo fmt -- --check --config format_code_in_doc_comments=true

.PHONY: ci
ci: kbs check lint format

.PHONY: clean
clean:
	cargo clean
