.PHONY: kbs
kbs:
	cargo build

.PHONY: kbs-no-as
kbs-no-as:
	cargo build --no-default-features --features rustls,resource

.PHONY: kbs-no-as-openssl
kbs-no-as-openssl:
	cargo build --no-default-features --features openssl,resource

.PHONY: kbs-coco-as
kbs-coco-as:
	cargo build --no-default-features --features coco-as-builtin,rustls,resource

.PHONY: kbs-coco-as-grpc
kbs-coco-as-grpc:
	cargo build --no-default-features --features coco-as-grpc,rustls,resource

.PHONY: kbs-coco-as-no-verifier
kbs-coco-as-no-verifier:
	cargo build --no-default-features --features coco-as-builtin-no-verifier,rustls,resource

.PHONY: kbs-coco-as-openssl
kbs-coco-as-openssl:
	cargo build --no-default-features --features coco-as-builtin,openssl,resource

.PHONY: kbs-coco-as-grpc-openssl
kbs-coco-as-grpc-openssl:
	cargo build --no-default-features --features coco-as-grpc,openssl,resource

.PHONY: kbs-coco-as-no-verifier-openssl
kbs-coco-as-no-verifier-openssl:
	cargo build --no-default-features --features coco-as-builtin-no-verifier,openssl,resource

.PHONY: kbs-amber-as
kbs-amber-as:
	cargo build --no-default-features --features amber-as,rustls,resource

.PHONY: kbs-amber-as-openssl
kbs-amber-as-openssl:
	cargo build --no-default-features --features amber-as,openssl,resource

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
