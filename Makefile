.PHONY: kbs
kbs:
	cargo build

.PHONY: kbs-native-as
kbs:
	cargo build --no-default-features --features native-as

.PHONY: kbs-grpc-as
kbs-grpc-as:
	cargo build --no-default-features --features grpc-as

.PHONY: kbs-native-as-no-verifier
kbs-native-as-no-verifier:
	cargo build --no-default-features --features native-as-no-verifier

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
