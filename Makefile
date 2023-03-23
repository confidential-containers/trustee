.PHONY: kbs
kbs:
	cargo build

.PHONY: kbs-native-as
kbs-native-as:
	cargo build --no-default-features --features native-as,rustls

.PHONY: kbs-grpc-as
kbs-grpc-as:
	cargo build --no-default-features --features grpc-as,rustls

.PHONY: kbs-native-as-no-verifier
kbs-native-as-no-verifier:
	cargo build --no-default-features --features native-as-no-verifier,rustls

.PHONY: kbs-native-as-openssl
kbs-native-as-openssl:
	cargo build --no-default-features --features native-as,openssl

.PHONY: kbs-grpc-as-openssl
kbs-grpc-as-openssl:
	cargo build --no-default-features --features grpc-as,openssl

.PHONY: kbs-native-as-no-verifier-openssl
kbs-native-as-no-verifier-openssl:
	cargo build --no-default-features --features native-as-no-verifier,openssl

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
