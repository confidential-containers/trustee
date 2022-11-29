.PHONY: kbs
kbs:
	cargo build

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
