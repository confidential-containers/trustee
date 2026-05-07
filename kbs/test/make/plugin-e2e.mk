# External plugin certificate generation
$(ECHO_PLUGIN_CA_KEY):
	mkdir -p $(WORK_DIR) && \
	openssl genrsa -out $(ECHO_PLUGIN_CA_KEY) 4096

$(ECHO_PLUGIN_CA_CERT): $(ECHO_PLUGIN_CA_KEY)
	openssl req -new -x509 -key $(ECHO_PLUGIN_CA_KEY) -out $(ECHO_PLUGIN_CA_CERT) -days 365 \
		-subj "/C=US/ST=CA/L=Test/O=Test/OU=EchoPlugin/CN=Echo Plugin CA"

$(ECHO_PLUGIN_SERVER_KEY):
	mkdir -p $(WORK_DIR) && \
	openssl genrsa -out $(ECHO_PLUGIN_SERVER_KEY) 4096

$(ECHO_PLUGIN_SERVER_CERT): $(ECHO_PLUGIN_SERVER_KEY) $(ECHO_PLUGIN_CA_CERT) $(ECHO_PLUGIN_CA_KEY)
	openssl req -new -key $(ECHO_PLUGIN_SERVER_KEY) -out $(WORK_DIR)/echo-plugin-server.csr \
		-subj "/C=US/ST=CA/L=Test/O=Test/OU=EchoPlugin/CN=127.0.0.1" && \
	echo -e "[v3_req]\nsubjectAltName=IP:127.0.0.1,DNS:localhost" > $(WORK_DIR)/echo-plugin-server.conf && \
	openssl x509 -req -in $(WORK_DIR)/echo-plugin-server.csr -CA $(ECHO_PLUGIN_CA_CERT) -CAkey $(ECHO_PLUGIN_CA_KEY) \
		-CAcreateserial -out $(ECHO_PLUGIN_SERVER_CERT) -days 365 -extensions v3_req \
		-extfile $(WORK_DIR)/echo-plugin-server.conf

# Start plaintext echo plugin server on :50051
.PHONY: start-echo-plugin
start-echo-plugin: echo-plugin.PID

echo-plugin.PID: echo-plugin
	@printf "${BOLD}start echo plugin (plaintext)${SGR0}\n"
	{ \
		PLUGIN_LISTEN_ADDR=127.0.0.1:50051 \
		"$(CURDIR)/echo-plugin" \
		& echo $$! > echo-plugin.PID; \
	} && \
	sleep 1

# Start TLS echo plugin server on :50052
.PHONY: start-echo-plugin-tls
start-echo-plugin-tls: echo-plugin-tls.PID

echo-plugin-tls.PID: echo-plugin $(ECHO_PLUGIN_SERVER_CERT) $(ECHO_PLUGIN_SERVER_KEY)
	@printf "${BOLD}start echo plugin (TLS)${SGR0}\n"
	{ \
		PLUGIN_LISTEN_ADDR=127.0.0.1:50052 \
		PLUGIN_TLS_CERT=$(ECHO_PLUGIN_SERVER_CERT) \
		PLUGIN_TLS_KEY=$(ECHO_PLUGIN_SERVER_KEY) \
		"$(CURDIR)/echo-plugin" \
		& echo $$! > echo-plugin-tls.PID; \
	} && \
	sleep 1

# Start KBS with external-plugin config (insecure, port 8085)
.PHONY: start-ext-plugin-kbs
start-ext-plugin-kbs: ext-plugin-kbs.PID

ext-plugin-kbs.PID: ext-plugin-kbs
	@printf "${BOLD}start ext-plugin-kbs (insecure)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin.toml" \
		& echo $$! > ext-plugin-kbs.PID; \
	} && \
	sleep 1

# Start KBS with external-plugin TLS config (port 8086)
.PHONY: start-ext-plugin-tls-kbs
start-ext-plugin-tls-kbs: ext-plugin-tls-kbs.PID

ext-plugin-tls-kbs.PID: ext-plugin-kbs $(ECHO_PLUGIN_CA_CERT)
	@printf "${BOLD}start ext-plugin-kbs (TLS)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin-tls.toml" \
		& echo $$! > ext-plugin-tls-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-echo-plugin
stop-echo-plugin:
	@if [ -f echo-plugin.PID ]; then \
		printf "${BOLD}stop echo plugin (plaintext)${SGR0}\n"; \
		kill $$(cat echo-plugin.PID) 2>/dev/null || true; \
		rm -f echo-plugin.PID; \
	fi

.PHONY: stop-echo-plugin-tls
stop-echo-plugin-tls:
	@if [ -f echo-plugin-tls.PID ]; then \
		printf "${BOLD}stop echo plugin (TLS)${SGR0}\n"; \
		kill $$(cat echo-plugin-tls.PID) 2>/dev/null || true; \
		rm -f echo-plugin-tls.PID; \
	fi

.PHONY: stop-ext-plugin-kbs
stop-ext-plugin-kbs:
	@if [ -f ext-plugin-kbs.PID ]; then \
		printf "${BOLD}stop ext-plugin-kbs (insecure)${SGR0}\n"; \
		kill $$(cat ext-plugin-kbs.PID) 2>/dev/null || true; \
		rm -f ext-plugin-kbs.PID; \
	fi

.PHONY: stop-ext-plugin-tls-kbs
stop-ext-plugin-tls-kbs:
	@if [ -f ext-plugin-tls-kbs.PID ]; then \
		printf "${BOLD}stop ext-plugin-kbs-tls (TLS)${SGR0}\n"; \
		kill $$(cat ext-plugin-tls-kbs.PID) 2>/dev/null || true; \
		rm -f ext-plugin-tls-kbs.PID; \
	fi

# Write the attestation policy for external plugin test
.PHONY: $(EXT_PLUGIN_ATTEST_POLICY)
$(EXT_PLUGIN_ATTEST_POLICY):
	echo "$$EXT_PLUGIN_POLICY_REGO" > $(EXT_PLUGIN_ATTEST_POLICY)

# Start KBS with external-plugin attestation config (HTTPS, port 8087)
.PHONY: start-ext-plugin-attest-kbs
start-ext-plugin-attest-kbs: ext-plugin-attest-kbs.PID

ext-plugin-attest-kbs.PID: ext-plugin-kbs kbs-keys kbs-certs $(EXT_PLUGIN_ATTEST_POLICY)
	@printf "${BOLD}start ext-plugin-kbs (attestation)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin-attest.toml" \
		& echo $$! > ext-plugin-attest-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-ext-plugin-attest-kbs
stop-ext-plugin-attest-kbs:
	@if [ -f ext-plugin-attest-kbs.PID ]; then \
		printf "${BOLD}stop ext-plugin-kbs (attestation)${SGR0}\n"; \
		kill $$(cat ext-plugin-attest-kbs.PID) 2>/dev/null || true; \
		rm -f ext-plugin-attest-kbs.PID; \
	fi

# Get attestation token for external plugin test
.PHONY: $(PLUGIN_ATTESTATION_TOKEN)
$(PLUGIN_ATTESTATION_TOKEN): client $(TEE_KEY) start-ext-plugin-attest-kbs
	./client \
		--url https://127.0.0.1:8087 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-resource-policy \
		--policy-file "$(EXT_PLUGIN_ATTEST_POLICY)" && \
	./client \
		--url https://127.0.0.1:8087 \
		--cert-file "$(HTTPS_CERT)" \
		attest \
		--tee-key-file "$(TEE_KEY)" \
		> "$(PLUGIN_ATTESTATION_TOKEN)"

# External plugin integration test (insecure / plaintext)
.PHONY: test-ext-plugin
test-ext-plugin: start-echo-plugin start-ext-plugin-kbs
	@printf "${BOLD}running external plugin integration test (insecure)${SGR0}\n"
	curl -sf -X POST http://127.0.0.1:8085/kbs/v0/external/echo-test/hello | grep -q "Echo:" && \
	printf "${BOLD}external plugin integration test (insecure) passed${SGR0}\n"

# External plugin integration test (TLS)
.PHONY: test-ext-plugin-tls
test-ext-plugin-tls: start-echo-plugin-tls start-ext-plugin-tls-kbs
	@printf "${BOLD}running external plugin integration test (TLS)${SGR0}\n"
	curl -sf -X POST http://127.0.0.1:8086/kbs/v0/external/echo-test/hello | grep -q "Echo:" && \
	printf "${BOLD}external plugin integration test (TLS) passed${SGR0}\n"

# External plugin integration test (attestation path)
.PHONY: test-ext-plugin-attest
test-ext-plugin-attest: start-echo-plugin $(PLUGIN_ATTESTATION_TOKEN)
	@printf "${BOLD}running external plugin integration test (attestation)${SGR0}\n"
	! curl -sf --cacert "$(HTTPS_CERT)" https://127.0.0.1:8087/kbs/v0/external/echo-test/hello && \
	curl -sf --cacert "$(HTTPS_CERT)" -H "Authorization: Bearer $$(cat $(PLUGIN_ATTESTATION_TOKEN))" \
		https://127.0.0.1:8087/kbs/v0/external/echo-test/hello | grep -q "Echo:" && \
	printf "${BOLD}external plugin integration test (attestation) passed${SGR0}\n"

# External plugin metrics test (verifies /metrics endpoint has plugin counters)
# Uses before/after snapshot so the test works regardless of prior requests.
.PHONY: test-ext-plugin-metrics
test-ext-plugin-metrics: start-echo-plugin start-ext-plugin-kbs
	@printf "${BOLD}running external plugin metrics test${SGR0}\n"
	before=$$(curl -sf http://127.0.0.1:8085/metrics | \
		sed -n 's/^kbs_plugin_request_duration_seconds_count{plugin_name="echo-test"} //p'); \
	before=$${before:-0}; \
	curl -sf -X POST http://127.0.0.1:8085/kbs/v0/external/echo-test/hello > /dev/null && \
	curl -sf -X POST http://127.0.0.1:8085/kbs/v0/external/echo-test/hello > /dev/null && \
	after=$$(curl -sf http://127.0.0.1:8085/metrics | \
		sed -n 's/^kbs_plugin_request_duration_seconds_count{plugin_name="echo-test"} //p') && \
	curl -sf http://127.0.0.1:8085/metrics | grep -q 'kbs_plugin_requests_total{plugin_name="echo-test"}' && \
	delta=$$((after - before)) && \
	if [ "$$delta" -eq 2 ]; then \
		printf "${BOLD}external plugin metrics test passed (count delta=%s)${SGR0}\n" "$$delta"; \
	else \
		printf "FAIL: expected delta=2, got delta=%s (before=%s, after=%s)\n" "$$delta" "$$before" "$$after"; \
		exit 1; \
	fi

$(EXT_RESOURCE_SECRET):
	mkdir -p $(WORK_DIR) && openssl rand 16 > $(EXT_RESOURCE_SECRET)

.PHONY: $(EXT_RESOURCE_POLICY)
$(EXT_RESOURCE_POLICY):
	echo "$$EXT_RESOURCE_PLUGIN_POLICY_REGO" > $(EXT_RESOURCE_POLICY)

# Start resource plugin server on :50053
.PHONY: start-plugin-resource
start-plugin-resource: plugin-resource.PID

plugin-resource.PID: plugin-resource
	@printf "${BOLD}start resource plugin${SGR0}\n"
	{ \
		PLUGIN_LISTEN_ADDR=127.0.0.1:50053 \
		PLUGIN_STORE_DATA=true \
		"$(CURDIR)/plugin-resource" \
		& echo $$! > plugin-resource.PID; \
	} && \
	sleep 1

# Start KBS with external resource plugin config (port 8088)
.PHONY: start-ext-resource-kbs
start-ext-resource-kbs: ext-resource-kbs.PID

ext-resource-kbs.PID: ext-plugin-kbs kbs-keys kbs-certs $(EXT_RESOURCE_POLICY)
	@printf "${BOLD}start ext-resource-kbs${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin-resource.toml" \
		& echo $$! > ext-resource-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-plugin-resource
stop-plugin-resource:
	@if [ -f plugin-resource.PID ]; then \
		printf "${BOLD}stop resource plugin${SGR0}\n"; \
		kill $$(cat plugin-resource.PID) 2>/dev/null || true; \
		rm -f plugin-resource.PID; \
	fi

.PHONY: stop-ext-resource-kbs
stop-ext-resource-kbs:
	@if [ -f ext-resource-kbs.PID ]; then \
		printf "${BOLD}stop ext-resource-kbs${SGR0}\n"; \
		kill $$(cat ext-resource-kbs.PID) 2>/dev/null || true; \
		rm -f ext-resource-kbs.PID; \
	fi

# External resource plugin roundtrip test:
# 1. Set resource policy via the built-in /kbs/v0/resource-policy endpoint.
# 2. POST a random secret via admin auth (InsecureAllowAll) to the external
#    plugin at /kbs/v0/external/resource/<path>.
# 3. Obtain an attestation token via kbs-client attest.
# 4. GET the secret back with the token and verify the roundtrip matches.
# Note: PLUGIN_ENCRYPT_GET is disabled — JWE decryption requires kbs-client
#       which hardcodes /kbs/v0/resource/... and cannot reach external plugins.
.PHONY: test-ext-resource-plugin
test-ext-resource-plugin: start-plugin-resource start-ext-resource-kbs client $(EXT_RESOURCE_SECRET) $(TEE_KEY)
	@printf "${BOLD}running external resource plugin roundtrip test${SGR0}\n"
	./client --url http://127.0.0.1:8088 \
		config --auth-private-key "$(KBS_KEY)" \
		set-resource-policy \
		--policy-file "$(EXT_RESOURCE_POLICY)" && \
	curl -sf -X POST \
		-H "Authorization: Bearer dummy" \
		--data-binary @"$(EXT_RESOURCE_SECRET)" \
		http://127.0.0.1:8088/kbs/v0/external/resource/$(EXT_STORE_PATH) && \
	./client --url http://127.0.0.1:8088 \
		attest --tee-key-file "$(TEE_KEY)" \
		> "$(WORK_DIR)/resource-attest-token" && \
	curl -sf \
		-H "Authorization: Bearer $$(cat $(WORK_DIR)/resource-attest-token)" \
		http://127.0.0.1:8088/kbs/v0/external/resource/$(EXT_STORE_PATH) \
		> "$(EXT_RESOURCE_ROUNDTRIP)" && \
	diff "$(EXT_RESOURCE_ROUNDTRIP)" "$(EXT_RESOURCE_SECRET)"
	@printf "${BOLD}external resource plugin roundtrip test passed${SGR0}\n"
	@printf "  stored   (base64): %s\n" "$$(base64 -w0 "$(EXT_RESOURCE_SECRET)")"
	@printf "  retrieved (base64): %s\n" "$$(base64 -w0 "$(EXT_RESOURCE_ROUNDTRIP)")"

# Start resource plugin server over TLS on :50054 (admin-gated POST, encrypted GET)
.PHONY: start-plugin-resource-tls
start-plugin-resource-tls: plugin-resource-tls.PID

plugin-resource-tls.PID: plugin-resource $(ECHO_PLUGIN_SERVER_CERT) $(ECHO_PLUGIN_SERVER_KEY)
	@printf "${BOLD}start resource plugin (TLS)${SGR0}\n"
	{ \
		PLUGIN_LISTEN_ADDR=127.0.0.1:50054 \
		PLUGIN_STORE_DATA=true \
		PLUGIN_TLS_CERT=$(ECHO_PLUGIN_SERVER_CERT) \
		PLUGIN_TLS_KEY=$(ECHO_PLUGIN_SERVER_KEY) \
		"$(CURDIR)/plugin-resource" \
		& echo $$! > plugin-resource-tls.PID; \
	} && \
	sleep 1

# Start KBS with external resource plugin TLS config (port 8089)
.PHONY: start-ext-resource-tls-kbs
start-ext-resource-tls-kbs: ext-resource-tls-kbs.PID

ext-resource-tls-kbs.PID: ext-plugin-kbs kbs-keys kbs-certs $(ECHO_PLUGIN_CA_CERT) $(EXT_RESOURCE_POLICY)
	@printf "${BOLD}start ext-resource-kbs (TLS)${SGR0}\n"
	{ \
		"$(CURDIR)/ext-plugin-kbs" --config-file "$(KBS_CONFIG_PATH)/external-plugin-resource-tls.toml" \
		& echo $$! > ext-resource-tls-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-plugin-resource-tls
stop-plugin-resource-tls:
	@if [ -f plugin-resource-tls.PID ]; then \
		printf "${BOLD}stop resource plugin (TLS)${SGR0}\n"; \
		kill $$(cat plugin-resource-tls.PID) 2>/dev/null || true; \
		rm -f plugin-resource-tls.PID; \
	fi

.PHONY: stop-ext-resource-tls-kbs
stop-ext-resource-tls-kbs:
	@if [ -f ext-resource-tls-kbs.PID ]; then \
		printf "${BOLD}stop ext-resource-kbs (TLS)${SGR0}\n"; \
		kill $$(cat ext-resource-tls-kbs.PID) 2>/dev/null || true; \
		rm -f ext-resource-tls-kbs.PID; \
	fi

# Resource plugin TLS roundtrip test: same as test-ext-resource-plugin but
# with TLS on the KBS→plugin gRPC connection.
.PHONY: test-ext-resource-plugin-tls
test-ext-resource-plugin-tls: start-plugin-resource-tls start-ext-resource-tls-kbs client $(EXT_RESOURCE_SECRET) $(TEE_KEY)
	@printf "${BOLD}running external resource plugin TLS roundtrip test${SGR0}\n"
	./client --url http://127.0.0.1:8089 \
		config --auth-private-key "$(KBS_KEY)" \
		set-resource-policy \
		--policy-file "$(EXT_RESOURCE_POLICY)" && \
	curl -sf -X POST \
		-H "Authorization: Bearer dummy" \
		--data-binary @"$(EXT_RESOURCE_SECRET)" \
		http://127.0.0.1:8089/kbs/v0/external/resource/$(EXT_STORE_PATH) && \
	./client --url http://127.0.0.1:8089 \
		attest --tee-key-file "$(TEE_KEY)" \
		> "$(WORK_DIR)/resource-tls-attest-token" && \
	curl -sf \
		-H "Authorization: Bearer $$(cat $(WORK_DIR)/resource-tls-attest-token)" \
		http://127.0.0.1:8089/kbs/v0/external/resource/$(EXT_STORE_PATH) \
		> "$(EXT_RESOURCE_TLS_ROUNDTRIP)" && \
	diff "$(EXT_RESOURCE_TLS_ROUNDTRIP)" "$(EXT_RESOURCE_SECRET)"
	@printf "${BOLD}external resource plugin TLS roundtrip test passed${SGR0}\n"
	@printf "  stored   (base64): %s\n" "$$(base64 -w0 "$(EXT_RESOURCE_SECRET)")"
	@printf "  retrieved (base64): %s\n" "$$(base64 -w0 "$(EXT_RESOURCE_TLS_ROUNDTRIP)")"

# Stop all external plugin processes
.PHONY: stop-ext-plugins
stop-ext-plugins: stop-echo-plugin stop-echo-plugin-tls stop-ext-plugin-kbs stop-ext-plugin-tls-kbs stop-ext-plugin-attest-kbs stop-plugin-resource stop-ext-resource-kbs stop-plugin-resource-tls stop-ext-resource-tls-kbs

# Run all external plugin tests; always run stop-ext-plugins even when a case fails
# (declarative prerequisite chains would skip stop after the first failing recipe).
.PHONY: e2e-ext-plugin
e2e-ext-plugin:
	@$(MAKE) test-ext-plugin test-ext-plugin-metrics test-ext-plugin-tls test-ext-plugin-attest test-ext-resource-plugin test-ext-resource-plugin-tls; \
	status=$$?; \
	$(MAKE) stop-ext-plugins; \
	if [ $$status -eq 0 ]; then \
		printf "${BOLD}all external plugin e2e tests passed${SGR0}\n"; \
	else \
		printf "${BOLD}external plugin e2e tests FAILED${SGR0}\n"; \
		exit 1; \
	fi
