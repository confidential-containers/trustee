Set `TRUSTEE_SRC` to the absolute path of the checked out trustee repo:

```sh
export TRUSTEE_SRC="__set_me__"
cd "${TRUSTEE_SRC}"
```

# Build "grpc" mode

From the top-level directory:

```sh
make -C attestation-service build VERIFIER=cca-verifier
make -C rvps build
make -C kbs build AS_TYPE=coco-as-grpc
```

# Setup Once

* Trustee services workdir

```sh
TRUSTEE_WDIR="/opt/confidential-containers"

sudo mkdir -p "${TRUSTEE_WDIR}/attestation-service/cca/opa"
sudo chown -R $(id -un):$(id -gn) "${TRUSTEE_WDIR}"
```

* `/etc/hosts`

```sh
sudo sh -c 'printf "# trustee services\n127.0.0.1 kbs rvps grpc-as\n" >> /etc/hosts'
```

* Endorsement stores

```sh
cp ${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/tastore.json "${TRUSTEE_WDIR}/attestation-service/cca/"
cp ${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/rvstore.json "${TRUSTEE_WDIR}/attestation-service/cca/"
```

* CCA OPA policy

```sh
cp ${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/default.rego "${TRUSTEE_WDIR}/attestation-service/cca/opa/"
```


# Run

## `kbs`

```sh
RUST_LOG=debug ${TRUSTEE_SRC}/target/release/kbs -c ${TRUSTEE_SRC}/kbs/conf/kbs-config-grpc.toml
```

## `rvps`

`rvps` MUST start before `as`

```sh
RUST_LOG=debug ${TRUSTEE_SRC}/target/release/rvps -c ${TRUSTEE_SRC}/kbs/conf/rvps.json
```

Once `rvps` is started, to configure the needed reference values, do:

```sh
( cd ${TRUSTEE_SRC}/deps/verifier/test_data/cca/scripts && \
  RIM="rof79/EF5xp4J8tvCJaInHPSvq9IMNT5ywXj6Ww/x7T6oEyvNqJr0JTPnHtzhhfkwYmq7hhN7dpdegPDnb2sfA==" ./endorse-rim.sh )
```

## `as`

* local verifier:

```sh
CCA_CONFIG_FILE=${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/cca-config-local.json \
RUST_LOG=debug \
  ${TRUSTEE_SRC}/target/release/grpc-as \
    -c ${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/as-config.json \
    -s 127.0.0.1:50004
```

* remote verifier:

```sh
CCA_CONFIG_FILE=${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/cca-config-remote.json \
RUST_LOG=debug \
  ${TRUSTEE_SRC}/target/debug/grpc-as \
    -c ${TRUSTEE_SRC}/deps/verifier/test_data/cca/conf/as-config.json \
    -s 127.0.0.1:50004
```

## `kbc` emulator

```sh
( cd ${TRUSTEE_SRC}/deps/verifier/test_data/cca/scripts && ./kbs-test-client.sh )
```