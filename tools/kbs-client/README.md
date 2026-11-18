# KBS Client Tool

This is a simple client for the KBS that facilitates testing of the KBS
and other basic attestation flows.

You can run this tool inside of a TEE to make a request with real attestation evidence.
You can also provide pre-existing evidence or use the sample attester as a fallback.

The client tool can also be used to provision the KBS/AS with resources and policies.

For more sophisticated attestation clients, please refer to [guest components](https://github.com/confidential-containers/guest-components)

For help:

```shell
kbs-client -h
```

We have a community version of kbs-client on [Github ORAS](https://github.com/confidential-containers/trustee/pkgs/container/staged-images%2Fkbs-client).

## Building and installing the client

Build the client binary with support to the default features as:

```shell
make -C ../../kbs cli
```

By default the client is built with support to the all attesters. If you want to build it with that sample attester only (this will
require fewer dependencies and so usually handy for CI) then you can pass the
`sample_only` feature as:

```shell
make -C ../../kbs cli CLI_FEATURES=sample_only
```

Find the built binary at `../../target/release/kbs-client`. You can get it
installed into the system as:
```shell
sudo make -C ../../kbs install-cli
```

### Building a container image

Build the client image from the repository root, selecting a comma-separated
list of attesters with the `attesters` build argument:
```shell
docker build -f kbs/docker/kbs-client-image/Dockerfile \
	--build-arg attesters=tdx-attester,az-tdx-vtpm-attester \
	-t kbs-client .
```

Usage example:
```shell
docker run --rm kbs-client kbs-client --version
```

Omitting the `attesters` argument builds the sample-only variant, intended for
testing rather than production attestation. Use `attesters=all-attesters` to
enable all attesters on amd64.

See the [client image documentation](../../kbs/docker/kbs-client-image/README.md)
for toolchain configuration, published images, and attester-specific dependencies.

## Examples

Get a resource from the KBS (after attesting)

```shell
./kbs-client --url http://127.0.0.1:8080 get-resource --path my_repo/resource_type/123abc
```

Add a resource to the KBS

```shell
./kbs-client --url http://127.0.0.1:8080 config --admin-token-file ../../kbs/config/docker-compose/admin-token set-resource --path my_repo/resource_type/123abc --resource-file test_resource
```

Set a resource policy
```shell
./kbs-client --url http://127.0.0.1:8080 config --admin-token-file ../../kbs/config/docker-compose/admin-token set-resource-policy --policy-file allow_all.rego
```

