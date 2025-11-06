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

## Examples

Get a resource from the KBS (after attesting)

```shell
./kbs-client --url http://127.0.0.1:8080 get-resource --path my_repo/resource_type/123abc
```

Add a resource to the KBS

```shell
./kbs-client --url http://127.0.0.1:8080 config --auth-private-key ../../kbs/config/private.key  set-resource --path my_repo/resource_type/123abc --resource-file test_resource
```

Set a resource policy
```shell
./kbs-client --url http://127.0.0.1:8080 config --auth-private-key ../../kbs/config/private.key  set-resource-policy --policy-file allow_all.rego
```

