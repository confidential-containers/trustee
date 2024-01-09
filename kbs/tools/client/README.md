# KBS Client Tool

This is a simple client for the KBS that facilitates testing of the KBS
and other basic attestation flows.

You can run this tool inside of a TEE to make a request with real attestation evidence.
You can also provide pre-existing evidence or use the sample attester as a fallback.

The client tool can also be used to provision the KBS/AS with resources and policies.

For more sophisticated attestation clients, please refer to [guest components](https://github.com/confidential-containers/guest-components)

For help:

```shell
./client -h
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

