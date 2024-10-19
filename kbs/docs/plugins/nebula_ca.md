# Nebula CA plugin

[Nebula](https://github.com/slackhq/nebula) is an open-source project that provides
tooling to create a Layer 3 Encrypted Nebula Overlay Network (ENON). Each Nebula release
provides two binaries.
- nebula: it's used to create nodes (Lighthouse or regular node) and
join to a Lighthouse's ENON
- nebula-cert: executable to generate keys, certificates, CA's, and to sign node certificates.

This plugin calls the `nebula-cert` binary to provide some of its CA functionalities for
nodes (e.g. CoCo PODs or confidential VMs) that want to join an ENON.

Every ENON must have at least one Lighthouse, which is a node that has an static IP address, identifies the ENON and helps with node discovery.

## Setup

1. Build the KBS with the cargo feature `nebula-ca-plugin` enabled and install the `nebula-cert` binary to the KBS image.

```bash
docker compose build --build-arg NEBULA_CA_PLUGIN=true
``` 

2. Configure the `nebula-ca` plugin. For simple cases, the plugin default configurations should be enough, just add the lines below to the [KBS config](#kbs/config/docker-compose/kbs-config.toml). For more complex cases, see the [config.md](#kbs/docs/config.md).

```toml
[[plugins]]
name = "nebula-ca"
```

3. Start trustee

```bash
docker compose up
```

## Runtime services

All runtime services supported are described in the following sections.

### credential service

Create a credential for the node to join an ENON.

Only `GET` request is supported, e.g. `GET /kbs/v0/nebula-ca/credential?name=podA&ip=10.9.8.7/21`.

The request takes parameters via URL query string. All parameters supported are described in the table below. Note that `name` and `ip` are required.

| Property            | Type   | Required | Description             | Default | Example                                   |
|---------------------|--------|----------|-------------------------|---------|-------------------------------------------|
| `name`              | String | Yes      | Name of the certificate, usually hostname or podname |         | `credential?name=podA&ip=10.9.8.7/21` |
| `ip`                | String | Yes      | IPv4 address and network in CIDR notation to assign to the certificate |         | `credential?name=podA&ip=10.9.8.7/21` |
| `duration`          | String | No       | How long the certificate should be valid for. | 1 second before the signing certificate expires. Valid time units are: <hours>"h"<minutes>"m"<seconds>"s" | `credential?name=podA&ip=10.9.8.7/21&duration=8760h0m0s` |
| `groups`            | String | No       | Comma separated list of groups |         | `credential?name=podA&ip=10.9.8.7/21&groups=ssh,server` |
| `subnets`           | String | No       | Comma separated list of IPv4 address and network in CIDR notation. Subnets the certificate can serve for. |         | `credential?name=podA&ip=10.9.8.7/21&subnets=10.9.7.7/21,10.9.8.7/21` |

The request will be processed only if the node passes the attestation, otherwise an error is returned. With that, the ENON is expected to have only attested nodes.

Once the request is processed, the following structure is returned in JSON format.

```rust
struct CredentialServiceOut {
    node_crt: Vec<u8>,  // Self-signed certificate created
    node_key: Vec<u8>,  // Key created
    ca_crt: Vec<u8>,    // CA certificate
}
```

Currently, this service provides only basic functionality.
- It is stateless. Once a requested credential is returned, it is deleted.
- It does not support [CA rotation](https://nebula.defined.net/docs/guides/rotating-certificate-authority/).
- It does not support runtime attestation. If the same POD requests another credential later, the changes made to the POD's initial state will not be attested. Ideally, the POD should make sure that the certificate will not expire before the workload is finished.
- It does not have any information about Lighthouses, so it is not able to check if the IP address provided in the request and the IP address of the Lighthouse are in the same network.