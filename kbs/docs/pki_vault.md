# PKI Vault plugin

This plugin currently generates credentials (keys and certificates) for a server running inside the confidential VM (aka sandbox) and for the workload owner (who acts as a client for the server). The current design of the plugin prioritizes the mutual authentication between the server and the client. Such design is necessary for the SplitAPI (kata-containers/kata-containers#9159 and
kata-containers/kata-containers#9752) and peer-pods.

This plugin also delivers the server-specific credentials to the sandbox (i.e., confidential PODs or VMs), specifically to the kata agent to initiate the server. The workload owner can communicate with the server using a secure tunnel.

The server-specific credentials can be obtained throught the `get-resource` APIs by specifying the `plugin-name`. Currently, the plugin requires that the sandbox or `kata-agent` sends the IPv4 address, name, and the ID of the sandbox (i.e., pod) as part of the query string to obtain the credentials from the KBS. 

After receiving the credential request, the `pki_vault` plugin will create a CA, a key pair for the server and another key pair for client, and sign them using the self-signed CA. Currently, the generated credentials are stored in a hashmap with a unique key for each sandbox based on its name, ID, and IP address. But we expect this design will be changed in future. PKI Vault plugin responds to a request from the sandbox by sending the server specific credentials (key, cert) along with the CA certificate. A request from workload owner gets the client specific credentials (key, cert) and CA's certificate.

# Setup

1. Build the KBS with the cargo feature `pki-vault-plugin` enabled.

```bash
make background-check-kbs POLICY_ENGINE=opa PKI_VAULT_PLUGIN=true
``` 

2. Configure the `pki-vault` plugin. Simply specifying the plugin name should be enough for the configuration, just add the lines below to the [KBS config](#kbs/config/docker-compose/kbs-config.toml). But one can specify addition details to the configuration file.

```toml
[[plugins]]
name = "pki_vault"
```
The following addition details can be set to the configuration file.
```toml
[[plugins]]
name = "pki_vault"
#plugin_dir = "/opt/confidential-containers/kbs/plugin/splitapi"
#cred_filename = "certificates.json"
[plugins.pkivault_cert_details]
country = "AA"
#state = "Default State"
#locality = "Default City"
organization = "Default Organization"
org_unit = "Default Unit"

[plugins.pkivault_cert_details.ca]
#common_name = "grpc-tls CA"
validity_days = 3650

[plugins.pkivault_cert_details.server]
#common_name = "server"
#validity_days = 180

[plugins.pkivault_cert_details.client]
common_name = "client"
validity_days = 180
```

3. Start trustee

```bash
sudo ../target/release/kbs --config-file ./config/kbs-config.toml
```
# Design choices [To be updated]

## 1. Separate CA for each server (sandbox)
## 2. Single CA for all
## 3. Persistence vs. non-persistence

# Runtime services

All runtime services for both the server and client supported are described in the following sections.

## Credentials service for server (i.e., pod or sandbox)

Request the credentials for initiating a server inside a pod or sandbox.

Only `GET` request is supported, e.g. `GET /kbs/v0/pki_vault/credentials?id=3367&ip=60.11.12.89&name=pod51`. Current the `GET` takes `id`, `ip`, and `name` parameters, but expect this parameters to be changed in the future design for supporting more generic use cases.

The request takes parameters via URL query string. All parameters supported are described in the table below. Note currently, all parameters are required.

| Property            | Type   | Required | Description             | Default | Example                                   |
|---------------------|--------|----------|-------------------------|---------|-------------------------------------------|
| `name`              | String | Yes      | Name of the pod |         | `credentials?id=3367&ip=60.11.12.89&name=pod51` |
| `ip`                | String | Yes      | IPv4 address of a pod to assign to the certificate |         | `credentials?id=3367&ip=60.11.12.89&name=pod51` |
| `id`          | String | Yes       | Pod ID |  | `credentials?id=3367&ip=60.11.12.89&name=pod51` |

The request will be processed only if the node passes the attestation, otherwise an error is returned. If the credentials for the server already already exists in the KBS, the plugin simply returns the existing credentials. Otherwise, the plugin generates the credentials.

Once the request is processed, the following structure is returned in JSON format.

```rust
pub struct CredentialsOut {
    pub key: Vec<u8>, // Key created
    pub cert: Vec<u8>, // Self-signed certificate created
    pub ca_cert: Vec<u8>, // CA certificate
}
```



## Credentials services for client (i.e., workload owner)

Request the client credentials for initiating a mutual TLS communication channel between client (workload owner) and the server (running inside a pod or sandbox).

### `list_pods`
Only `GET` request is supported, e.g. `GET /kbs/v0/pki_vault/list_pods`. Here, `list_pods` is an API that the client (or workload owner) can invoke to get the list of pod names and their additional information.

### `get_client_credentials`
Only `GET` request is supported, e.g. `GET /kbs/v0/pki_vault/get_client_credentials?id=3367&ip=60.11.12.89&name=pod51`. Here, `get_client_credentials` is an API that the client (or workload owner) can invoke to get the owner or client-specific credentails for a pod. A pod obtains the server-specific credentials through the `get_resource` API. The `get_client_credentials` API need a `query` parameter to indicate the target pod.

All APIs supported are described in the table below.

| API            |  Description             | Example                                   |
|---------------------|-------------------------|-------------------------------------------|
| `list_pods`              | To get the list of pods that have server credentials created| `kbs/v0/pki_vault/list_pods` |
| `get_client_credentials`              | To get the client credentials for a pod | `/kbs/v0/pki_vault/get_client_credentials?id=3367&ip=60.11.12.89&name=pod51` |

The request will be processed only if the request is authenticated, otherwise an error is returned. In the current design, the credentials for the client already already exists in the KBS as they have been already created as part of the response of server credential request, so the plugin simply returns the existing client credentials.

Once the request is processed, the following structure is returned in JSON format.

```rust
pub struct CredentialsOut {
    pub key: Vec<u8>, // Key created
    pub cert: Vec<u8>, // Self-signed certificate created
    pub ca_cert: Vec<u8>, // CA certificate
}
```


# How to test (client or owner-side code)
In order to test the `pki-vault` plugin, we need to enable the plugin support in the `kbs_protocol` inside `attestation-agent` of the `guest-components` respository. The plugin support has been enabled in the `pki-vault-test` branch of following `guest-components` repository.

`https://github.com/salmanyam/guest-components/tree/pki-vault-test`

In addition to that, we need to patch the `kbs-client` located inside `tools` of `trustee`, so that the `kbs-client` can invoke the plugin call. A patched version of the `kbs-client` can be located in the `pki-vault-test` branch of the following `trustee` repository.

`https://github.com/salmanyam/trustee/commits/pki-vault-test/`

This patched `kbs-client` has also used the patched `guest-component` with the modified `kbs_protocol`.

```
kbs_protocol = { git = "https://github.com/salmanyam/guest-components.git", rev = "281be58d49e91a13a1c55fb30324c705f9d0d9c5", default-features = false }
kms = { git = "https://github.com/salmanyam/guest-components.git", rev = "281be58d49e91a13a1c55fb30324c705f9d0d9c5", default-features = false }
```

Once the `kbs-client` is built, use the `kbs-client` to make a request to KBS for generating and providing the server specific credentials.

## Step-by-step instructions

Pull the patched `kbs-client` code
```
$ git clone https://github.com/salmanyam/trustee.git
$ cd trustee
$ git checkout pki-vault-test
```

Build the `kbs-client` code
```
$ cd kbs && make cli
```
> **Note:** To specify an attester, please use the `ATTESTER` environment variable, e.g., `ATTESTER=snp-attester`



To invoke the `get_resource` API. KBS should return the server specific credentials such as server key, server certificates, and the certificate of the CA.
```
$ sudo ../target/release/kbs-client --url http://127.0.0.1:8080 get-resource --plugin-name "pki_vault" --resource-path "credentials?id=3367353&ip=60.11.12.48&name=pod33" | base64 -d
```


To invoke the `list_pods` API. This should return the list of pod names and associated information.

```
$ sudo ../target/release/kbs-client --url http://127.0.0.1:8080 pki-vault-config --auth-private-key config/private.key list-pods
```



To invoke the `get_client_credentials` API. This should return the client credentials of the following format.
```
$ sudo ../target/release/kbs-client --url http://127.0.0.1:8080 pki-vault-config --auth-private-key config/private.key get-client-credentials --query "name=pod51&ip=60.11.12.89&id=3367383"
```


```
pub struct Credentials {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
    pub ca_cert: Vec<u8>,
}
```
