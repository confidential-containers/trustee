# PKI Vault plugin

This plugin currently generates credentials (keys and certificates) for the confidential VM (aka pod VM or sandbox) and for the owner of the confidential workload that runs inside the confidential VM as a confidential container. The credentials allow us to establish a secured client-server communication where the owner acts as a client for the server. Such a design is useful for the SplitAPI (kata-containers/kata-containers#9159 and
kata-containers/kata-containers#9752) and peer-pods. The current design of the plugin prioritizes the mutual authentication between the server and the client.

This plugin also delivers the credentials to the confidential pod VM through the invocation of the `get-resource` API call by specifying the `plugin-name`. Currently, the plugin requires that the pod VM sends an identifier (required) and any additinal parameters as part of the query string passed to the `get-resource` API as the `resource-path`. The identifier is used as a key to obtain the credentials from the KBS.

Once receiving the credential request from pod VM through `get-resource` API, the plugin creates a CA and two key pairs (one for pod VM and another for workload owner), and signs the key pairs using the self-signed CA. Currently, the generated credentials are stored in a hashmap with the identifer as the key for each pod VM. PKI Vault plugin responds to a request from the pod VM by sending the server specific credentials (key, cert) along with the CA certificate. A request from workload owner gets the client specific credentials (key, cert) and CA's certificate.

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
plugin_dir = "/opt/confidential-containers/kbs/plugin/splitapi"
cred_filename = "certificates.json"

[plugins.pkivault_cert_details]
country = "AA"
state = "Default State"
locality = "Default City"
organization = "Default Organization"
org_unit = "Default Unit"

[plugins.pkivault_cert_details.ca]
common_name = "grpc-tls CA"
validity_days = 3650

[plugins.pkivault_cert_details.server]
common_name = "server"
validity_days = 180

[plugins.pkivault_cert_details.client]
common_name = "client"
validity_days = 180
```

3. Start trustee

```bash
sudo ../target/release/kbs --config-file ./config/kbs-config.toml
```
# Design choices
There can be three key design choices one can consider to configure PKI Vault plugin. As of now, PKI Vault only supports the separte CA per Pod approach with a non-persistent credential storage.

1. **Separate CA per Pod VM**:
Each pod VM gets its own Certificate Authority (CA), meaning every sandbox has an independent root of trust. This design isolates security domains — if one pod’s CA is compromised, others remain safe. It also simplifies per-pod credential generation and teardown. However, it creates more CA certificates to manage and requires persistent storage so that a pod’s CA isn’t lost after a restart.

2. **Single CA for All Pod VMs**:
Using one global CA to sign credentials for all pod VMs simplifies trust management, since all pods share the same root certificate. It reduces operational overhead and avoids losing trust links after service restarts. The downside is that it introduces a single point of failure — if the CA key is compromised, all pods are affected — and reduces isolation between sandboxes.

3. **Persistent vs. Non-Persistent Credential Storage**:
Persistent storage keeps CA keys and certificates on disk so they survive restarts, maintaining continuity in authentication. Non-persistent storage is simpler and more secure in the sense that credentials vanish after shutdown, but it breaks mutual authentication if the service restarts. In this design, persistence is chosen to ensure pod CAs and credentials remain valid even after trustee restarts.

# Runtime services

All the supported runtime services for both the Pod VM and workload owner are described in the following sections.

## Credentials service for Pod VM

A Pod VM requests the the credentials (e.g., to initiate a server inside the pod VM) through the `GET` request.

Only the `GET` request is supported, e.g., `GET /kbs/v0/pki_vault/credentials?token=podToken12345&name=pod51&ip=60.11.12.89`. Currently, the `GET` takes `name`, `token`, and `ip` parameters. The Pod VM can pass the `name` and `ip` parameters to the request, but owner has to set the `token` to the Pod VM through init data. The `token`, together with the `name` and `ip`, serves as a unique identifier for associating a Pod VM with its record. This identifier is used as the key in a hashmap to store the Pod VM’s credentials.

The request takes parameters via URL query string. All parameters supported are described in the table below. 

>**Note:** Currently, all parameters are required. We have plan to support additional parameters in the query string in later version. A policy can help check the query string.

| Property            | Type   | Required | Description             | Example                                   |
|---------------------|--------|----------|-------------------------|-------------------------------------------|
| `token`          | String | Yes       | Token assigned to the Pod by owner | `credentials?token=podToken12345` |
| `name`              | String | Yes      | Pod name | `credentials?name=pod51` |
| `ip`                | String | Yes      | IPv4 address of a pod to assign to the certificate | `credentials?ip=60.11.12.89` |


The request will be processed only if the node passes the attestation, otherwise an error is returned. If the credentials for the Pod VM already exists in Trustee, the plugin simply returns the existing credentials. Otherwise, the plugin generates the credentials.

Once the request is processed, the following structure is returned in JSON format.

```rust
pub struct CredentialsOut {
    pub key: Vec<u8>, // Key created
    pub cert: Vec<u8>, // Self-signed certificate created
    pub ca_cert: Vec<u8>, // CA certificate
}
```
Example credentials are below:
```rust
{
    "key":[45,45,45,45,45,66,69,71,73,78,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10,77,67,52,67,65,81,65,119,66,81,89,68,75,50,86,119,66,67,73,69,73,79,109,112,47,49,69,73,50,82,65,90,73,99,117,87,99,108,54,80,111,100,104,101,79,85,68,119,65,57,52,82,109,109,78,83,81,114,86,98,50,50,113,55,10,45,45,45,45,45,69,78,68,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10],
    "cert":[45,45,45,45,45,66,69,71,73,78,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10,77,73,73,67,110,68,67,67,65,107,54,103,65,119,73,66,65,103,73,66,65,106,65,70,66,103,77,114,90,88,65,119,103,89,103,120,67,122,65,74,66,103,78,86,66,65,89,84,65,107,70,66,77,82,89,119,70,65,89,68,86,81,81,73,10,68,65,49,69,90,87,90,104,100,87,120,48,73,70,78,48,89,88,82,108,77,82,85,119,69,119,89,68,86,81,81,72,68,65,120,69,90,87,90,104,100,87,120,48,73,69,78,112,100,72,107,120,72,84,65,98,66,103,78,86,66,65,111,77,10,70,69,82,108,90,109,70,49,98,72,81,103,84,51,74,110,89,87,53,112,101,109,70,48,97,87,57,117,77,82,85,119,69,119,89,68,86,81,81,76,68,65,120,69,90,87,90,104,100,87,120,48,73,70,86,117,97,88,81,120,70,68,65,83,10,66,103,78,86,66,65,77,77,67,50,100,121,99,71,77,116,100,71,120,122,73,69,78,66,77,66,52,88,68,84,73,49,77,84,69,120,77,84,69,50,77,122,81,121,78,49,111,88,68,84,73,50,77,68,85,120,77,68,69,50,77,122,81,121,10,78,49,111,119,103,89,77,120,67,122,65,74,66,103,78,86,66,65,89,84,65,107,70,66,77,82,89,119,70,65,89,68,86,81,81,73,68,65,49,69,90,87,90,104,100,87,120,48,73,70,78,48,89,88,82,108,77,82,85,119,69,119,89,68,10,86,81,81,72,68,65,120,69,90,87,90,104,100,87,120,48,73,69,78,112,100,72,107,120,72,84,65,98,66,103,78,86,66,65,111,77,70,69,82,108,90,109,70,49,98,72,81,103,84,51,74,110,89,87,53,112,101,109,70,48,97,87,57,117,10,77,82,85,119,69,119,89,68,86,81,81,76,68,65,120,69,90,87,90,104,100,87,120,48,73,70,86,117,97,88,81,120,68,122,65,78,66,103,78,86,66,65,77,77,66,110,78,108,99,110,90,108,99,106,65,113,77,65,85,71,65,121,116,108,10,99,65,77,104,65,80,122,80,102,119,105,57,69,51,48,47,88,114,117,99,88,66,88,119,97,120,68,118,109,108,102,47,122,77,57,88,115,51,56,53,84,72,69,104,72,110,111,76,111,52,72,102,77,73,72,99,77,65,119,71,65,49,85,100,10,69,119,69,66,47,119,81,67,77,65,65,119,67,119,89,68,86,82,48,80,66,65,81,68,65,103,87,103,77,66,48,71,65,49,85,100,68,103,81,87,66,66,84,66,69,75,99,69,89,65,122,67,57,88,85,72,51,105,43,98,71,113,101,68,10,84,74,54,79,97,84,67,66,110,119,89,68,86,82,48,106,66,73,71,88,77,73,71,85,111,89,71,79,112,73,71,76,77,73,71,73,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,66,81,84,69,87,77,66,81,71,65,49,85,69,10,67,65,119,78,82,71,86,109,89,88,86,115,100,67,66,84,100,71,70,48,90,84,69,86,77,66,77,71,65,49,85,69,66,119,119,77,82,71,86,109,89,88,86,115,100,67,66,68,97,88,82,53,77,82,48,119,71,119,89,68,86,81,81,75,10,68,66,82,69,90,87,90,104,100,87,120,48,73,69,57,121,90,50,70,117,97,88,112,104,100,71,108,118,98,106,69,86,77,66,77,71,65,49,85,69,67,119,119,77,82,71,86,109,89,88,86,115,100,67,66,86,98,109,108,48,77,82,81,119,10,69,103,89,68,86,81,81,68,68,65,116,110,99,110,66,106,76,88,82,115,99,121,66,68,81,89,73,66,65,68,65,70,66,103,77,114,90,88,65,68,81,81,67,104,54,98,66,117,77,53,65,79,119,52,80,116,117,109,90,49,54,111,55,83,10,103,112,99,104,121,90,99,51,102,71,97,78,78,51,43,65,53,47,111,81,99,98,70,48,108,73,108,106,75,88,121,56,121,90,90,113,51,119,89,87,78,116,99,115,122,48,54,118,102,116,117,99,86,88,105,66,47,103,109,120,82,86,85,77,10,45,45,45,45,45,69,78,68,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10],
    "ca_cert":[45,45,45,45,45,66,69,71,73,78,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10,77,73,73,66,117,106,67,67,65,87,119,67,65,81,65,119,66,81,89,68,75,50,86,119,77,73,71,73,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,66,81,84,69,87,77,66,81,71,65,49,85,69,67,65,119,78,82,71,86,109,10,89,88,86,115,100,67,66,84,100,71,70,48,90,84,69,86,77,66,77,71,65,49,85,69,66,119,119,77,82,71,86,109,89,88,86,115,100,67,66,68,97,88,82,53,77,82,48,119,71,119,89,68,86,81,81,75,68,66,82,69,90,87,90,104,10,100,87,120,48,73,69,57,121,90,50,70,117,97,88,112,104,100,71,108,118,98,106,69,86,77,66,77,71,65,49,85,69,67,119,119,77,82,71,86,109,89,88,86,115,100,67,66,86,98,109,108,48,77,82,81,119,69,103,89,68,86,81,81,68,10,68,65,116,110,99,110,66,106,76,88,82,115,99,121,66,68,81,84,65,101,70,119,48,121,78,84,69,120,77,84,69,120,78,106,77,48,77,106,100,97,70,119,48,122,78,84,69,120,77,68,107,120,78,106,77,48,77,106,100,97,77,73,71,73,10,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,66,81,84,69,87,77,66,81,71,65,49,85,69,67,65,119,78,82,71,86,109,89,88,86,115,100,67,66,84,100,71,70,48,90,84,69,86,77,66,77,71,65,49,85,69,66,119,119,77,10,82,71,86,109,89,88,86,115,100,67,66,68,97,88,82,53,77,82,48,119,71,119,89,68,86,81,81,75,68,66,82,69,90,87,90,104,100,87,120,48,73,69,57,121,90,50,70,117,97,88,112,104,100,71,108,118,98,106,69,86,77,66,77,71,10,65,49,85,69,67,119,119,77,82,71,86,109,89,88,86,115,100,67,66,86,98,109,108,48,77,82,81,119,69,103,89,68,86,81,81,68,68,65,116,110,99,110,66,106,76,88,82,115,99,121,66,68,81,84,65,113,77,65,85,71,65,121,116,108,10,99,65,77,104,65,74,116,89,115,52,68,83,115,51,81,53,117,78,54,75,51,55,77,103,51,50,76,104,88,103,100,89,111,49,69,55,101,104,120,70,82,100,119,65,102,122,57,71,77,65,85,71,65,121,116,108,99,65,78,66,65,79,73,103,10,90,105,109,66,47,101,120,106,77,47,78,113,117,52,106,65,86,116,68,74,47,107,108,109,84,97,103,76,79,98,109,103,122,107,114,110,55,50,102,53,69,51,84,104,121,116,69,49,79,85,104,83,114,109,102,98,97,118,83,114,78,57,73,90,10,102,119,57,98,66,81,110,79,101,87,78,113,122,109,101,74,115,119,52,61,10,45,45,45,45,45,69,78,68,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10]
}
```

## Credentials services for workload owner

The workload owners can retrieve the client (or owner) specific credentials from Trustee. A workload woner (who has the private key of Trustee) can invoke the following APIs.

### `list_pods`
Only `GET` request is supported, e.g. `GET /kbs/v0/pki_vault/list_pods`. Here, `list_pods` is an API that the client (or workload owner) can invoke to get the list of pod names and their additional information.

### `client_credentials`
Only `GET` request is supported, e.g. `GET /kbs/v0/pki_vault/client_credentials?token=podToken12345&name=pod51&ip=60.11.12.89`. Here, `client_credentials` is an API that the workload owner can invoke to get the owner or client-specific credentails for a pod. A Pod VM obtains the server-specific credentials through the `get_resource` API. The `client_credentials` API also need to pass the same set of parameters through the `query` string to indicate the target pod.

All APIs supported are described in the table below.

| API            |  Description             | Example                                   |
|---------------------|-------------------------|-------------------------------------------|
| `list_pods`              | To get the list of pods that have server credentials created| `kbs/v0/pki_vault/list_pods` |
| `client_credentials`              | To get the client credentials for a pod | `/kbs/v0/pki_vault/client_credentials?token=podToken12345&name=pod51&ip=60.11.12.89` |

The request will be processed only if the request is authenticated, otherwise an error is returned. The credentials for the client already already exists in the KBS as they have been already created as part of the response of server credential request, so the plugin simply returns the existing client credentials.

Once the request is processed, the following structure is returned in JSON format.

```rust
pub struct CredentialsOut {
    pub key: Vec<u8>, // Key created
    pub cert: Vec<u8>, // Self-signed certificate created
    pub ca_cert: Vec<u8>, // CA certificate
}
```

Example credentials are below:

```rust
{ 
    key:[45,45,45,45,45,66,69,71,73,78,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10,77,67,52,67,65,81,65,119,66,81,89,68,75,50,86,119,66,67,73,69,73,66,114,83,49,51,47,79,56,65,76,53,108,116,122,117,105,78,105,53,82,120,48,82,56,57,90,105,116,49,103,88,67,77,88,89,51,80,47,87,81,56,86,97,10,45,45,45,45,45,69,78,68,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10],
    cert:[45,45,45,45,45,66,69,71,73,78,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10,77,73,73,67,110,68,67,67,65,107,54,103,65,119,73,66,65,103,73,66,65,106,65,70,66,103,77,114,90,88,65,119,103,89,103,120,67,122,65,74,66,103,78,86,66,65,89,84,65,107,70,66,77,82,89,119,70,65,89,68,86,81,81,73,10,68,65,49,69,90,87,90,104,100,87,120,48,73,70,78,48,89,88,82,108,77,82,85,119,69,119,89,68,86,81,81,72,68,65,120,69,90,87,90,104,100,87,120,48,73,69,78,112,100,72,107,120,72,84,65,98,66,103,78,86,66,65,111,77,10,70,69,82,108,90,109,70,49,98,72,81,103,84,51,74,110,89,87,53,112,101,109,70,48,97,87,57,117,77,82,85,119,69,119,89,68,86,81,81,76,68,65,120,69,90,87,90,104,100,87,120,48,73,70,86,117,97,88,81,120,70,68,65,83,10,66,103,78,86,66,65,77,77,67,50,100,121,99,71,77,116,100,71,120,122,73,69,78,66,77,66,52,88,68,84,73,49,77,84,69,120,77,84,69,50,78,68,89,121,78,49,111,88,68,84,73,50,77,68,85,120,77,68,69,50,78,68,89,121,10,78,49,111,119,103,89,77,120,67,122,65,74,66,103,78,86,66,65,89,84,65,107,70,66,77,82,89,119,70,65,89,68,86,81,81,73,68,65,49,69,90,87,90,104,100,87,120,48,73,70,78,48,89,88,82,108,77,82,85,119,69,119,89,68,10,86,81,81,72,68,65,120,69,90,87,90,104,100,87,120,48,73,69,78,112,100,72,107,120,72,84,65,98,66,103,78,86,66,65,111,77,70,69,82,108,90,109,70,49,98,72,81,103,84,51,74,110,89,87,53,112,101,109,70,48,97,87,57,117,10,77,82,85,119,69,119,89,68,86,81,81,76,68,65,120,69,90,87,90,104,100,87,120,48,73,70,86,117,97,88,81,120,68,122,65,78,66,103,78,86,66,65,77,77,66,110,78,108,99,110,90,108,99,106,65,113,77,65,85,71,65,121,116,108,10,99,65,77,104,65,66,88,105,90,70,54,106,115,102,48,72,53,88,121,43,66,117,107,109,65,65,115,90,81,51,85,66,89,108,86,121,119,66,103,82,88,72,71,77,54,102,103,56,111,52,72,102,77,73,72,99,77,65,119,71,65,49,85,100,10,69,119,69,66,47,119,81,67,77,65,65,119,67,119,89,68,86,82,48,80,66,65,81,68,65,103,87,103,77,66,48,71,65,49,85,100,68,103,81,87,66,66,81,68,108,55,70,52,85,90,106,104,71,55,80,90,50,43,105,52,70,70,74,75,10,104,114,72,77,55,122,67,66,110,119,89,68,86,82,48,106,66,73,71,88,77,73,71,85,111,89,71,79,112,73,71,76,77,73,71,73,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,66,81,84,69,87,77,66,81,71,65,49,85,69,10,67,65,119,78,82,71,86,109,89,88,86,115,100,67,66,84,100,71,70,48,90,84,69,86,77,66,77,71,65,49,85,69,66,119,119,77,82,71,86,109,89,88,86,115,100,67,66,68,97,88,82,53,77,82,48,119,71,119,89,68,86,81,81,75,10,68,66,82,69,90,87,90,104,100,87,120,48,73,69,57,121,90,50,70,117,97,88,112,104,100,71,108,118,98,106,69,86,77,66,77,71,65,49,85,69,67,119,119,77,82,71,86,109,89,88,86,115,100,67,66,86,98,109,108,48,77,82,81,119,10,69,103,89,68,86,81,81,68,68,65,116,110,99,110,66,106,76,88,82,115,99,121,66,68,81,89,73,66,65,68,65,70,66,103,77,114,90,88,65,68,81,81,65,54,48,80,122,65,67,74,121,87,109,77,104,67,43,71,57,98,118,102,67,80,10,116,66,102,109,86,67,89,89,90,116,108,84,115,90,99,104,51,112,118,116,76,102,81,114,55,113,105,79,111,112,71,57,87,50,87,49,104,75,77,50,87,103,105,104,51,114,108,106,67,80,115,70,83,70,90,115,86,99,85,119,118,56,69,71,10,45,45,45,45,45,69,78,68,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10],
    ca_cert:[45,45,45,45,45,66,69,71,73,78,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10,77,73,73,66,117,106,67,67,65,87,119,67,65,81,65,119,66,81,89,68,75,50,86,119,77,73,71,73,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,66,81,84,69,87,77,66,81,71,65,49,85,69,67,65,119,78,82,71,86,109,10,89,88,86,115,100,67,66,84,100,71,70,48,90,84,69,86,77,66,77,71,65,49,85,69,66,119,119,77,82,71,86,109,89,88,86,115,100,67,66,68,97,88,82,53,77,82,48,119,71,119,89,68,86,81,81,75,68,66,82,69,90,87,90,104,10,100,87,120,48,73,69,57,121,90,50,70,117,97,88,112,104,100,71,108,118,98,106,69,86,77,66,77,71,65,49,85,69,67,119,119,77,82,71,86,109,89,88,86,115,100,67,66,86,98,109,108,48,77,82,81,119,69,103,89,68,86,81,81,68,10,68,65,116,110,99,110,66,106,76,88,82,115,99,121,66,68,81,84,65,101,70,119,48,121,78,84,69,120,77,84,69,120,78,106,77,48,77,106,100,97,70,119,48,122,78,84,69,120,77,68,107,120,78,106,77,48,77,106,100,97,77,73,71,73,10,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,66,81,84,69,87,77,66,81,71,65,49,85,69,67,65,119,78,82,71,86,109,89,88,86,115,100,67,66,84,100,71,70,48,90,84,69,86,77,66,77,71,65,49,85,69,66,119,119,77,10,82,71,86,109,89,88,86,115,100,67,66,68,97,88,82,53,77,82,48,119,71,119,89,68,86,81,81,75,68,66,82,69,90,87,90,104,100,87,120,48,73,69,57,121,90,50,70,117,97,88,112,104,100,71,108,118,98,106,69,86,77,66,77,71,10,65,49,85,69,67,119,119,77,82,71,86,109,89,88,86,115,100,67,66,86,98,109,108,48,77,82,81,119,69,103,89,68,86,81,81,68,68,65,116,110,99,110,66,106,76,88,82,115,99,121,66,68,81,84,65,113,77,65,85,71,65,121,116,108,10,99,65,77,104,65,74,116,89,115,52,68,83,115,51,81,53,117,78,54,75,51,55,77,103,51,50,76,104,88,103,100,89,111,49,69,55,101,104,120,70,82,100,119,65,102,122,57,71,77,65,85,71,65,121,116,108,99,65,78,66,65,79,73,103,10,90,105,109,66,47,101,120,106,77,47,78,113,117,52,106,65,86,116,68,74,47,107,108,109,84,97,103,76,79,98,109,103,122,107,114,110,55,50,102,53,69,51,84,104,121,116,69,49,79,85,104,83,114,109,102,98,97,118,83,114,78,57,73,90,10,102,119,57,98,66,81,110,79,101,87,78,113,122,109,101,74,115,119,52,61,10,45,45,45,45,45,69,78,68,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10]

}
```