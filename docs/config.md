# KBS Configuration File

Some Confidential Containers KBS properties can be configured through a
JSON-formatted configuration file.

The location of this file is passed to the KBS binary with the `--config`
command line option.

## Configurable Properties

The following KBS properties can be set through the configuration file:

| Property Key             | Description | Optional |
|--------------------------|-------------|----------|
| `repository_type`        | The resource repository type, e.g. `LocalFs`.                                                                                              | No |
| `repository_description` | <p> The resource repository description. <p> This is a JSON string, and is repository type specific.                                       | Yes |
| `attestation_token_type` | Attestation token broker type, e.g. `Simple`.                                                                                              | No |
| `as_addr`                | <p>Attestation service socket address <p>This is only relevant when running the attestation service remotely, i.e. not as a builtin crate. | Yes |
| `as_config_file_path`    | <p>Attestation service configuration file path.                                                                                            | Yes |
| `amber`                  | <p>Amber description. <p>This is only relevant when running with Amber attestation service, and this is a JSON string, the following properties can be set: <p>`base_url` and `api_key` are used to call Amber API. <p>`certs_file` is a JWKS file to verify Amber token. <p>`allow_unmatched_policy` is optional, default is `false`. It determines whether to ignore the `amber_unmatched_policy_ids` field in Amber token. | Yes |

### Examples
Running the attestation service remotely:
``` json
{
    "repository_type": "LocalFs",
    "repository_description": {
        "dir_path": "/opt/confidential-containers/kbs/repository"
    },
    "attestation_token_type": "Simple",
    "as_addr": "http://127.0.0.1:50004",
}
```

Running with Amber attestation service:
``` json
{
    "repository_type": "LocalFs",
    "repository_description": {
        "dir_path": "/opt/confidential-containers/kbs/repository"
    },
    "attestation_token_type": "Simple",
    "amber" : {
        "base_url": "https://api-xxx.com",
        "api_key":  "tBfd5kKX2x9ahbodKV1...",
        "certs_file": "/etc/amber/amber-certs.txt",
        "allow_unmatched_policy": true
    }
}
```
