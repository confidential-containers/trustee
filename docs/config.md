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

### Examples

``` json
{
    "repository_type": "LocalFs",
    "repository_description": {
        "dir_path": "/opt/confidential-containers/kbs/repository"
    },
    "attestation_token_type": "Simple",
    "as_addr": "http://127.0.0.1:50004"
}
```
