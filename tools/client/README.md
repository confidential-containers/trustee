# KBS Client Tool

This is a simple KBS Client cmdline tool for test.
It use [Attestation Agent](https://github.com/confidential-containers/attestation-agent) CC-KBC.

## Usage

For help:

```shell
./client -h
```

Request resource from KBS:

```shell
./client --resource-uri kbs://127.0.0.1:8080/<repository>/<type>/<tag>
```

Where the format of [KBS Resource URI](https://github.com/confidential-containers/attestation-agent/blob/main/docs/KBS_URI.md) is defined by Attestation Agent.

Make sure this client run inside a real TEE which [Attestation Agent](https://github.com/confidential-containers/attestation-agent) supported (otherwise attestation will failed).

If you want to use Sample TEE attester in CC-KBC, set the following environment variable first:

```
export AA_SAMPLE_ATTESTER_TEST=yes
```