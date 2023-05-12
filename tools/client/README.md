# KBS Client Tool

This is a simple KBS Client cmdline tool for test.

## Usage

For help:

```shell
./client -h
```

If you want use this client to test KBS APIs that need attestation, make sure this client runs
inside an [Attestation Agent](https://github.com/confidential-containers/attestation-agent)
supported TEE, otherwise attestation will fail.

If you want to use Sample TEE attester in CC-KBC, set the following environment variable first:

```
export AA_SAMPLE_ATTESTER_TEST=yes
```
