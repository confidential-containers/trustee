# Restful Attestation Service

`restful-as` is an Attestation Service application based on RESTful.

## Usage

Here are the steps of building and running RESTful Attestation Service:

### Build

Build and install binary
```shell
git clone https://github.com/confidential-containers/trustee
cd trustee/attestation-service
WORKDIR=$(pwd)
make && make install
```

Build and run container image
```shell
git clone https://github.com/confidential-containers/trustee
cd trustee
docker build -t coco-as:restful -f attestation-service/Dockerfile.as-restful .
```

### Run

- For help information, run:
```shell
restful-as --help
```

- For version information, run:
```shell
restful-as --version
```

Start Attestation Service and specify the listen port of its web service:
```shell
restful-as --socket 127.0.0.1:8080
```

If you want to see the runtime log, run:
```shell
RUST_LOG=debug restful-as --socket 127.0.0.1:8080 -c config.json
```

#### HTTPS support

Generate self-signed cert (Optional)

```shell
# Generate a RSA private key
openssl genrsa -out private_key.key 2048

# Generate the public key cert
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout private_key.key -out certificate.crt
```

Launch the HTTPS CoCo-AS Server
```shell
RUST_LOG=debug restful-as \
    --socket 127.0.0.1:8080 \
    -c config.json \
    --https-pubkey-cert certificate.crt \
    --https-prikey private_key.key
```

### API

RESTful CoCo-AS's endpoints are as following:
- `/attestation`: receives evidence verification request. The request POST payload is like
```json
{
    "tee": "sgx", // tee type.
    "evidence": "YWFhCg==...", // base64 encoded evidence in URL SAFE NO PAD,
    "runtime_data": {           // `runtime_data` is optional. If given, the runtime data binding will
                                // be checked.
                                // The field `raw` and `structured` are exclusive.
        "raw": "YWFhCg==...",   // Base64 encoded runtime data slice. The whole string will be base64
                                // decoded. The result one will then be accumulated into a digest which
                                // is used as the expected runtime data to check against the one inside
                                // evidence.
                                //
                                // The alphabet is URL_SAFE_NO_PAD.
                                // defined in https://datatracker.ietf.org/doc/html/rfc4648#section-5
                                
        "structured": {}        // Runtime data in a JSON map. CoCoAS will rearrange each layer of the
                                // data JSON object in dictionary order by key, then serialize and output
                                // it into a compact string, and perform hash calculation on the whole
                                // to check against the one inside evidence. The hash algorithm is defined
                                // by `runtime_data_hash_algorithm`.
                                //
                                // After the verification, the structured runtime data field will be included
                                // inside the token claims.
    }, 
    "init_data": {              // `init_data` is optional. If given, the init data binding will
                                // be checked.
                                // The field `raw` and `structured` are exclusive.
        "raw": "YWFhCg==...",   // Base64 encoded init data slice. The whole string will be base64
                                // decoded. The result one will then be accumulated into a digest which
                                // is used as the expected init data to check against the one inside
                                // evidence. The hash algorithm is defined by `init_data_hash_algorithm`.
                                //
                                // The alphabet is URL_SAFE_NO_PAD.
                                // defined in https://datatracker.ietf.org/doc/html/rfc4648#section-5
                                
        "structured": {}        // Init data in a JSON map. CoCoAS will rearrange each layer of the
                                // data JSON object in dictionary order by key, then serialize and output
                                // it into a compact string, and perform hash calculation on the whole
                                // to check against the one inside evidence.
                                //
                                // After the verification, the structured init data field will be included
                                // inside the token claims.
    }, 
    "runtime_data_hash_algorithm": "sha384",// Hash algorithm used to calculate runtime data. Currently can be 
                                            // "sha256", "sha384" or "sha512". If not specified, "sha384" will be selected.
    "init_data_hash_algorithm": "sha384",   // Hash algorithm used to calculate init data. Currently can be 
                                            // "sha256", "sha384" or "sha512". If not specified, "sha384" will be selected.
    "policy_ids": ["default", "policy-1"]           // List of IDs of the policy used to check evidence. If
                                                    // not provided, a "default" one will be used.
}
```
- `/policy`: receives policy setting request. The request POST payload is like
```json
{
    "type": "rego",         // policy type
    "policy_id": "yyyyy",   // raw string of policy id
    "policy": "xxxxx"       // base64 encoded policy content
}
```

#### Supported Tees

Restful CoCoAS can specify the evidence type in `tee` field. Now the following types are supported:
- `azsnpvtpm`: Azure SNP vTPM
- `sev`: AMD SEV (Not implemented)
- `sgx`: Intel SGX
- `snp`: AMD SNP
- `tdx`: Intel TDX
- `cca`: Arm CCA
- `sample`: A fake platform. Only for test and sample
- `csv`: Hygon CSV
- `aztdxvtpm`: Azure TDX vTPM (Not implemented)

### Test

For example, we can use an SGX evidence to test CoCo-AS (RESTful)

```shell
cd $WORKDIR

curl -k -X POST http://127.0.0.1:8080/attestation \
     -i \
     -H 'Content-Type: application/json' \
     -d @tests/coco-as/restful-request.json
```

Then, a token will be retrieved as HTTP response body like
```plaintext
eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJjdXN0b21pemVkX2NsYWltcyI6eyJ0ZXN0X2tleSI6InRlc3RfdmFsdWUifSwiZXZhbHVhdGlvbi1yZXBvcnRzIjpbeyJldmFsdWF0aW9uLXJlc3VsdCI6IntcImFsbG93XCI6dHJ1ZX0iLCJwb2xpY3ktaGFzaCI6ImMwZTc5Mjk2NzFmYjY3ODAzODdmNTQ3NjBkODRkNjVkMmNlOTYwOTNkZmIzM2VmZGEyMWY1ZWIwNWFmY2RhNzdiYmE0NDRjMDJjZDE3N2IyM2E1ZDM1MDcxNjcyNjE1NyIsInBvbGljeS1pZCI6ImRlZmF1bHQifV0sImV4cCI6MTcwMTY3Mjk2NSwiaXNzIjoiQ29Dby1BdHRlc3RhdGlvbi1TZXJ2aWNlIiwiandrIjp7ImFsZyI6IlJTMzg0IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiMGhGUHdHNmdTSmJKV1NaTFR6SzRfVThHSWo5WVdYc3FZbDFjbUhveHlhQ05oQ3JCYVVUcW5KdHlPRVpMLVBDcWJBS2VXNGFCWnY1M3Zycm13OU41S2lHMHNOTVJOMUc1V2V2RTFNSEEzQU1qNlNlSWtwT1hzT01DNzJBNUZrZFIzRG1hM3dMaW5tZUVHYk9xZE5rN2IzMHdtWkRhVG13QTJJSjdnNVhPZk8zNTl6YWFLaDFRZDdPUXRkT2RfaV8tQlEzQlpEYnZ4R1ctWmRsdHVwWXBjRVQwWUZLSlE1NTdPSGtsOGMxT3BVdFc5ODlEQjM3d1BGTlRxM25oU3ZveDBwYWdDd3FwZ3JCYXVVUDBlOGlkX1VhSGFVZWlPd2tXc2UxdkdYQW55cFZqUlhhdERhS2dzbzZ5QjdGQ3pMUmRwM3JzWW1kd1lMaTdtMms3TkNPaE9RIn0sIm5iZiI6MTcwMTY3MjY2NSwidGNiLXN0YXR1cyI6eyJzZ3guYm9keS5hdHRyaWJ1dGVzLmZsYWdzIjoiMDcwMDAwMDAwMDAwMDAwMCIsInNneC5ib2R5LmF0dHJpYnV0ZXMueGZybSI6ImU3MDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5jb25maWdfaWQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneC5ib2R5LmNvbmZpZ19zdm4iOiIwMDAwIiwic2d4LmJvZHkuY3B1X3N2biI6IjA2MDYwYzBjZmZmZjAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2d4LmJvZHkuaXN2X2V4dF9wcm9kX2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5pc3ZfZmFtaWx5X2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5pc3ZfcHJvZF9pZCI6IjAwMDAiLCJzZ3guYm9keS5pc3Zfc3ZuIjoiMDAwMCIsInNneC5ib2R5Lm1pc2Nfc2VsZWN0IjoiMDEwMDAwMDAiLCJzZ3guYm9keS5tcl9lbmNsYXZlIjoiOGYxNzNlNDYxM2ZmMDVjNTJhYWYwNDE2MmQyMzRlZGFlOGM5OTc3ZWFlNDdlYjIyOTlhZTE2YTU1MzAxMWM2OCIsInNneC5ib2R5Lm1yX3NpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQzMDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzZ3guYm9keS5yZXBvcnRfZGF0YSI6Ijc0NjU3Mzc0MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2d4LmJvZHkucmVzZXJ2ZWQxIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic2d4LmJvZHkucmVzZXJ2ZWQyIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneC5ib2R5LnJlc2VydmVkMyI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guYm9keS5yZXNlcnZlZDQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzZ3guaGVhZGVyLmF0dF9rZXlfZGF0YV8wIjoiMDAwMDAwMDAiLCJzZ3guaGVhZGVyLmF0dF9rZXlfdHlwZSI6IjAyMDAiLCJzZ3guaGVhZGVyLnBjZV9zdm4iOiIwZDAwIiwic2d4LmhlYWRlci5xZV9zdm4iOiIwODAwIiwic2d4LmhlYWRlci51c2VyX2RhdGEiOiJkY2NkZTliMzFjZTg4NjA1NDgxNzNiYjRhMmE1N2ExNjAwMDAwMDAwIiwic2d4LmhlYWRlci52ZW5kb3JfaWQiOiI5MzlhNzIzM2Y3OWM0Y2E5OTQwYTBkYjM5NTdmMDYwNyIsInNneC5oZWFkZXIudmVyc2lvbiI6IjAzMDAifX0.SG7TUxm0E3yZs7rozijScMJIZTY8WVPZN3Yxu2CsW8HFE6lDLymdTzc1XTVrYb97PpGc6oCLwuLax786XHLN250SY_IW5GmR5WKRcYSGSQtOnYfsY7AMX3hvpV3rHGjP0QWZo_ezUp9yIbnJNwSprmFTzcNZkr2YNr1KmwWU-LhGSVCyviQwgtnqnhmQGwH-nHCcmgk0F3su_hdoFXImCggSHStXECAJ0cNjpAuTCsSQvrB4g3lM-dMii-D6a58uB_TGuOVf8Yqj9Gi6PrdxvIJZc1LSDDgo9uYuavNzunU3S3TkA2ZLDK4HIB0zDWfOnS2ZTrjyRdu5ZkzoGVK_YQ
```

The value is a base64 encoded JWT. The body of the JWT is showed in the [example.token.json](./example.token.json).