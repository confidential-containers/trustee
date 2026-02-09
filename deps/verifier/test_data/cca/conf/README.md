# CCA Verifier

| Property | Type | Description | Required | Default |
|----|----|----|----|----|
| `type` | `remote` or `local` | Type of CCA verifier | True | none |

* `local` : Use the local verifier
* `remote` : Use a remote verifier

## Local Verifier

When `type` is `local`, acceptable CCA platforms' reference values and trust anchors are configured via two JSON files using [ccatoken’s store](https://github.com/veraison/rust-ccatoken/blob/main/src/store/data-model.cddl) format.

| Property | Type | Description | Required | Default |
|----|----|----|----|----|
| `ta-store` | Path | Location of the CCA trust anchor store | True | none |
| `rv-store` | Path | Location of the CCA reference values store | True | none |

Example

~~~json
{
    "cca-verifier": {
        "type": "local",
        "ta-store": "/etc/trustee/as/cca/ta-store.json",
        "rv-store": "/etc/trustee/as/cca/rv-store.json"
    }
}
~~~

## Remote Verifier

When `type` is `remote`, the verifier location and (optional) trust anchor are supplied using the following properties:

| Property | Type | Description | Required | Default |
|----|----|----|----|----|
| `address` | URI | URI of the verifier | True | none |
| `ca-cert` | Path | Location of the (custom) root CA certificate | False | none |

The verifier must implement Veraison's ["challenge-response"](https://github.com/veraison/docs/tree/main/api/challenge-response) and ["well-known"](https://github.com/veraison/docs/tree/main/api/well-known) APIs.

~~~json
{
    "cca-verifier": {
        "type": "remote",
        "address": "https://veraison.test.linaro.org:8443"
    }
}
~~~

Example deployment that uses a custom Veraison verifier with a custom root CA:

~~~json
{
    "cca-verifier": {
        "type": "remote",
        "address": "https://localhost:8443",
        "ca-cert": "/etc/trustee/as/cca/rootCA.pem"
    }
}
~~~
