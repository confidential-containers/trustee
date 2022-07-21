# KBS attestation Protocol

The Key Broker Service attestation protocol defines communication between a Key Broker Client in a confidential guest 
and a trusted Key Broker Service. The protocol uses the simple, universal, and extensible 
"Request-Challenge-Attestation-Response" (RCAR) method to facilitate guest attestation and secret injection.

# Introduction

The purpose of the attestation between KBS and KBC is actually to confirm whether 
**the platform where the KBC is located is in the expected security state**, that is, it runs in 
a real and harmless HW-TEE, and the software stack is measured and verifiable.

In this document, HW-TEE attestation process is the semantics of the application 
layer, which is defined as a simple, universal and extensible 
"Request-Challenge-Attestation-Response" (RACR) protocol. The temporary asymmetric key generated 
by HW-TEE is used to encrypt the response output payload, and the token mechanism is used to avoid the 
performance problems caused by multiple attestation: it's fairly typical to request for several resources, 
and then send from the same KBC multiple Requests. Having to do the whole attestation dance would 
be time consuming and have a latency impact on the guest.

In order to ensure the ease of use and security completeness of KBS, we will use HTTPS 
as the default transmission method to carry the application layer semantics designed in this 
document. This is because HTTPS provides KBC with a means to authenticate KBS identity, which 
effectively avoids malicious attackers from hijacking KBS address to impersonate KBS and deceive KBC.
In order to achieve this, the public key of KBS needs to be transmitted to KBC through an effective way, 
and the specific way of public key distribution is not within the scope of this document.
In addition, it should be noted that the confidentiality protection provided by HTTPS alone is not enough 
to meet the security requirements of KBS protocol, therefore, as mentioned above, the key generated 
by HW-TEE needs to be used to encrypt and protect the confidential data.

# RCAR semantics

The semantics of attestation defined by KBS is a simple and extensible four-step model, 
which uses JSON structure to organize information. As follows:

1. **Request**: The KBC sends to KBS, calls the service API provided by KBS to request resources.
2. **Challenge**: After receiving the request, KBS returns a challenge to KBC and asks KBC to 
send evidence to prove that its environment (HW-TEE) is safe and reliable.
3. **Attestation**: KBC sends the evidence and the HW-TEE generated, ephemeral public key to the KBS.
4. **Response**: The `Response` payload includes the resource data requested when sending the initial `Request` to
the specific KBS resource endpoint. The resource data is protected by the ephemeral public key
passed via the previously sent Attestation payload. Within the valid time of the token, KBC can directly 
request resources or services from KBS by virtue of the token without going through step 2 and step 3.

## Request

The payload format of the request is as follows:

(Note that the `/*...*/` comments are not valid in JSON, and must not be used in real message.)

```json
{
    "request": {
        /* Attestation protocol version number used by KBC */
        "version": "0.1.0",
        /* Type of HW-TEE platforms where KBC is located, such as "tdx", "sev-snp", etc. */
        "tee": "",
        /* Access token to avoid multiple attempts triggered by consecutive requests. */
        "token": "",
        /* Reserved fields are used to support some special requests sent by HW-TEE. */
        "extra-params": {}
    }
}
```

- `protocol-version`

The protocol version number supported by KBC. KBS needs to judge whether this KBC can communicate 
normally according to this field.

- `tee`

Used to declare the type of HW-TEE platform where KBC is located, the valid values now is `tdx`, `sgx` and `sev-snp`.

- `token`

If other requests have been made before this request, in the previous response KBS would return a 
token to KBC. There are two cases for the contents of this field: 

1. A token is provided, which means a previous attestation was done. If the token is valid, 
the Challenge/Attestation part can be skipped. If it is not valid, KBS will send a Challenge.

2. Left blank, which means the KBC is implictly expecting to go through attestation 
and KBS will reply with a Challenge.

- `extra-params`

In the run-time attestation scenario (TDX, SEV-SNP, SGX), the `extra-params` are not used, so it is kept empty.
However, for the attestation of some special HW-TEE platforms, this field may be used to transfer some specific information,
for example, some attestations depend on Diffie–Hellman to build a secure channel and transfer secret messages 
(Such as the SEV(-ES) pre-attestation).

## Challenge

After KBS receives the request, if the token is found to be empty or expired, KBS will return an 
attestation challenge to KBC. The payload format is as follows:

```json
{
    "challenge": {
        /* To ensure the freshness of evidence. */
        "nonce": "",
        /* Extra parameters to support some special HW-TEE attestation. */
        "extra-params": {}
    }
}
```

- `nonce`

The fresh number passed to KBC. KBC needs to place it in the evidence sent to KBS in the next 
step to prevent replay attacks.

- `extra-params`

The reserved extra parameter field which is used to pass the additional information provided by 
the KBS when some specific HW-TEE needs to be attested.

## Attestation

After receiving the invitation challenge, KBC collects the attestation evidence from the HW-TEE 
platform and organizes it into the following payload format:

```json
{
    "evidence": {
        /* The nonce in the Challenge; its hash needs to be included in HW-TEE evidence and signed by HW-TEE hardware. */
        "nonce": "",
        /* TEE type name */
        "tee": "",
        /* The public key generated by KBC in HW-TEE, it is valid until the next time an attestation is required. Its hash needs to be included in HW-TEE evidence and signed by HW-TEE hardware. */
        "tee-pubkey": {
            "algorithm": "",
            "pubkey-length": "",
            "pubkey": ""
        },
        /* The content of evidence. Its format is specified by Attestation-Service. */
        "tee-evidence": {}
    }
}
```

- `nonce`

This is the nonce received by KBC in `Challenge` to prove the freshness of the evidence to KBS. 
KBS will match the evidence corresponding to the request through this nonce. 
In addition to providing nonce here, its hash needs to be included in HW-TEE evidence payload and signed by HW-TEE.

- `tee`

Used to declare the type of HW-TEE platform where evidence is from, the valid values now is `tdx`, `sgx` and `sev-snp`.

- `tee-pubkey`

After KBC receives the attestation challenge, an ephemeral asymmetric key pair is generated 
in HW-TEE. The private key is stored in HW-TEE. The public key and its description information 
are exported and placed in the `tee-pubkey` field and sent to KBS together with evidence. The 
hash of the `tee-pubkey` field needs to be included in the custom field of HW-TEE evidence and 
signed by HW-TEE hardware. This public key is valid until the next time KBC receives this KBS's 
attestation challenge.

- `tee-evidence`

The specific content of evidence related to the HW-TEE platform software and hardware in KBC's 
environment, different `tee-evidence` formats will be defined according to the type of TEE. This 
format is defined by the Attestation-Service. 
**KBS will not analyze the content of this structure, but will directly forward it to the Attestation-Service for verification**.

## Response

If Attestation-Service fails to verify the evidence, KBS returns error response information to 
KBC.

If KBS verified the token or the attestation evidence successfully, it will return a response to KBC in the following format:

```json
{
    "response": {
        /* The output of KBS service API, needs to be encrypted by a symmetric key randomly generated by KBS. */
        "output": "",
        /* Symmetric key and algorithm information for encrypting `output`. */
        "crypto-annotation": {
            "algorithm": "",
            /* The input to a cryptographic primitive being used to provide the initial state, if the algorithm used does not need it, this field left blank */
            "initialization-vector": "",
            /* The symmetric key used to encrypt `output`, which is encrypted by HW-TEE's public key */
            "enc-symkey": ""
        },
        /* The token issued by KBS to KBC. If there is a token in the request, this field will be left blank. */
        "token": "",
    }
}
```

- `output`

The output of KBS service API, it needs to be encrypted by a symmetric key randomly generated by KBS. 

- `crypto-annotation`

The symmetric key and algorithm used to encrypt `output`. Because the output of KBS service 
API may contain large data, it is inefficient to directly use HW-TEE's public key for encryption. 
Therefore, digital envelope technology is used here, KBS generate a random symmetric key to 
encrypt `output`, and then use HW-TEE's public key to encrypt the random symmetric key.

- `token`

If the attestation evidence sent by KBC is verified before returning the response, KBS will issue 
a token to KBC in this field and sign it with KBS's root key. KBS will maintain the corresponding 
relationship between each issued token and its original attestation result. KBC can use this token 
to request resources or services from KBS without Challenge and Attestation within the validity period of 
the token. If there is already a token in the KBC's request, no new token will be issued and this 
field will be left blank.

The [JSON web token](https://jwt.io/) standard is adopted for the token. The format is as follows:

(Note that the `/*...*/` comments are not valid in JSON web token, and must not be used in real token.)

```json
{
    /* JWT header */
    "alg": "HS256",
    "typ": "JWT"
}.
{
    /* JWT Payload official claim set */
  
    /* Token's expiration time */
    "exp": 1568187398,
    /* Token's issuing time */
    "iat": 1568158598,
    /* Token's issuer, which is the URL address of KBS */
    "iss": "https://xxxxxx",
    
    /* JWT payload custom claim set */
  
    /* The HW-TEE's public key sent by KBC in the attestation evidence, which is valid within the validity period of the token. */
    "tee-pubkey": {
        "algo": "",
        "pubkey-length": "",
        "pubkey": ""
    }
}.
[Signature]
```

The header part of the token declares the format standard of the token and the signature algorithm used.

The payload part is divided into official claim set and custom claim set. In the official claim 
set, we select three fields, `exp`, `iat`' and `iss`, which respectively declare the expiration 
time, issuing time and issuer (KBS URL address) of the token. The custom field in the payload 
contains the HW-TEE's public key sent by KBC along with the attestation evidence, which is valid 
within the validity period of the token. When KBC uses the token to request resources or services 
of KBS service API, KBS uses this public key recorded in the token to encrypt the symmetric key used to 
encrypt the `output`.

At the end of the token, KBS signs the header and payload with its root key to confirm that the 
token is indeed issued by KBS itself.

Within the validity period of the token, KBC can provide the token encoded by Base64 as the 
content of the `token` field in the request to KBS, so as to quickly obtain the required 
resources or service result.

# Error information

In addition to using the standard HTTPS status code to represent the returned error type, 
it is also necessary to provide a detailed description of the attestation error. 
We define the error return payload as follows:

```json
{
    "error": {
        "info": ""
    }
}
```

# Integration

KBS uses HTTPS protocol for request and response by default. 
The above "RCAR" attestation message can be passed as the payload of HTTPS request and response. 
The following examples illustrate the integration of "RCAR" semantics with HTTPS request and response:

For example, KBC needs to request a key, and the URL is `/kbs/key/key_id`, the steps are as follows:

1. KBC sends `GET /kbs/key/key_id` request. The request payload is the `Request` message in the "RCAR" semantics.
2. If no token is provided in the request payload or the token is invalid, KBS returns `HTTP/1.1 200 OK` response to KBC, 
but the payload of the response is the `Challenge` message in the "RCAR" semantics. 
If a valid token is provided in the request payload, KBS directly jumps to step 4.
3. KBC sends `GET /kbs/key/key_id` request to KBS again, but the payload of this request is the `Attestation` message in the "RCAR" semantics.
4. KBS returns an `HTTP/1.1 200 OK` response to KBC and the payload is the `Response` message in the "RCAR" semantics.


