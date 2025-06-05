# PKCS11 plugin

PKCS11 is a broad specification supporting many cryptographic operations, mainly applicable to Hardware Security Modules (HSMs). Trustee implements a subset of features that can be of use to attested clients.

## Resource Storage

The PKCS11 plugin can store plaintext resources in an HSM. Since the KBS expects resources to be in plaintext, we store these resources in the HSM as secret keys of the generic secret type. This storage interface will provision resources to the HSM in the expected way when a user uploads a resource to the KBS. The user must simply specify the location of an initialized HSM slot. A user can fetch resources using the same semantics as a resource backend.

`GET https://<kbs_address>/kbs/v0/pkcs11/resource/<repository_name>/<type>/<tag>`

Admins can also store resources to an HSM using similar semantics as a resource backend.

`POST https://<kbs_address>/kbs/v0/pkcs11/resource/<repository_name>/<type>/<tag>`

## Key Wrapping/Unwrapping

Upon initialization of the plugin, a unique public/private keypair is generated for wrapping and unwrapping data with an HSM.

### Key wrapping
To wrap data, clients can send a POST request to

`POST https://<kbs_address>/kbs/v0/pkcs11/wrap-key`

Giving the plaintext data in the request body. The PKCS11 plugin will wrap the data with the public key and return it to client.

Key wrapping requires admin validation, as only admins should be able to wrap data for attestation clients.

### Key Unwrapping
To unwrap data, clients can send a GET request to

`GET https://<kbs_address>/kbs/v0/pkcs11/wrap-key`

Giving the wrapped data in the request body. The PKCS11 plugin will unwrap the data with the private key and return it to client.
