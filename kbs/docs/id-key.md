# ID-key Plugin

In addition to fetchable resources upon successful attestation, KBS also offers the ID-key plugin for encrypting and decrypting data with a key provisioned by the KBS. This key can be persisted across multiple reboots of CVMs and help tie decryption resources to a specific KBS instance.

## Data Encryption

As a guest owner would be responsible for encrypting persistent storage, they are the sole authority that is permitted to request resources be encrypted. The KBS is expected to be fully in control by the guest owner with credentials configured.

## Flow

### Provisioning encrypted data

A credentialed guest owner is the only one authorized to request that keys be encrypted by the ID-key plugin. To do this, the guest owner will POST some plaintext data (created locally) to be encrypted. This plaintext data could be a LUKS passphrase, SecureBoot keys, etc. The actual purpose of the data is of no concern to the KBS.

`POST /kbs/v0/id-key/{base64-plaintext-data}`


```
          ┌───────────┐        
          │   POST    │        
Owner ──► ├───────────┤ ──► KBS
  ▲       │ Plaintext │        
  │       │ data      │      │ 
  │       └───────────┘      │ 
  │                          │ 
  │                          │ 
  │       ┌───────────┐      │ 
  └────── │ Encrypted │ ◄────┘ 
          │ data      │        
          └───────────┘        
```

With this, the guest owner is now free to configure persistent storage as they wish for their CVMs to have access to encrypted data when they boot. Upon successful attestation, this encrypted data will be presented to the KBS by the CVM for decryption.

### Post-attestation, decrypting data

With a CVM booted and attested, it is now assumed that the CVM was configured in such a way that it has access to readable storage that contains the encrypted data. The CVM can now send this data to the KBS for decryption.

To prevent replay attacks, the CVM must wrap the encrypted data in a ECDH key cipher. To support this, the ID-key plugin presents an endpoint `ecdh-pub-sec1` that a VM can use to fetch the EC public key in order to wrap the encrypted data.

`GET /kbs/v0/id-key/ecdh-pub-sec1`

```
          ┌────────┐
          │  GET   │
          ┤        │
Client ──►│ EC     │ ──► KBS
          │ public │
  ▲       │ key    │      │
  │       └────────┘      │
  │                       │
  │                       │
  │  ┌─────────────────┐  │
  │  │       EC        │  │
  └──┤     public      │◄─┘
     │       key       │
     │  (sec1 encoded) │
     └─────────────────┘
```

With the KBS's public EC key, the CVM can create its own ephemeral EC key and wrap the encrypted data with an ECDH/SHA256/AES256GCM cipher.

The CVM will then present the ECDH-wrapped encrypted data along with all data needed for unwrapping (client EC public key and AESGCM iv). The KBS will use this data to unwrap the encrypted data and decrypt it.

`GET /kbs/v0/id-key/{base64-wrapped-encrypted-data}?ecdh-pubkey={base64-client-ecdh-pubkey-sec1}&iv={base64-aesgcm-iv}`

```                                            
              ┌───────────────┐             
              │      GET      │             
              ├───────────────┤             
    Client ──►│   Encrypted   │ ──► KBS     
              │   Data        │             
      ▲       │ (ECDH wrapped)│      │      
      │       └───────────────┘      │      
      │                              │      
      │      ┌─────────────────┐     │      
      │      │   Decrypted     │     │      
      └───── │   Data          │ ◄───┘      
             │  (TEE public    │            
             │   key wrapped)  │            
             └─────────────────┘            
```

As the decrypted secret is sensitive and will be passing through an untrusted host network, the secret must be wrapped by some data only known to the CVM. The KBS re-uses the TEE public key presented at attestation for this purpose. In this sense, a client reading the decrypted secret from the KBS is much like reading a resource from the KBS. A KBS `Response` wrapping the secret in the TEE public key will be returned to the CVM. The CVM will use the `Response` to unwrap the secret.
