
# KBS with IBM SE verifier

This is a document to guide developer run a KBS with IBM SE verifier locally for development purpose.

## Index

- [Deployment of KBS with IBM SE verifier](#deployment-of-kbs-with-ibm-se-verifier)
- [Set attestation policy for IBM SE verifier](#set-attestation-policy)



# Deployment of KBS with IBM SE verifier

This section is about deployment of KBS without rvps checking.

## Generate RSA keys
Generate RSA 4096 key pair following commands:
```bash
openssl genrsa -aes256 -passout pass:test1234 -out encrypt_key-psw.pem 4096
openssl rsa -in encrypt_key-psw.pem -passin pass:test1234 -pubout -out encrypt_key.pub
openssl rsa -in encrypt_key-psw.pem -out encrypt_key.pem
```


## Download Certs, CRLs
Donwload these materials from: https://www.ibm.com/support/resourcelink/api/content/public/secure-execution-gen2.html
Which includes:

### Certs
ibm-z-host-key-signing-gen2.crt
DigiCertCA.crt 

### CRL
ibm-z-host-key-gen2.crl  
DigiCertTrustedRootG4.crl  
DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl

Note: `DigiCertTrustedRootG4.crl` and `DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl` come from commands as below:
```bash
# openssl x509 -in DigiCertCA.crt --text --noout |grep crl
                  URI:http://crl3.digicert.com/DigiCertTrustedRootG4.crl
# openssl x509 -in ibm-z-host-key-signing-gen2.crt --text --noout |grep crl
                  URI:http://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
                  URI:http://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
```

## Download HKD
Download IBM Secure Execution Host Key Document following: https://www.ibm.com/docs/en/linux-on-z?topic=execution-verify-host-key-document

## Get SE Header
Build `se.img` following [Generate an IBM Secure Execution image](https://www.ibm.com/docs/en/linux-on-systems?topic=commands-genprotimg) and retrieve the hdr.bin via command like below.
```bash
./pvextract-hdr -o hdr.bin se.img
```

Refer [ibm-s390-linux](https://github.com/ibm-s390-linux/s390-tools/blob/v2.33.1/rust/pvattest/tools/pvextract-hdr) to get `pvextract-hdr`.

## Generate KBS key
Generate keys used by KBS service.
```bash
openssl genpkey -algorithm ed25519 > kbs.key
openssl pkey -in kbs.key -pubout -out kbs.pem
```

## (Option 1) Launch KBS as a program

- Build KBS
```bash
cargo install --locked --debug --path kbs/src/kbs --no-default-features --features coco-as-builtin,openssl,resource,opa 
```

- Prepare the material retrieved above, similar as:
```
/run/confidential-containers/ibmse#
.
├── certs
│   ├── ibm-z-host-key-signing-gen2.crt
|   └── DigiCertCA.crt
├── crls
│   └── ibm-z-host-key-gen2.crl
│   └── DigiCertTrustedRootG4.crl
│   └── DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
├── hdr
│   └── hdr.bin
├── hkds
│   └── HKD-3931-0275D38.crt
└── rsa
    ├── encrypt_key.pem
    └── encrypt_key.pub
```

> Note: alternative is to use system variables listed in [ibmse.rs](./ibmse.rs) to overwrite the files.

- Prepare the `kbs-config.toml`, similar as:
```
sockets = ["0.0.0.0:8080"]
auth_public_key = "/kbs/kbs.pem"
# Ideally we should use some solution like cert-manager to issue let's encrypt based certificate:
# https://cert-manager.io/docs/configuration/acme/
insecure_http = true

[attestation_token_config]
attestation_token_type = "CoCo"

[as_config]
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"
attestation_token_broker = "Simple"

[as_config.attestation_token_config]
duration_min = 5

[as_config.rvps_config]
store_type = "LocalFs"
remote_addr = ""
```

- Launch the KBS program
```bash
export RUST_LOG=debug
export SE_SKIP_CERTS_VERIFICATION=true
./kbs --config-file ./kbs-config.toml
```

> Note: `export SE_SKIP_CERTS_VERIFICATION=true` only required for a development machine. Use `export CERTS_OFFLINE_VERIFICATION=true` to verifiy the certificates offline.

## (Option 2) Launch KBS via docker-compose
- Build the docker image
```
DOCKER_BUILDKIT=1 docker build --build-arg HTTPS_CRYPTO="openssl" --build-arg ARCH="s390x" -t ghcr.io/confidential-containers/staged-images/kbs:latest . -f kbs/docker/Dockerfile
```

- Prepare a docker compose file, similar as:
```
services:
  kbs:
    image: ghcr.io/confidential-containers/staged-images/kbs:latest
    command: [
        "/usr/local/bin/kbs",
        "--config-file",
        "/etc/kbs-config.toml",
      ]
    restart: always # keep the server running
    environment:
      - RUST_LOG=debug
      - SE_SKIP_CERTS_VERIFICATION=true
    ports:
      - "8080:8080"
    volumes:
      - ./data/kbs-storage:/opt/confidential-containers/kbs/repository:rw
      - ./data/attestation-service:/opt/confidential-containers/attestation-service:rw
      - ./kbs.pem:/kbs/kbs.pem
      - ./kbs-config.toml:/etc/kbs-config.toml
      - ./data/hkds:/run/confidential-containers/ibmse/hkds
      - ./data/certs:/run/confidential-containers/ibmse/certs
      - ./data/crls:/run/confidential-containers/ibmse/crls
      - ./data/hdr.bin:/run/confidential-containers/ibmse/hdr/hdr.bin
      - ./data/rsa/encrypt_key.pem:/run/confidential-containers/ibmse/rsa/encrypt_key.pem
      - ./data/rsa/encrypt_key.pub:/run/confidential-containers/ibmse/rsa/encrypt_key.pub
```
> Note: `export SE_SKIP_CERTS_VERIFICATION=true` only required for a development machine. Use `export CERTS_OFFLINE_VERIFICATION=true` to verifiy the certificates offline.

- Prepare the material, similar as:
```
.
├── data
│   ├── attestation-service
│   │   ├── opa
│   │   │   └── default.rego
│   ├── certs
│   │   ├── ibm-z-host-key-signing-gen2.crt
│   │   └── DigiCertCA.crt
│   ├── crls
│   │   └── ibm-z-host-key-gen2.crl
│   │   └── DigiCertTrustedRootG4.crl
│   │   └── DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl
│   ├── hdr.bin
│   ├── hkds
│   │   └── HKD-3931-0275D38.crt
│   ├── kbs-storage
│   │   ├── default
│   │   └── one
│   │       └── two
│   │           └── key
│   └── rsa
│       ├── encrypt_key.pem
│       └── encrypt_key.pub
├── docker-compose.yaml
├── kbs-config.toml
├── kbs.key
└── kbs.pem
```

- Launch KBS as docker compose application
```bash
docker-compose up -d
docker-compose logs kbs
docker-compose down
```


# Set attestation policy

This section is about setting attestation policy.

### Retrive the attestation policy fields for IBM SE

Using [se_parse_hdr.py](se_parse_hdr.py) on a s390x instance to retrieve the IBM SE fields for attestation policy.

```bash
python3 se_parse_hdr.py hdr.bin HKD-3931.crt 

...
  ================================================ 
  se.image_phkh: xxx
  se.version: 256
  se.tag: xxx
  se.attestation_phkh: xxx
```

We get following fields and will set these fields in rvps for attestation policy. 
`se.version: 256`  
`se.tag: xxx`  
`se.attestation_phkh: xxx`  
`se.image_phkh: xxx`  


### Set attestation policy

#### Generate attestation policy file
```bash
cat << EOF > ibmse-policy.rego
package policy
import rego.v1
default allow = false

converted_version := sprintf("%v", [input["se.version"]])

allow if {
    input["se.attestation_phkh"] == "xxx"
    input["se.image_phkh"] == "xxx"
    input["se.tag"] == "xxx"
    input["se.user_data"] == "xxx"
    converted_version == "256"
}
EOF
```

Where the values `se.version`, `se.attestation_phkh`, `se.image_phkh` and `se.tag` come from [retrive-the-rvps-field-for-an-ibm-se-image](#retrive-the-rvps-field-for-an-ibm-se-image). The value `se.user_data` comes from [initdata](https://github.com/confidential-containers/cloud-api-adaptor/blob/main/src/cloud-api-adaptor/docs/initdata.md). Please remove `input["se.user_data"] == "xxx"` if `initdata` is not used.

#### Set the attestation policy
```bash
kbs-client --url http://127.0.0.1:8080 config --auth-private-key ./kbs/kbs.key set-attestation-policy --policy-file ./ibmse-policy.rego
```