# Deployment of KBS with IBM SE verifier

This is a document to guide developer run a KBS with IBM SE verifier locally for development purpose.

## Generate RSA keys
Generate RSA 4096 key pair following commands:
```
openssl genrsa -aes256 -passout pass:test1234 -out encrypt_key-psw.pem 4096
openssl rsa -in encrypt_key-psw.pem -passin pass:test1234 -pubout -out encrypt_key.pub
openssl rsa -in encrypt_key-psw.pem -out encrypt_key.pem
```


## Download Certs, CRLs, Root CA
Donwload these materials from: https://www.ibm.com/support/resourcelink/api/content/public/secure-execution-gen2.html
Which includes:

### Certs
ibm-z-host-key-signing-gen2.crt

### CRL
ibm-z-host-key-gen2.crl

### Root CA
DigiCertCA.crt 

## Download HKD
Download IBM Secure Execution Host Key Document following: https://www.ibm.com/docs/en/linux-on-z?topic=execution-verify-host-key-document

## Get SE Header
Build `se.img` following [Generate an IBM Secure Execution image](https://www.ibm.com/docs/en/linux-on-systems?topic=commands-genprotimg) and retrieve the hdr.bin via command like below.
```
./pvextract-hdr -o hdr.bin se.img
```

Refer [ibm-s390-linux](https://github.com/ibm-s390-linux/s390-tools/blob/v2.33.1/rust/pvattest/tools/pvextract-hdr) to get `pvextract-hdr`.

## Generate KBS key
Generate keys used by KBS service.
```
openssl genpkey -algorithm ed25519 > kbs.key
openssl pkey -in kbs.key -pubout -out kbs.pem
```

## Build KBS
```
cargo install --locked --path kbs/src/kbs --no-default-features --features coco-as-builtin,openssl,resource,opa 
```

## (Option 1) Launch KBS as a program

- Prepare the material retrieved above, similar as:
```
/run/confidential-containers/ibmse#
.
├── DigiCertCA.crt
├── certs
│   └── ibm-z-host-key-signing-gen2.crt
├── crls
│   └── ibm-z-host-key-gen2.crl
├── hdr
│   └── hdr.bin
├── hkds
│   └── HKD-3931-0275D38.crt
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
```
export RUST_LOG=debug
export SE_SKIP_CERTS_VERIFICATION=true
./kbs --config-file ./kbs-config.toml
```

> Note: `SE_SKIP_CERTS_VERIFICATION=true` only required for a development machine.

## (Option 2) Launch KBS via docker-compose
- Build the docker image
```
DOCKER_BUILDKIT=1 docker build -t ghcr.io/confidential-containers/staged-images/kbs:latest --build-arg KBS_FEATURES=coco-as-builtin,openssl,resource,opa . -f kbs/docker/Dockerfile
```

- Prepare a docker compose file, similar as:
```
services:
  web:
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
      - ./data/DigiCertCA.crt:/run/confidential-containers/ibmse/DigiCertCA.crt
      - ./data/crls:/run/confidential-containers/ibmse/crls
      - ./data/hdr.bin:/run/confidential-containers/ibmse/hdr/hdr.bin
      - ./data/rsa/encrypt_key.pem:/run/confidential-containers/ibmse/rsa/encrypt_key.pem
      - ./data/rsa/encrypt_key.pub:/run/confidential-containers/ibmse/rsa/encrypt_key.pub
```
> Note: `SE_SKIP_CERTS_VERIFICATION=true` only required for a development machine.

- Prepare the material, similar as:
```
.
├── data
│   ├── DigiCertCA.crt
│   ├── attestation-service
│   │   ├── opa
│   │   │   └── default.rego
│   ├── certs
│   │   └── ibm-z-host-key-signing-gen2.crt
│   ├── crls
│   │   └── ibm-z-host-key-gen2.crl
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
```
docker-compose up -d
docker-compose logs web
docker-compose down
```


