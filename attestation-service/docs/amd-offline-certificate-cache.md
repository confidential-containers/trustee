# Offline AMD VCEK Caching Guide

This document describes the process to pre-load VCEKs (Versioned Chip
Endorsement Keys) into the trustee environment to allow normal attestation
without connection to the AMD KDS. This guide mainly targets air-gapped
environments.

> [!Note]
> Currently this guide shows a method that builds on using
> [docker](https://confidentialcontainers.org/docs/attestation/installation/docker/)
> to manage kbs services. Additional deployment methods will be covered in future releases.

## Enabling Offline VCEK Store in Attestation Service

### 1. Set VCEK Sources Configuration Option

Update the attestation configuration file to use a predefined vcek store:

`kbs/config/as-config.json`:

```json
{
    // ... other fields ...
    "verifier_config": {
        "snp_verifier": {
          // Configure VCEK sources to try, in order. Defaults to [KDS].
            "vcek_sources": [
                {
                  "type": "OfflineStore",
                },
                // Optionally add a fallback to KDS. Leave out if KDS will not
                // be reachable.
                //{
                //  "type": "KDS",
                //}
            ]
        }
    }
}
```

With the `OfflineStore` configuration specified, Trustee will inspect the
configured directory for VCEK values following the following format:

```
/opt/confidential-containers/attestation-service/kds-store/vcek/{hwid}/vcek.der
```

Where `{hwid}` is the hardware ID of the AMD EPYC server in lowercase hexadecimal.

### 2. Create and Populate VCEK directory

Create a `vcek` directory populated with the following structure:

```
vcek/
├── <Hex hardware ID>/ (ID must be lowercase)
│   └── vcek.der (cert pre-downloaded from kdsintf.amd.com)
├── <Hex hardware ID>/
│   └── vcek.der
├── <Hex hardware ID>/
    └── vcek.der
```

Trustee requires one unique certificate per physical AMD EPYC server that the
KBS will be servicing. The server's hardware ID and certificate's URL can be
fetched using the [snphost tool](https://github.com/virtee/snphost).

On each AMD SNP host, with root/admin access run:
```
sudo snphost show vcek-url
```

You should get a URL of the form:
```
https://kdsintf.amd.com/vcek/{version}/{machine}/{product_name}/{hwid}?{params}
```

You may download it from a browser by pasting that URL, or you can run
the following command on any server with network access to AMD's KDS.
```
sudo snphost fetch vcek der .
```

> [!IMPORTANT]
> - Note that the VCEK URL is specific to the hardware AMD firmware of the
> machine. If the firmware is updated, the VCEK URL will change. See the
> [AMD VCEK documentation](https://docs.amd.com/api/khub/documents/dWGhwYpo1Wv51rJN4d~47g/content)
> for more information about the VCEK URL format.

### 3. Install `vcek` directory into trustee deployment

- **Install in running trustee deployment**

Use docker commands to copy your `vcek` folder into the configured directory:
```
sudo docker exec -it trustee-as-1 mkdir -p /opt/confidential-containers/attestation-service/kds-store/
sudo docker cp ./vcek/ trustee-as-1:/opt/confidential-containers/attestation-service/kds-store/vcek/
```

- **Mount shared directory**

You may also mount a shared directory from the host into the container by
updating `docker-compose.yml` with a specified directory mapping:

```yaml
  as:
    ... <existing configuration>
    volumes:
    ... <existing volumes>
    - ./vcek:/opt/confidential-containers/attestation-service/kds-store/vcek:rw
```

### Example:

For some number of AMD EPYC servers you wish for trustee to service:
```
ssh privileged-user@epyc-host "sudo snphost show vcek-url" >> urls.txt
```

On a system with network access to AMD KDS:
```bash

# Create the vcek folder that will be copied to trustee
mkdir vcek

# Fetch certificates using the above URLs file
# There should be one line for each EPYC host that kds will service
cat urls.txt | while read line; do
  hwid="$(echo "$line" | cut -d/ -f7 | cut -d'?' -f1 | tr '[:upper:]' '[:lower:]')"
  mkdir vcek/$hwid
  cd vcek/$hwid
  sudo snphost fetch vcek der .
  cd ../..
done

# Copy the archive to your air-gapped trustee attestation-service deployment
scp -r vcek user@target-host:/path/to/trustee
```

On the air-gapped trustee attestation-service host:
```bash
# Update as-config.json to enable Disk Caching
cd /path/to/trustee
vi kbs/config/as-config.json
# Update the verifier_config section to:
#     "verifier_config": {
#        "snp_verifier": {
#            "vcek_sources": [
#              {
#                "type": "OfflineStore",
#              }
#            ]
#        }
#    }

# Start trustee
docker compose up -d

# Copy the vcek store into the running attestation service container
sudo docker exec -it trustee-as-1 mkdir -p /opt/confidential-containers/attestation-service/kds-store/
sudo docker cp ./vcek/ trustee-as-1:/opt/confidential-containers/attestation-service/kds-store/vcek/

# Alternative to docker copy would be to add the following shared mount to
# docker-compose.yml under as.volumes section:
# - ./vcek:/opt/confidential-containers/attestation-service/kds-store/vcek:rw
```

## Limitations

VCEK stores must be updated/rebuilt in the following events:
- AMD EPYC host added to serviced cluster
- AMD EPYC host firmware components updated
- VCEK certificate revoked by CA

## Troubleshooting

Enable debug and check logs for `vcek` keyword. Ensure configured sources match
expected values.

```
echo "RUST_LOG=debug" > debug.env
docker compose --env-file debug.env up -d
docker logs trustee-as-1 | grep -i vcek
```
