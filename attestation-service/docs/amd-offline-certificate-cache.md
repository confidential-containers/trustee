# Offline AMD VCEK Store Guide

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

`kbs/config/docker-compose/as-config.json`:

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
configured directory for VCEK values.

Given an attestation report, trustee will search first:
```
# Preferred (TCB-based filename, when present):
/opt/confidential-containers/attestation-service/kds-store/vcek/{hwid}/{tcb_prefix}_vcek.der
```

And if that lookup fails, the legacy flat format will be searched:
```
# Fallback (legacy flat layout):
/opt/confidential-containers/attestation-service/kds-store/vcek/{hwid}/vcek.der
```

Where:
- `{hwid}` is the hardware ID of the AMD EPYC server in lowercase hexadecimal
- `{tcb_prefix}` is a TCB-parameter-based filename prefix in the format:
  - For non-Turin processors: `bl{BL}_tee{TEE}_snp{SNP}_ucode{UCODE}`
  - For Turin processors: the above with `_fmc{FMC}` appended

  Each parameter is zero-padded to 2 digits (e.g., `bl02_tee00_snp06_ucode21`)

### 2. Create and Populate VCEK directory

Create a `vcek` directory populated with one of the following structures per
hardware ID. The TCB-prefixed filename is recommended, to allow loading multiple VCEKs per host.

```
vcek/
├── <Hex hardware ID>/ (ID must be lowercase)
│   ├── vcek.der                          # flat layout (fallback)
│   └── <TCB prefix>_vcek.der             # optional, preferred when present
├── <Hex hardware ID>/
│   └── vcek.der
└── <Hex hardware ID>/
    └── <TCB prefix>_vcek.der
```

The `<TCB prefix>` is derived from the certificate's TCB parameters and follows
the format `bl{BL}_tee{TEE}_snp{SNP}_ucode{UCODE}` (with `_fmc{FMC}` appended for Turin
processors). For example: `bl02_tee00_snp06_ucode21_vcek.der`

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
the following command on the SNP host itself (it derives the URL from the
local firmware). Requires network access to AMD's KDS.
```
sudo snphost fetch vek der .
```

To fetch from a different machine (e.g. a build box), pass the URL explicitly
so the cert matches the originating host's firmware rather than the local one:
```
sudo snphost fetch vek der . "<vcek-url>"
```

> [!Note]
> Older versions of `snphost` use `snphost fetch vcek` instead of `vek`. However it's recommended to update to the latest version of `snphost`.

> [!IMPORTANT]
> - Note that the VCEK URL is specific to the hardware AMD firmware of the
> machine. If the firmware is updated, the VCEK URL will change. See the
> [AMD VCEK documentation](https://docs.amd.com/api/khub/documents/dWGhwYpo1Wv51rJN4d~47g/content)
> for more information about the VCEK URL format.

### 3. Install `vcek` directory into trustee deployment

- **Install in running trustee deployment**

Use docker commands to copy your `vcek` folder into the configured directory:
```
sudo docker exec trustee-as-1 mkdir -p /opt/confidential-containers/attestation-service/kds-store/
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
mkdir vcek
# qval <tcb-key> <query-string>: extract the SPL value for a TCB key
qval() { grep -oP "$1SPL=\K[0-9]+" <<<"$2"; }

# url_hwid <vcek-url>: derive the lowercase hardware ID from the URL path
url_hwid() { tr '[:upper:]' '[:lower:]' <<<"${1##*/}" | cut -d'?' -f1; }

while read -r url; do
  hwid=$(url_hwid "$url")
  query="${url#*\?}"  # If no '?', yields whole URL; produces flat layout below

  tcb_prefix=""
  for key in bl tee snp ucode fmc; do
    val=$(qval "$key" "$query") || continue
    tcb_prefix+="${tcb_prefix:+_}${key}$(printf '%02d' "$((10#$val))")"
  done

  mkdir -p "vcek/$hwid"
  # snphost writes to vcek.der in the given directory; rename to the
  # TCB-prefixed filename. If no TCB params were parsed, keep the flat name.
  (
    cd "vcek/$hwid" || exit 1
    sudo snphost fetch vek der . "$url"
    [ -n "$tcb_prefix" ] && mv vcek.der "${tcb_prefix}_vcek.der"
  )
done < urls.txt

scp -r vcek user@target-host:/path/to/trustee
```

On the air-gapped trustee attestation-service host:
```bash
# Update as-config.json to enable the offline VCEK store
cd /path/to/trustee
vi kbs/config/docker-compose/as-config.json
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
sudo docker exec trustee-as-1 mkdir -p /opt/confidential-containers/attestation-service/kds-store/
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
