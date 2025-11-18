# Offline AMD VCEK Caching Guide

This document describes the process to pre-load VCEKs (Versioned Chip
Endorsement Keys) into the trustee environment to allow normal attestation
without connection to the AMD KDS. Trustee supports certificate caching through
the rust `http_cache_reqwest` crate, which caches URL responses into a
specified folder that can be preloaded with certificates using the
[cache-preloader](../../tools/cache-preloader) tool. This use case is primarily
targeted at air-gapped environments as a stopgap solution while a more
comprehensive approach is developed.

> [!Note]
> Currently this guide shows a method that builds on using
> [docker](https://confidentialcontainers.org/docs/attestation/installation/docker/)
> to manage kbs services. Information about enabling it with the
> [Trustee Operator](https://confidentialcontainers.org/docs/attestation/installation/kubernetes/)
> will be added in the near future.

## Contents

- [Prerequisites](#prerequisites)
- [Method for Cache Population](#method-for-cache-population)
- [Understanding the Cache Structure](#understanding-the-cache-structure)
- [Limitations](#limitations)

## Prerequisites

- On system used to build cache:
  - Network access to AMD KDS (https://kdsintf.amd.com)
  - Rust toolchain installed (for building cache-preloader)
- On AMD EPYC host(s) with guests to be attested:
  - snphost tool ([link](https://github.com/virtee/snphost))

## Method for Cache Population

### 1. Create URL target file

Create a text file with the list of URLs that you would like cached. The KDS
will need a VCEK URL for each physical AMD EPYC server that the KDS will be
servicing. The machine's VCEK URL can be fetched using the
[snphost tool](https://github.com/virtee/snphost).

On each AMD SNP host, with root/admin access run:

```
snphost show vcek-url
```

You should get a URL of the form:

```
https://kdsintf.amd.com/vcek/{version}/{machine}/{product_name}/{hwid}?{params}
```

See the [AMD VCEK documentation](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf)
for more information about the VCEK URL format.

> [!IMPORTANT]
> Note that the VCEK URL is specific to the hardware AMD firmware of the
> machine. If the firmware is updated, the VCEK URL will change.

### 2. Run cache_preloader to generate cache contents

On a system with access to the AMD KDS, run `cache_preloader` specifying
the VCEK URL file and output directory.

```
# Navigate to the cache-preloader directory
cd tools/cache-preloader

# Preload the cache and create an archive
cargo run -- -u vcek_urls.txt -c ./vcek_cache -a vcek_cache.tar.gz
```

### 3. Configure the attestation service

Update the attestation config file to use a predefined cache:

`kbs/config/as-config.json`:

```json
{
    // ... other fields ...
    "verifier_config": {
        "snp_verifier": {
            "cache": {
                "type": "HttpCacheReqwest",
                "offline_mode": true,
                "cache_dir": "/path/to/cache"
            }
        }
    }
}
```

### 4. Install cache contents on air-gapped attestation deployment

Copy output directory contents to your air-gapped attestation deployment
maintaining the same directory structure.

### Docker:

- **Install on running attestation service**

You may copy the cache to the container after it has started - ensure that
the as-config.json has picked up your expected cache directory:
```bash
$ docker logs trustee-as-1 | grep cache_dir
                            cache_dir: "/vcek_cache",
```

Then copy your archive (making sure to add the ending `/` in both paths):
```
docker cp ./tools/cache-preloader/vcek_cache/ trustee-as-1:/vcek_cache/
```

- **Mount shared directory**

You may also mount a shared directory from the host into the container by
updating `docker-compose.yml` with a specified directory mapping:

```yaml
  as:
    ... <existing configuration>
    volumes:
    ... <existing volumes>
    - ./tools/cache-preloader/vcek_cache:/vcek_cache:rw
```

In the above example, the `cache-preloader` tool's target directory was `./vcek_cache`:
```bash
cargo run -- -u test_urls.txt -c ./vcek_cache
```

And `as-config.json` sets `cache_dir` to `/vcek_cache`.

### Kubernetes Operator:

*** TBD *** More information will be added about K8s operator support.

### Example (Docker):

On a system with network access to AMD KDS:
```bash
# Navigate to the cache-preloader directory
cd tools/cache-preloader

# Create a URLs file - one line for each target machine that kds will service
cat > vcek_urls.txt << EOF
https://kdsintf.amd.com/vcek/v-1/Milan/0123456789abcdef?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115
https://kdsintf.amd.com/vcek/v-1/Genoa/fedcba9876543210?blSPL=02&teeSPL=00&snpSPL=03&ucodeSPL=209
EOF

# Create cache preloader archive
cargo run -- -u vcek_urls.txt -c ./vcek_cache -a vcek_cache.tar.gz

# Copy the archive to your air-gapped trustee attestation-service deployment
scp vcek_cache.tar.gz user@target-host:
```

On the air-gapped trustee attestation-service host:
```bash
# Extract the archive into the desired cache directory
mkdir vcek_cache
cd vcek_cache
tar -xzf ../vcek_cache.tar.gz

# Update as-config.json to point to the new cache directory
cd /path/to/trustee
vi kbs/config/as-config.json
# Update the verifier_config section to:
#     "verifier_config": {
#        "snp_verifier": {
#            "vcek_cache": {
#                "type": "HttpCacheReqwest",
#                "offline_mode": true,
#                "cache_dir": "/vcek_cache"
#            }
#        }
#    }
docker compose build as
docker compose up -d

# Copy the cache into the running attestation service container
docker cp ./vcek_cache/ trustee-as-1:/vcek_cache/
```

## Understanding the Cache Structure

The cache-preloader tool uses the `http-cache-reqwest` crate which creates a
content-addressable cache with the following structure:

```
cache-directory/
├── content-v2/
│   └── sha256/
│       └── XX/
│           └── YY/
│               └── <hash> (actual certificate data)
└── index-v5/
    └── XX/
        └── YY/
            └── <hash> (cache metadata and mappings)
```

- **content-v2/sha256/**: Stores the actual HTTP response bodies (the VCEK
  certificates) indexed by content hash
- **index-v5/**: Stores cache metadata including URL-to-content mappings,
  headers, and cache control information

When transferring the cache to an air-gapped environment, you must preserve
this exact directory structure. The entire cache directory should be copied
as-is to the location specified in `cache_dir` configuration.

## Limitations

This offline caching solution has several limitations that users should be
aware of:

- **Firmware-Specific Certificates**: VCEKs are tied to specific firmware
  versions. If the AMD firmware is updated on any host, new VCEKs must be
  fetched and added to the cache. The existing cached certificates will become
  invalid for that host.

- **Manual Cache Management**: There is no automatic mechanism to detect when
  cached certificates become stale or when new certificates are needed.
  Administrators must manually track firmware updates and rebuild the cache
  accordingly.

- **No Certificate Revocation Checking**: When operating in offline mode, the
  system cannot check for certificate revocations or updates from the AMD KDS.
  This is an inherent limitation of air-gapped deployments.

- **TCB Version Dependencies**: The VCEK URLs include TCB (Trusted Computing
  Base) version parameters (blSPL, teeSPL, snpSPL, ucodeSPL). If these versions
  change due to firmware updates, the cached certificates will not match and
  attestation will fail.

- **Storage Requirements**: Each VCEK certificate must be cached separately.
  For large deployments with many hosts, ensure adequate storage is available
  for the cache directory.

- **Inserting New Certificates**: There is currently not a tool for
  adding new certificates to an existing cache. Administrators may need to
  modify cache files or rebuild the cache from scratch when new certificates
  are required.
